package compute

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"

	"breachmap/internal/domain"
	"breachmap/internal/logging"
)

// MapRolesToLambdaFunctions maps IAM roles to Lambda functions that use those roles
func MapRolesToLambdaFunctions(ctx context.Context, roleARNs []string) (domain.RoleToLambdasMapping, error) {
	startTime := time.Now()
	logging.LogOperationStart("map_roles_to_lambda_functions", map[string]interface{}{
		"role_count": len(roleARNs),
	})

	if len(roleARNs) == 0 {
		logging.LogInfo("No role ARNs provided for Lambda mapping")
		return make(domain.RoleToLambdasMapping), nil
	}

	metricsInst := logging.GetMetrics()

	roleARNSet := make(map[string]bool)
	for _, roleARN := range roleARNs {
		roleARNSet[roleARN] = true
	}

	logging.LogInfo("Mapping roles to Lambda functions", map[string]interface{}{
		"role_count": len(roleARNs),
	})

	regions, err := DiscoverEnabledRegions(ctx)
	if err != nil {
		logging.LogWarn("Failed to discover regions, falling back to default", map[string]interface{}{
			"error": err.Error(),
		})
		metricsInst.RecordAPICall("DescribeRegions", false, err)
		lambdaClient, err := ec2Deps.GetAWSClient(ctx, "lambda")
		if err != nil {
			logging.LogOperationEnd("map_roles_to_lambda_functions", time.Since(startTime), false, 0, 0, err)
			return nil, fmt.Errorf("failed to get Lambda client: %w", err)
		}
		lambdaSvc := lambdaClient.(*lambda.Client)
		region := lambdaSvc.Options().Region
		if region == "" {
			region = "us-east-1"
		}
		regions = []string{region}
	} else {
		metricsInst.RecordAPICall("DescribeRegions", true, nil)
		logging.LogInfo("Discovered regions", map[string]interface{}{
			"region_count": len(regions),
		})
	}

	var cfg aws.Config
	if ec2Deps.GetAuditorConfig != nil {
		if auditorCfg := ec2Deps.GetAuditorConfig(); auditorCfg != nil {
			cfg = *auditorCfg
		} else {
			cfg, err = config.LoadDefaultConfig(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to load AWS config: %w", err)
			}
		}
	} else {
		cfg, err = config.LoadDefaultConfig(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to load AWS config: %w", err)
		}
	}

	type lambdaWithRole struct {
		lambda         domain.LambdaInfo
		matchedRoleARN string
	}

	type regionResult struct {
		region  string
		lambdas []lambdaWithRole
		err     error
	}

	resultChan := make(chan regionResult, len(regions))
	var wg sync.WaitGroup

	const maxConcurrentRegions = 10
	semaphore := make(chan struct{}, maxConcurrentRegions)

	for _, region := range regions {
		wg.Add(1)
		go func(regionName string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			regionCfg := cfg
			regionCfg.Region = regionName
			regionLambdaSvc := lambda.NewFromConfig(regionCfg)

			paginator := lambda.NewListFunctionsPaginator(regionLambdaSvc, &lambda.ListFunctionsInput{})
			var regionLambdas []lambdaWithRole

			lambdaCount := 0
			for paginator.HasMorePages() {
				pageStartTime := time.Now()
				page, err := paginator.NextPage(ctx)
				pageDuration := time.Since(pageStartTime)

				if err != nil {
					metricsInst.RecordAPICall("ListFunctions", false, err)
					metricsInst.RecordRegionOperation(regionName, false, 0, err)
					logging.LogRegionOperation(regionName, "list_lambda_functions", false, 0, err)
					resultChan <- regionResult{region: regionName, lambdas: nil, err: err}
					return
				}

				metricsInst.RecordAPICall("ListFunctions", true, nil)
				logging.LogAPICall("ListFunctions", true, pageDuration, nil)

				if page == nil || page.Functions == nil {
					continue
				}

				for _, fn := range page.Functions {
					if fn.Role == nil || fn.FunctionName == nil {
						continue
					}

					roleARN := aws.ToString(fn.Role)
					if !roleARNSet[roleARN] {
						continue
					}

					lambdaInfo := extractLambdaInfo(fn, regionName, roleARN)

					regionLambdas = append(regionLambdas, lambdaWithRole{
						lambda:         lambdaInfo,
						matchedRoleARN: roleARN,
					})
					lambdaCount++
				}
			}

			metricsInst.RecordRegionOperation(regionName, true, lambdaCount, nil)
			logging.LogRegionOperation(regionName, "list_lambda_functions", true, lambdaCount, nil)
			resultChan <- regionResult{region: regionName, lambdas: regionLambdas, err: nil}
		}(region)
	}

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	mapping := make(domain.RoleToLambdasMapping)
	totalLambdas := 0
	regionsProcessed := 0
	regionsFailed := 0

	for result := range resultChan {
		if result.err != nil {
			regionsFailed++
			continue
		}

		regionsProcessed++

		for _, lambdaWithRole := range result.lambdas {
			mapping[lambdaWithRole.matchedRoleARN] = append(mapping[lambdaWithRole.matchedRoleARN], lambdaWithRole.lambda)
			totalLambdas++
		}
	}

	duration := time.Since(startTime)
	logging.LogOperationEnd("map_roles_to_lambda_functions", duration, true, len(roleARNs), totalLambdas, nil)

	logging.LogInfo("Lambda role mapping completed", map[string]interface{}{
		"regions_processed": regionsProcessed,
		"regions_failed":    regionsFailed,
		"lambdas_found":     totalLambdas,
		"roles_mapped":      len(mapping),
		"duration_ms":       duration.Milliseconds(),
	})

	return mapping, nil
}

func extractLambdaInfo(fn lambdatypes.FunctionConfiguration, region string, roleARN string) domain.LambdaInfo {
	lambdaInfo := domain.LambdaInfo{
		FunctionName:     aws.ToString(fn.FunctionName),
		FunctionARN:      aws.ToString(fn.FunctionArn),
		Region:           region,
		RoleARN:          roleARN,
		SubnetIDs:        []string{},
		SecurityGroupIDs: []string{},
	}

	if fn.VpcConfig != nil {
		if fn.VpcConfig.VpcId != nil {
			lambdaInfo.VPCID = fn.VpcConfig.VpcId
		}
		if fn.VpcConfig.SubnetIds != nil {
			for _, subnetID := range fn.VpcConfig.SubnetIds {
				lambdaInfo.SubnetIDs = append(lambdaInfo.SubnetIDs, subnetID)
			}
		}
		if fn.VpcConfig.SecurityGroupIds != nil {
			for _, sgID := range fn.VpcConfig.SecurityGroupIds {
				lambdaInfo.SecurityGroupIDs = append(lambdaInfo.SecurityGroupIDs, sgID)
			}
		}
	}

	return lambdaInfo
}

// EnrichLambdasWithPublicExposure enriches Lambda functions with public exposure information
func EnrichLambdasWithPublicExposure(ctx context.Context, mapping domain.RoleToLambdasMapping) error {
	startTime := time.Now()
	totalLambdas := 0
	for _, lambdas := range mapping {
		totalLambdas += len(lambdas)
	}

	logging.LogOperationStart("enrich_lambdas_with_public_exposure", map[string]interface{}{
		"lambda_count": totalLambdas,
	})

	var cfg aws.Config
	var err error
	if ec2Deps.GetAuditorConfig != nil {
		if auditorCfg := ec2Deps.GetAuditorConfig(); auditorCfg != nil {
			cfg = *auditorCfg
		} else {
			cfg, err = config.LoadDefaultConfig(ctx)
			if err != nil {
				return fmt.Errorf("failed to load AWS config: %w", err)
			}
		}
	} else {
		cfg, err = config.LoadDefaultConfig(ctx)
		if err != nil {
			return fmt.Errorf("failed to load AWS config: %w", err)
		}
	}

	lambdasByRegion := make(map[string][]*domain.LambdaInfo)
	for roleARN := range mapping {
		for i := range mapping[roleARN] {
			region := mapping[roleARN][i].Region
			if region == "" {
				region = "us-east-1"
				mapping[roleARN][i].Region = region
			}
			lambdasByRegion[region] = append(lambdasByRegion[region], &mapping[roleARN][i])
		}
	}

	for region, lambdas := range lambdasByRegion {
		regionCfg := cfg
		regionCfg.Region = region
		regionLambdaSvc := lambda.NewFromConfig(regionCfg)
		regionAPIGatewaySvc := apigateway.NewFromConfig(regionCfg)
		regionAPIGatewayV2Svc := apigatewayv2.NewFromConfig(regionCfg)

		logging.LogInfo("Checking public exposure for Lambda functions", map[string]interface{}{
			"region":       region,
			"lambda_count": len(lambdas),
		})

		for _, lambdaInfo := range lambdas {
			exposureInfo := &domain.LambdaExposureInfo{}

			// Fetch Lambda function to get tags (including Name tag)
			funcStartTime := time.Now()
			funcResult, err := regionLambdaSvc.GetFunction(ctx, &lambda.GetFunctionInput{
				FunctionName: aws.String(lambdaInfo.FunctionName),
			})
			funcDuration := time.Since(funcStartTime)

			if err == nil && funcResult != nil && funcResult.Tags != nil {
				metrics := logging.GetMetrics()
				metrics.RecordAPICall("GetFunction", true, nil)
				logging.LogAPICall("GetFunction", true, funcDuration, nil)

				// Extract Name tag
				if nameTag, ok := funcResult.Tags["Name"]; ok && nameTag != "" {
					lambdaInfo.Name = &nameTag
				}
			} else if err != nil {
				metrics := logging.GetMetrics()
				if !strings.Contains(err.Error(), "ResourceNotFoundException") {
					metrics.RecordAPICall("GetFunction", false, err)
					logging.LogAPICall("GetFunction", false, funcDuration, err)
				}
			}

			urlStartTime := time.Now()
			urlConfig, err := regionLambdaSvc.GetFunctionUrlConfig(ctx, &lambda.GetFunctionUrlConfigInput{
				FunctionName: aws.String(lambdaInfo.FunctionName),
			})
			urlDuration := time.Since(urlStartTime)

			if err == nil && urlConfig != nil {
				metricsInst := logging.GetMetrics()
				metricsInst.RecordAPICall("GetFunctionUrlConfig", true, nil)
				logging.LogAPICall("GetFunctionUrlConfig", true, urlDuration, nil)

				authType := string(urlConfig.AuthType)
				if authType == "NONE" {
					lambdaInfo.PublicLambdaURL = true
					exposureInfo.FunctionURLConfig = &domain.FunctionURLConfig{
						FunctionURL: aws.ToString(urlConfig.FunctionUrl),
						AuthType:    authType,
					}
				}
			} else if err != nil {
				metricsInst := logging.GetMetrics()
				if !strings.Contains(err.Error(), "ResourceNotFoundException") {
					metricsInst.RecordAPICall("GetFunctionUrlConfig", false, err)
					logging.LogAPICall("GetFunctionUrlConfig", false, urlDuration, err)
				}
			}

			apiStartTime := time.Now()
			apiIntegrations, err := findAPIGatewayIntegrations(ctx, regionAPIGatewaySvc, regionAPIGatewayV2Svc, lambdaInfo.FunctionARN)
			apiDuration := time.Since(apiStartTime)

			if err != nil {
				metricsInst := logging.GetMetrics()
				metricsInst.RecordAPICall("GetRestApis/GetApis", false, err)
				logging.LogWarn("Failed to check API Gateway integrations", map[string]interface{}{
					"lambda": lambdaInfo.FunctionName,
					"region": region,
					"error":  err.Error(),
				})
			} else {
				metricsInst := logging.GetMetrics()
				metricsInst.RecordAPICall("GetRestApis/GetApis", true, nil)
				logging.LogAPICall("GetRestApis/GetApis", true, apiDuration, nil)

				exposureInfo.APIGatewayIntegrations = apiIntegrations
				for _, integration := range apiIntegrations {
					if integration.Public {
						lambdaInfo.PublicAPIGateway = true
						break
					}
				}
			}

			lambdaInfo.InternetReachable = lambdaInfo.PublicLambdaURL || lambdaInfo.PublicAPIGateway

			if lambdaInfo.PublicLambdaURL || lambdaInfo.PublicAPIGateway {
				lambdaInfo.ExposureDetails = exposureInfo
			}
		}
	}

	duration := time.Since(startTime)
	exposedCount := 0
	for _, lambdas := range mapping {
		for _, lambdaInfo := range lambdas {
			if lambdaInfo.InternetReachable {
				exposedCount++
			}
		}
	}

	logging.LogOperationEnd("enrich_lambdas_with_public_exposure", duration, true, totalLambdas, exposedCount, nil)
	logging.LogInfo("Lambda exposure enrichment completed", map[string]interface{}{
		"regions":         len(lambdasByRegion),
		"lambdas_total":   totalLambdas,
		"lambdas_exposed": exposedCount,
		"duration_ms":     duration.Milliseconds(),
	})

	return nil
}

func findAPIGatewayIntegrations(ctx context.Context, apiGatewaySvc *apigateway.Client, apiGatewayV2Svc *apigatewayv2.Client, functionARN string) ([]domain.APIGatewayIntegration, error) {
	var integrations []domain.APIGatewayIntegration

	restAPIs, err := apiGatewaySvc.GetRestApis(ctx, &apigateway.GetRestApisInput{})
	if err == nil && restAPIs != nil {
		for _, api := range restAPIs.Items {
			stages, err := apiGatewaySvc.GetStages(ctx, &apigateway.GetStagesInput{
				RestApiId: api.Id,
			})
			if err != nil {
				continue
			}

			for _, stage := range stages.Item {
				resources, err := apiGatewaySvc.GetResources(ctx, &apigateway.GetResourcesInput{
					RestApiId: api.Id,
				})
				if err != nil {
					continue
				}

				for _, resource := range resources.Items {
					for method := range resource.ResourceMethods {
						methodIntegration, err := apiGatewaySvc.GetIntegration(ctx, &apigateway.GetIntegrationInput{
							RestApiId:  api.Id,
							ResourceId: resource.Id,
							HttpMethod: aws.String(method),
						})
						if err != nil {
							continue
						}

						if methodIntegration.Uri != nil && strings.Contains(aws.ToString(methodIntegration.Uri), functionARN) {
							methodDetails, err := apiGatewaySvc.GetMethod(ctx, &apigateway.GetMethodInput{
								RestApiId:  api.Id,
								ResourceId: resource.Id,
								HttpMethod: aws.String(method),
							})
							if err != nil {
								continue
							}

							authorizerType := "NONE"
							if methodDetails.AuthorizationType != nil {
								authorizerType = aws.ToString(methodDetails.AuthorizationType)
							}

							apiKeyRequired := false
							if methodDetails.ApiKeyRequired != nil {
								apiKeyRequired = aws.ToBool(methodDetails.ApiKeyRequired)
							}

							isPublic := authorizerType == "NONE" || (!apiKeyRequired && authorizerType == "NONE")

							integrations = append(integrations, domain.APIGatewayIntegration{
								APIID:          aws.ToString(api.Id),
								APIName:        aws.ToString(api.Name),
								APIType:        "REST",
								StageName:      aws.ToString(stage.StageName),
								AuthorizerType: authorizerType,
								APIKeyRequired: apiKeyRequired,
								Public:         isPublic,
							})
						}
					}
				}
			}
		}
	}

	httpAPIs, err := apiGatewayV2Svc.GetApis(ctx, &apigatewayv2.GetApisInput{})
	if err == nil && httpAPIs != nil {
		for _, api := range httpAPIs.Items {
			integrationsList, err := apiGatewayV2Svc.GetIntegrations(ctx, &apigatewayv2.GetIntegrationsInput{
				ApiId: api.ApiId,
			})
			if err != nil {
				continue
			}

			for _, integration := range integrationsList.Items {
				if integration.IntegrationUri != nil && strings.Contains(aws.ToString(integration.IntegrationUri), functionARN) {
					routes, err := apiGatewayV2Svc.GetRoutes(ctx, &apigatewayv2.GetRoutesInput{
						ApiId: api.ApiId,
					})
					if err != nil {
						continue
					}

					hasAuthorizer := false
					for _, route := range routes.Items {
						authType := string(route.AuthorizationType)
						if authType != "" && authType != "NONE" {
							hasAuthorizer = true
							break
						}
					}

					stages, err := apiGatewayV2Svc.GetStages(ctx, &apigatewayv2.GetStagesInput{
						ApiId: api.ApiId,
					})
					if err != nil {
						continue
					}

					for _, stage := range stages.Items {
						isPublic := !hasAuthorizer

						integrations = append(integrations, domain.APIGatewayIntegration{
							APIID:          aws.ToString(api.ApiId),
							APIName:        aws.ToString(api.Name),
							APIType:        "HTTP",
							StageName:      aws.ToString(stage.StageName),
							AuthorizerType: map[bool]string{true: "NONE", false: "AWS_IAM"}[isPublic],
							APIKeyRequired: false,
							Public:         isPublic,
						})
					}
				}
			}
		}
	}

	return integrations, nil
}
