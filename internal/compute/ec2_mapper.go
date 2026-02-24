package compute

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"

	"breachmap/internal/domain"
	"breachmap/internal/logging"
)

// EC2Dependencies holds injected functions
type EC2Dependencies struct {
	GetAWSClient     func(ctx context.Context, service string) (interface{}, error)
	GetAuditorConfig func() *aws.Config
}

var ec2Deps EC2Dependencies

// SetEC2Dependencies sets the injected dependencies
func SetEC2Dependencies(d EC2Dependencies) {
	ec2Deps = d
}

// DiscoverEnabledRegions discovers all enabled AWS regions for the account
func DiscoverEnabledRegions(ctx context.Context) ([]string, error) {
	logging.LogDebug("--- Discovering Enabled AWS Regions ---")

	if ec2Deps.GetAWSClient == nil {
		return nil, fmt.Errorf("GetAWSClient is not set")
	}

	baseClient, err := ec2Deps.GetAWSClient(ctx, "ec2")
	if err != nil {
		return nil, fmt.Errorf("failed to get EC2 client for region discovery: %w", err)
	}
	baseEC2Svc := baseClient.(*ec2.Client)

	baseCfg := baseEC2Svc.Options()

	region := baseCfg.Region
	if region == "" {
		region = "us-east-1"
	}

	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	if ec2Deps.GetAuditorConfig != nil {
		if auditorCfg := ec2Deps.GetAuditorConfig(); auditorCfg != nil {
			cfg = *auditorCfg
			cfg.Region = region
		}
	}

	ec2Svc := ec2.NewFromConfig(cfg)

	regionsOutput, err := ec2Svc.DescribeRegions(ctx, &ec2.DescribeRegionsInput{
		AllRegions: aws.Bool(false),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to describe regions: %w", err)
	}

	if regionsOutput == nil || regionsOutput.Regions == nil {
		log.Println("Warning: No regions returned, using default region")
		return []string{region}, nil
	}

	regions := make([]string, 0, len(regionsOutput.Regions))
	for _, regionInfo := range regionsOutput.Regions {
		if regionInfo.RegionName != nil {
			regions = append(regions, *regionInfo.RegionName)
		}
	}

	return regions, nil
}

// MapRolesToEC2Instances maps IAM roles to EC2 instances that assume those roles
func MapRolesToEC2Instances(ctx context.Context, roleARNs []string) (domain.RoleToInstancesMapping, error) {
	startTime := time.Now()
	logging.LogOperationStart("map_roles_to_ec2_instances", map[string]interface{}{
		"role_count": len(roleARNs),
	})

	if len(roleARNs) == 0 {
		logging.LogInfo("No role ARNs provided for EC2 mapping")
		return make(domain.RoleToInstancesMapping), nil
	}

	metricsInst := logging.GetMetrics()

	roleARNSet := make(map[string]bool)
	for _, roleARN := range roleARNs {
		roleARNSet[roleARN] = true
	}

	logging.LogInfo("Mapping roles to EC2 instances", map[string]interface{}{
		"role_count": len(roleARNs),
	})

	regions, err := DiscoverEnabledRegions(ctx)
	if err != nil {
		logging.LogWarn("Failed to discover regions, falling back to default", map[string]interface{}{
			"error": err.Error(),
		})
		metricsInst.RecordAPICall("DescribeRegions", false, err)
		if ec2Deps.GetAWSClient == nil {
			logging.LogOperationEnd("map_roles_to_ec2_instances", time.Since(startTime), false, 0, 0, err)
			return nil, fmt.Errorf("EC2 dependencies not initialized - call SetEC2Dependencies first")
		}
		ec2Client, err := ec2Deps.GetAWSClient(ctx, "ec2")
		if err != nil {
			logging.LogOperationEnd("map_roles_to_ec2_instances", time.Since(startTime), false, 0, 0, err)
			return nil, fmt.Errorf("failed to get EC2 client: %w", err)
		}
		ec2Svc := ec2Client.(*ec2.Client)
		region := ec2Svc.Options().Region
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

	if ec2Deps.GetAWSClient == nil {
		return nil, fmt.Errorf("EC2 dependencies not initialized - call SetEC2Dependencies first")
	}

	iamClient, err := ec2Deps.GetAWSClient(ctx, "iam")
	if err != nil {
		return nil, fmt.Errorf("failed to get IAM client: %w", err)
	}
	iamSvc := iamClient.(*iam.Client)

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

	type instanceWithRoles struct {
		instance     domain.EC2InstanceInfo
		matchedRoles []string
	}

	type regionResult struct {
		region    string
		instances []instanceWithRoles
		err       error
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
			regionEC2Svc := ec2.NewFromConfig(regionCfg)

			regionStartTime := time.Now()
			instances, err := regionEC2Svc.DescribeInstances(ctx, &ec2.DescribeInstancesInput{})
			regionDuration := time.Since(regionStartTime)

			if err != nil {
				metricsInst.RecordAPICall("DescribeInstances", false, err)
				metricsInst.RecordRegionOperation(regionName, false, 0, err)
				logging.LogRegionOperation(regionName, "describe_ec2_instances", false, 0, err)
				resultChan <- regionResult{region: regionName, instances: nil, err: err}
				return
			}

			metricsInst.RecordAPICall("DescribeInstances", true, nil)
			logging.LogAPICall("DescribeInstances", true, regionDuration, nil)

			if instances == nil || instances.Reservations == nil {
				metricsInst.RecordRegionOperation(regionName, true, 0, nil)
				resultChan <- regionResult{region: regionName, instances: []instanceWithRoles{}, err: nil}
				return
			}

			var regionInstances []instanceWithRoles
			instanceCount := 0

			for _, reservation := range instances.Reservations {
				if reservation.Instances == nil {
					continue
				}

				for _, instance := range reservation.Instances {
					if instance.IamInstanceProfile == nil || instance.IamInstanceProfile.Arn == nil {
						continue
					}

					instanceProfileARN := aws.ToString(instance.IamInstanceProfile.Arn)

					profileRoles, err := GetInstanceProfileRoles(ctx, iamSvc, instanceProfileARN)
					if err != nil {
						metricsInst.RecordAPICall("GetInstanceProfile", false, err)
						logging.LogWarn("Failed to get roles for instance profile", map[string]interface{}{
							"region":           regionName,
							"instance_profile": instanceProfileARN,
							"error":            err.Error(),
						})
						continue
					}
					metricsInst.RecordAPICall("GetInstanceProfile", true, nil)

					var matchedRoles []string
					for _, profileRoleARN := range profileRoles {
						if roleARNSet[profileRoleARN] {
							matchedRoles = append(matchedRoles, profileRoleARN)
						}
					}

					if len(matchedRoles) == 0 {
						continue
					}

					instanceInfo := extractInstanceInfo(instance, regionName)

					regionInstances = append(regionInstances, instanceWithRoles{
						instance:     instanceInfo,
						matchedRoles: matchedRoles,
					})
					instanceCount++
				}
			}

			metricsInst.RecordRegionOperation(regionName, true, instanceCount, nil)
			logging.LogRegionOperation(regionName, "describe_ec2_instances", true, instanceCount, nil)
			resultChan <- regionResult{region: regionName, instances: regionInstances, err: nil}
		}(region)
	}

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	mapping := make(domain.RoleToInstancesMapping)
	totalInstances := 0
	regionsProcessed := 0
	regionsFailed := 0

	for result := range resultChan {
		if result.err != nil {
			regionsFailed++
			continue
		}

		regionsProcessed++

		for _, instanceWithRoles := range result.instances {
			for _, roleARN := range instanceWithRoles.matchedRoles {
				mapping[roleARN] = append(mapping[roleARN], instanceWithRoles.instance)
			}
			totalInstances++
		}
	}

	duration := time.Since(startTime)
	logging.LogOperationEnd("map_roles_to_ec2_instances", duration, true, len(roleARNs), totalInstances, nil)

	logging.LogInfo("EC2 role mapping completed", map[string]interface{}{
		"regions_processed": regionsProcessed,
		"regions_failed":    regionsFailed,
		"instances_found":   totalInstances,
		"roles_mapped":      len(mapping),
		"duration_ms":       duration.Milliseconds(),
	})

	return mapping, nil
}

// GetInstanceProfileRoles resolves an instance profile ARN to the role ARNs it contains
func GetInstanceProfileRoles(ctx context.Context, iamSvc *iam.Client, instanceProfileARN string) ([]string, error) {
	prefix := ":instance-profile/"
	idx := strings.Index(instanceProfileARN, prefix)
	if idx == -1 {
		return nil, fmt.Errorf("invalid instance profile ARN format: %s", instanceProfileARN)
	}
	profileName := instanceProfileARN[idx+len(prefix):]
	if profileName == "" {
		return nil, fmt.Errorf("instance profile ARN missing profile name: %s", instanceProfileARN)
	}

	profileOutput, err := iamSvc.GetInstanceProfile(ctx, &iam.GetInstanceProfileInput{
		InstanceProfileName: aws.String(profileName),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get instance profile %s: %w", profileName, err)
	}

	if profileOutput == nil || profileOutput.InstanceProfile == nil {
		return nil, fmt.Errorf("empty instance profile response for %s", profileName)
	}

	var roleARNs []string
	if profileOutput.InstanceProfile.Roles != nil {
		for _, role := range profileOutput.InstanceProfile.Roles {
			if role.Arn != nil {
				roleARNs = append(roleARNs, aws.ToString(role.Arn))
			}
		}
	}

	if len(roleARNs) == 0 {
		return nil, fmt.Errorf("instance profile %s has no roles", profileName)
	}

	return roleARNs, nil
}

func extractInstanceInfo(instance ec2types.Instance, region string) domain.EC2InstanceInfo {
	instanceInfo := domain.EC2InstanceInfo{
		InstanceID:       aws.ToString(instance.InstanceId),
		Region:           region,
		SecurityGroupIDs: []string{},
	}

	if instance.VpcId != nil {
		instanceInfo.VPCID = instance.VpcId
	}

	if instance.SubnetId != nil {
		instanceInfo.SubnetID = instance.SubnetId
	}

	if instance.PublicIpAddress != nil {
		publicIP := aws.ToString(instance.PublicIpAddress)
		instanceInfo.PublicIP = &publicIP
		instanceInfo.PublicIPFlag = true
	}

	if instance.PrivateIpAddress != nil {
		privateIP := aws.ToString(instance.PrivateIpAddress)
		instanceInfo.PrivateIP = &privateIP
	}

	if instance.SecurityGroups != nil {
		for _, sg := range instance.SecurityGroups {
			if sg.GroupId != nil {
				instanceInfo.SecurityGroupIDs = append(instanceInfo.SecurityGroupIDs, aws.ToString(sg.GroupId))
			}
		}
	}

	// Extract Name tag
	if instance.Tags != nil {
		for _, tag := range instance.Tags {
			if tag.Key != nil && aws.ToString(tag.Key) == "Name" && tag.Value != nil {
				name := aws.ToString(tag.Value)
				instanceInfo.Name = &name
				break
			}
		}
	}

	return instanceInfo
}

// CheckInstancePublicExposure checks if an EC2 instance is publicly exposed
func CheckInstancePublicExposure(ctx context.Context, ec2Svc *ec2.Client, instance domain.EC2InstanceInfo) (*domain.PublicExposureInfo, error) {
	exposureInfo := &domain.PublicExposureInfo{
		HasPublicIP:          instance.PublicIPFlag,
		PublicSecurityGroups: []string{},
		ExposedPorts:         []domain.ExposedPort{},
	}

	if len(instance.SecurityGroupIDs) == 0 {
		return exposureInfo, nil
	}

	sgOutput, err := ec2Svc.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{
		GroupIds: instance.SecurityGroupIDs,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to describe security groups: %w", err)
	}

	if sgOutput == nil || sgOutput.SecurityGroups == nil {
		return exposureInfo, nil
	}

	for _, sg := range sgOutput.SecurityGroups {
		sgID := aws.ToString(sg.GroupId)
		hasPublicAccess, exposedPorts := AnalyzeSecurityGroupPublicAccess(sg)

		if hasPublicAccess {
			exposureInfo.PublicSecurityGroups = append(exposureInfo.PublicSecurityGroups, sgID)
			exposureInfo.ExposedPorts = append(exposureInfo.ExposedPorts, exposedPorts...)
		}
	}

	return exposureInfo, nil
}

// AnalyzeSecurityGroupPublicAccess analyzes a security group for public internet access
func AnalyzeSecurityGroupPublicAccess(sg ec2types.SecurityGroup) (bool, []domain.ExposedPort) {
	if sg.IpPermissions == nil {
		return false, nil
	}

	hasPublicAccess := false
	var exposedPorts []domain.ExposedPort

	for _, perm := range sg.IpPermissions {
		if perm.IpRanges != nil {
			for _, ipRange := range perm.IpRanges {
				if ipRange.CidrIp != nil && (*ipRange.CidrIp == "0.0.0.0/0") {
					hasPublicAccess = true
					exposedPort := domain.ExposedPort{
						Protocol: aws.ToString(perm.IpProtocol),
					}
					if perm.FromPort != nil {
						exposedPort.FromPort = perm.FromPort
					}
					if perm.ToPort != nil {
						exposedPort.ToPort = perm.ToPort
					}
					exposedPorts = append(exposedPorts, exposedPort)
				}
			}
		}

		if perm.Ipv6Ranges != nil {
			for _, ipv6Range := range perm.Ipv6Ranges {
				if ipv6Range.CidrIpv6 != nil && (*ipv6Range.CidrIpv6 == "::/0") {
					hasPublicAccess = true
					exposedPort := domain.ExposedPort{
						Protocol: aws.ToString(perm.IpProtocol),
					}
					if perm.FromPort != nil {
						exposedPort.FromPort = perm.FromPort
					}
					if perm.ToPort != nil {
						exposedPort.ToPort = perm.ToPort
					}
					exposedPorts = append(exposedPorts, exposedPort)
				}
			}
		}
	}

	return hasPublicAccess, exposedPorts
}

// EnrichInstancesWithPublicExposure enriches EC2 instances with public exposure information
func EnrichInstancesWithPublicExposure(ctx context.Context, mapping domain.RoleToInstancesMapping) error {
	logging.LogDebug("--- Enriching EC2 Instances with Public Exposure Information (Multi-Region) ---")

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

	instancesByRegion := make(map[string][]*domain.EC2InstanceInfo)
	for roleARN := range mapping {
		for i := range mapping[roleARN] {
			region := mapping[roleARN][i].Region
			if region == "" {
				region = "us-east-1"
				mapping[roleARN][i].Region = region
			}
			instancesByRegion[region] = append(instancesByRegion[region], &mapping[roleARN][i])
		}
	}

	for region, instances := range instancesByRegion {
		regionCfg := cfg
		regionCfg.Region = region
		regionEC2Svc := ec2.NewFromConfig(regionCfg)

		logging.LogDebug(fmt.Sprintf("Checking public exposure for %d instances in region %s", len(instances), region))

		for _, instance := range instances {
			exposureInfo, err := CheckInstancePublicExposure(ctx, regionEC2Svc, *instance)
			if err != nil {
				log.Printf("Failed to check public exposure for instance %s in region %s: %v", instance.InstanceID, region, err)
				continue
			}

			instance.PublicExposure = exposureInfo
			if len(exposureInfo.PublicSecurityGroups) > 0 {
				instance.PublicSGFlag = true
			}
			instance.InternetExposed = instance.PublicIPFlag && instance.PublicSGFlag
		}
	}

	logging.LogDebug(fmt.Sprintf("Enriched instances with public exposure information across %d regions", len(instancesByRegion)))
	return nil
}
