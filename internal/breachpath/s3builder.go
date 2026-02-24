package breachpath

import (
	"breachmap/internal/app"
	"breachmap/internal/authorization"
	internalaws "breachmap/internal/aws"
	"breachmap/internal/crownjewels"
	"breachmap/internal/domain"
	"breachmap/internal/exposure"
	"breachmap/internal/logging"
	"breachmap/internal/network"
	"breachmap/internal/outputter"
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// buildBreachPathFromComputeResource constructs a BreachPath from unified ComputeResource
// This unified function works for all runtime types (EC2, Lambda, ECS, etc.)
func buildBreachPathFromComputeResource(
	pathCounter int,
	bucket domain.S3CrownJewel,
	exposureResult *domain.ExposureResult,
	access domain.PrincipalAccess,
	computeResource domain.ComputeResource,
	accountID string,
	isLateralPath bool,
	lateralRoleARN string,
) domain.BreachPath {
	// Build path ID - runtime type is now metadata, not in the ID
	pathID := fmt.Sprintf("s3-breach-path-%d", pathCounter)

	// Build status message based on runtime type
	var status string
	var exposure *string

	switch computeResource.RuntimeType {
	case "EC2":
		status = buildStatusMessage(exposureResult.FinalExposure, access.RiskProfile)
		exposureStr := fmt.Sprintf("Public EC2 Instance (%s)", exposureResult.FinalExposure)
		exposure = &exposureStr
	case "Lambda":
		// Convert ComputeResource back to LambdaInfo for status message
		lambdaInfo := convertComputeResourceToLambdaInfo(computeResource)
		status = buildLambdaStatusMessage(exposureResult.FinalExposure, access.RiskProfile, lambdaInfo)
		exposureParts := []string{}
		if computeResource.ExposureDetails != nil {
			if computeResource.ExposureDetails.FunctionURLConfig != nil {
				exposureParts = append(exposureParts, "Function URL (NONE auth)")
			}
			if len(computeResource.ExposureDetails.APIGatewayIntegrations) > 0 {
				exposureParts = append(exposureParts, "API Gateway (public)")
			}
		}
		if len(exposureParts) > 0 {
			exposureStr := strings.Join(exposureParts, ", ")
			exposure = &exposureStr
		}
	default:
		status = fmt.Sprintf("CRITICAL: Internet-Exposed %s with S3 Access", computeResource.RuntimeType)
		exposureStr := fmt.Sprintf("Public %s", computeResource.RuntimeType)
		exposure = &exposureStr
	}

	resourceARN := computeResource.ResourceARN

	bp := domain.BreachPath{
		PathID:           pathID,
		Vector:           computeResource.RuntimeType, // Runtime type as metadata
		ResourceID:       computeResource.ResourceID,
		ResourceARN:      &resourceARN,
		Role:             access.PrincipalName,
		RoleARN:          computeResource.RoleARN,
		TargetDB:         bucket.ARN,
		TargetType:       "S3",
		Status:           status,
		PublicIP:         computeResource.PublicIP,
		Exposure:         exposure,
		VPCID:            computeResource.VPCID,
		SubnetIDs:        computeResource.SubnetIDs,
		SecurityGroupIDs: computeResource.SecurityGroupIDs,
		TargetEncrypted:  bucket.Encrypted,
		KMSKeyID:         bucket.KMSKeyID,
	}

	// For lateral paths, store the assumed role ARN
	if isLateralPath && lateralRoleARN != "" {
		bp.AssumedRoleARN = access.PrincipalARN // The role that is assumed (bucket access role)
	}

	return bp
}

// buildBreachPathOutputFromComputeResource constructs BreachPathOutput from unified ComputeResource
// This unified function works for all runtime types (EC2, Lambda, ECS, etc.)
func buildBreachPathOutputFromComputeResource(
	pathCounter int,
	bucket domain.S3CrownJewel,
	exposureResult *domain.ExposureResult,
	access *domain.PrincipalAccess,
	computeResource domain.ComputeResource,
	isLateralPath bool,
	lateralRoleARN string,
) domain.BreachPathOutput {
	pathID := fmt.Sprintf("s3-breach-path-%d", pathCounter)
	bucketExposed := isPubliclyExposed(exposureResult.FinalExposure)

	// Determine path type based on runtime type
	pathType := fmt.Sprintf("%s_TO_BUCKET", strings.ToUpper(computeResource.RuntimeType))

	// Build bucket info
	storeInfo := domain.StoreInfo{
		ResourceARN:      bucket.ARN,
		ResourceName:     bucket.Name,
		ResourceType:     "S3",
		Encrypted:        bucket.Encrypted,
		KMSKeyID:         bucket.KMSKeyID,
		IsCrownJewel:     true,
		CrownJewelReason: determineCrownJewelReason(bucket),
	}

	outputBreachPath := domain.BreachPathOutput{
		PathID:          pathID,
		PathType:        pathType,
		InternetExposed: computeResource.InternetExposed,
		Store:           storeInfo,
		BucketExposed:   bucketExposed,
		ExposureDetails: exposureResult,
	}

	// Build path string based on runtime type
	pathParts := []string{"Internet"}
	switch computeResource.RuntimeType {
	case "EC2":
		if computeResource.PublicIP != nil {
			pathParts = append(pathParts, fmt.Sprintf("EC2 %s (Public IP: %s)", computeResource.ResourceID, *computeResource.PublicIP))
		} else {
			pathParts = append(pathParts, fmt.Sprintf("EC2 %s", computeResource.ResourceID))
		}
	case "Lambda":
		if computeResource.ExposureDetails != nil {
			if computeResource.ExposureDetails.FunctionURLConfig != nil {
				pathParts = append(pathParts, fmt.Sprintf("Lambda %s (%s)", computeResource.ResourceID, computeResource.ExposureDetails.FunctionURLConfig.FunctionURL))
			} else if len(computeResource.ExposureDetails.APIGatewayIntegrations) > 0 {
				api := computeResource.ExposureDetails.APIGatewayIntegrations[0]
				pathParts = append(pathParts, fmt.Sprintf("Lambda %s (API Gateway %s/%s)", computeResource.ResourceID, api.APIName, api.StageName))
			} else {
				pathParts = append(pathParts, fmt.Sprintf("Lambda %s", computeResource.ResourceID))
			}
		} else {
			pathParts = append(pathParts, fmt.Sprintf("Lambda %s", computeResource.ResourceID))
		}
	default:
		pathParts = append(pathParts, fmt.Sprintf("%s %s", computeResource.RuntimeType, computeResource.ResourceID))
	}

	if access != nil {
		if isLateralPath && lateralRoleARN != "" {
			// Show role assumption chain: lateral role → (assume) → bucket access role
			lateralRoleName := outputter.ExtractRoleNameFromARN(lateralRoleARN)
			pathParts = append(pathParts, fmt.Sprintf("role %s", lateralRoleName))
			pathParts = append(pathParts, fmt.Sprintf("(assume role %s)", access.PrincipalName))
		} else {
			pathParts = append(pathParts, fmt.Sprintf("role %s", access.PrincipalName))
		}
	}
	pathParts = append(pathParts, fmt.Sprintf("%s (Bucket)", bucket.ARN))
	outputBreachPath.PathString = strings.Join(pathParts, " → ")

	// Build container info based on runtime type
	switch computeResource.RuntimeType {
	case "EC2":
		outputBreachPath.Container = buildEC2WorkloadInfoFromComputeResource(computeResource)
	case "Lambda":
		outputBreachPath.Container = buildLambdaWorkloadInfoFromComputeResource(computeResource)
	default:
		// For other runtime types, create a generic container info
		outputBreachPath.Container = buildGenericWorkloadInfoFromComputeResource(computeResource)
	}

	if access != nil {
		outputBreachPath.IAMRole = buildIAMRoleInfo(access)
	}

	return outputBreachPath
}

// convertComputeResourceToLambdaInfo converts ComputeResource back to LambdaInfo for compatibility
// This is a temporary helper until we fully migrate to ComputeResource
func convertComputeResourceToLambdaInfo(cr domain.ComputeResource) domain.LambdaInfo {
	lambdaInfo := domain.LambdaInfo{
		FunctionName:      cr.ResourceID,
		FunctionARN:       cr.ResourceARN,
		Region:            cr.Region,
		RoleARN:           cr.RoleARN,
		VPCID:             cr.VPCID,
		SubnetIDs:         cr.SubnetIDs,
		SecurityGroupIDs:  cr.SecurityGroupIDs,
		InternetReachable: cr.InternetExposed,
		ExposureDetails:   cr.ExposureDetails,
	}

	if cr.ExposureDetails != nil {
		if cr.ExposureDetails.FunctionURLConfig != nil {
			lambdaInfo.PublicLambdaURL = true
		}
		if len(cr.ExposureDetails.APIGatewayIntegrations) > 0 {
			lambdaInfo.PublicAPIGateway = true
		}
	}

	return lambdaInfo
}

// buildEC2WorkloadInfoFromComputeResource constructs EC2WorkloadInfo from ComputeResource for EC2
func buildEC2WorkloadInfoFromComputeResource(cr domain.ComputeResource) *domain.EC2WorkloadInfo {
	if cr.RuntimeType != "EC2" {
		return nil
	}

	var subnetID *string
	if len(cr.SubnetIDs) > 0 {
		subnetID = &cr.SubnetIDs[0]
	}

	return &domain.EC2WorkloadInfo{
		InstanceID:       cr.ResourceID,
		InstanceARN:      cr.ResourceARN,
		Region:           cr.Region,
		VPCID:            cr.VPCID,
		SubnetID:         subnetID,
		SecurityGroupIDs: cr.SecurityGroupIDs,
		PublicIP:         cr.PublicIP,
		PrivateIP:        cr.PrivateIP,
		InternetExposed:  cr.InternetExposed,
		PublicExposure:   cr.PublicExposure,
	}
}

// buildLambdaWorkloadInfoFromComputeResource constructs EC2WorkloadInfo from ComputeResource for Lambda
func buildLambdaWorkloadInfoFromComputeResource(cr domain.ComputeResource) *domain.EC2WorkloadInfo {
	if cr.RuntimeType != "Lambda" {
		return nil
	}

	return &domain.EC2WorkloadInfo{
		InstanceID:       cr.ResourceID,
		InstanceARN:      cr.ResourceARN,
		Region:           cr.Region,
		VPCID:            cr.VPCID,
		SubnetID:         nil, // Lambda can have multiple subnets
		SecurityGroupIDs: cr.SecurityGroupIDs,
		PublicIP:         nil, // Lambdas don't have public IPs
		PrivateIP:        nil, // Lambdas don't have private IPs
		InternetExposed:  cr.InternetExposed,
		PublicExposure:   nil, // Lambda exposure is different from EC2
	}
}

// buildGenericWorkloadInfoFromComputeResource constructs EC2WorkloadInfo from ComputeResource for other runtime types
func buildGenericWorkloadInfoFromComputeResource(cr domain.ComputeResource) *domain.EC2WorkloadInfo {
	var subnetID *string
	if len(cr.SubnetIDs) > 0 {
		subnetID = &cr.SubnetIDs[0]
	}

	return &domain.EC2WorkloadInfo{
		InstanceID:       cr.ResourceID,
		InstanceARN:      cr.ResourceARN,
		Region:           cr.Region,
		VPCID:            cr.VPCID,
		SubnetID:         subnetID,
		SecurityGroupIDs: cr.SecurityGroupIDs,
		PublicIP:         cr.PublicIP,
		PrivateIP:        cr.PrivateIP,
		InternetExposed:  cr.InternetExposed,
		PublicExposure:   nil, // Generic - may need to be enhanced for specific runtime types
	}
}

// buildLambdaStatusMessage creates a status message for Lambda breach paths
func buildLambdaStatusMessage(exposureType string, riskProfile string, lambdaInfo domain.LambdaInfo) string {
	var riskDesc string
	switch riskProfile {
	case "FULL_ADMIN":
		riskDesc = "Full Admin Access"
	case "BUCKET_ADMIN":
		riskDesc = "Bucket Admin Access"
	case "READ_ONLY":
		riskDesc = "Read-Only Access"
	case "NARROW_READ":
		riskDesc = "Narrow Read Access"
	default:
		riskDesc = "Access"
	}

	exposureDesc := ""
	if lambdaInfo.PublicLambdaURL && lambdaInfo.PublicAPIGateway {
		exposureDesc = "Function URL + API Gateway"
	} else if lambdaInfo.PublicLambdaURL {
		exposureDesc = "Function URL"
	} else if lambdaInfo.PublicAPIGateway {
		exposureDesc = "API Gateway"
	}

	return fmt.Sprintf("CRITICAL: %s S3 Bucket with Internet-Reachable Lambda (%s) - %s", exposureType, riskDesc, exposureDesc)
}

// isPubliclyExposed checks if an exposure type indicates public exposure
func isPubliclyExposed(exposureType string) bool {
	switch exposureType {
	case "Public":
		return true
	case "Public to all AWS accounts":
		return true
	case "Conditionally Public":
		return true
	case "Org-Restricted":
		return true
	default:
		return false
	}
}

// buildBreachPathOutput constructs an enhanced BreachPathOutput with all details
func buildBreachPathOutput(
	pathCounter int,
	bucket domain.S3CrownJewel,
	exposureResult *domain.ExposureResult,
	access *domain.PrincipalAccess,
	instance *domain.EC2InstanceInfo,
	accountID string,
	region string,
	pathType string,
) domain.BreachPathOutput {
	pathID := fmt.Sprintf("s3-breach-path-%d", pathCounter)
	bucketExposed := isPubliclyExposed(exposureResult.FinalExposure)

	// Build bucket info
	storeInfo := domain.StoreInfo{
		ResourceARN:      bucket.ARN,
		ResourceName:     bucket.Name,
		ResourceType:     "S3",
		Encrypted:        bucket.Encrypted,
		KMSKeyID:         bucket.KMSKeyID,
		IsCrownJewel:     true,
		CrownJewelReason: determineCrownJewelReason(bucket),
	}

	output := domain.BreachPathOutput{
		PathID:          pathID,
		PathType:        pathType,
		InternetExposed: pathType == "EC2_TO_BUCKET" && instance != nil && instance.InternetExposed,
		Store:           storeInfo,
		BucketExposed:   bucketExposed,
		ExposureDetails: exposureResult,
	}

	// Build path string
	if pathType == "EC2_TO_BUCKET" && instance != nil && access != nil {
		// Internet → EC2 Instance → Role → Bucket
		pathParts := []string{"Internet"}
		if instance.InternetExposed {
			if instance.PublicIP != nil {
				pathParts = append(pathParts, fmt.Sprintf("EC2 %s (%s)", instance.InstanceID, *instance.PublicIP))
			} else {
				pathParts = append(pathParts, fmt.Sprintf("EC2 %s", instance.InstanceID))
			}
			pathParts = append(pathParts, fmt.Sprintf("role %s", access.PrincipalName))
			pathParts = append(pathParts, fmt.Sprintf("%s (Bucket)", bucket.ARN))
		}
		output.PathString = strings.Join(pathParts, " → ")
		output.Container = buildEC2WorkloadInfo(instance, accountID, region)
		output.IAMRole = buildIAMRoleInfo(access)
	} else if pathType == "PUBLIC_BUCKET" {
		// Internet → Bucket ARN (Bucket)
		output.PathString = fmt.Sprintf("Internet → %s (Bucket)", bucket.ARN)
		output.InternetExposed = true // Bucket is publicly exposed
	}

	return output
}

// buildEC2WorkloadInfo constructs EC2WorkloadInfo from EC2InstanceInfo
func buildEC2WorkloadInfo(instance *domain.EC2InstanceInfo, accountID, region string) *domain.EC2WorkloadInfo {
	if instance == nil {
		return nil
	}

	instanceARN := fmt.Sprintf("arn:aws:ec2:%s:%s:instance/%s", instance.Region, accountID, instance.InstanceID)

	return &domain.EC2WorkloadInfo{
		InstanceID:       instance.InstanceID,
		InstanceARN:      instanceARN,
		Region:           instance.Region,
		VPCID:            instance.VPCID,
		SubnetID:         instance.SubnetID,
		SecurityGroupIDs: instance.SecurityGroupIDs,
		PublicIP:         instance.PublicIP,
		PrivateIP:        instance.PrivateIP,
		InternetExposed:  instance.InternetExposed,
		PublicExposure:   instance.PublicExposure,
	}
}

// buildIAMRoleInfo constructs IAMRoleInfo from PrincipalAccess
func buildIAMRoleInfo(access *domain.PrincipalAccess) *domain.IAMRoleInfo {
	if access == nil {
		return nil
	}

	return &domain.IAMRoleInfo{
		RoleARN:       access.PrincipalARN,
		RoleName:      access.PrincipalName,
		RiskProfile:   access.RiskProfile,
		AccessActions: access.AccessActions,
		PolicyDetails: access.PolicyDetails,
	}
}

// determineCrownJewelReason determines why a bucket is considered a crown jewel
func determineCrownJewelReason(bucket domain.S3CrownJewel) string {
	reasons := []string{}

	if bucket.Encrypted != nil && *bucket.Encrypted {
		reasons = append(reasons, "encrypted")
	}

	// Check if bucket name matches crown jewel patterns
	// Only pass true if it's KMS-encrypted (SSE-S3 should go through regex filters)
	kmsEncrypted := bucket.KMSKeyID != nil && *bucket.KMSKeyID != ""
	bucketARN := "arn:aws:s3:::" + bucket.Name
	if crownjewels.IsCrownJewel(bucketARN, bucket.Name, []map[string]string{}, kmsEncrypted) {
		if !kmsEncrypted {
			reasons = append(reasons, "name pattern match")
		}
	}

	if len(reasons) == 0 {
		return "crown jewel detection"
	}

	return strings.Join(reasons, ", ")
}

// buildStatusMessage creates a status message based on exposure and risk profile
func buildStatusMessage(exposureType string, riskProfile string) string {
	var riskDesc string
	switch riskProfile {
	case "FULL_ADMIN":
		riskDesc = "Full Admin Access"
	case "BUCKET_ADMIN":
		riskDesc = "Bucket Admin Access"
	case "READ_ONLY":
		riskDesc = "Read-Only Access"
	case "NARROW_READ":
		riskDesc = "Narrow Read Access"
	default:
		riskDesc = "Access"
	}

	return fmt.Sprintf("CRITICAL: %s S3 Bucket with Internet-Exposed EC2 (%s)", exposureType, riskDesc)
}

// ProcessS3ExposureAndKMSSeparation processes resource-specific steps 1.5, 2, and 3 for S3
// Step 1.5: KMS/Non-KMS separation
// Step 2: Exposure analysis
// Step 3: KMS vs Non-KMS output formatting
func ProcessS3ExposureAndKMSSeparation(
	ctx context.Context,
	breachSurfacer *app.BreachSurfacer,
	s3CrownJewels *[]domain.S3CrownJewel,
) (*domain.S3ResourceData, error) {
	if s3CrownJewels == nil || len(*s3CrownJewels) == 0 {
		return &domain.S3ResourceData{
			KMSBuckets:            []domain.S3CrownJewel{},
			NonKMSBuckets:         []domain.S3CrownJewel{},
			BucketToCMKMap:        make(map[string]string),
			CMKSet:                make(map[string]bool),
			ExposureMap:           make(map[string]*domain.ExposureResult),
			CrownJewelMap:         make(map[string]domain.S3CrownJewel),
			EncryptedResources:    []domain.EncryptedResource{},
			NonEncryptedResources: []domain.NonEncryptedResource{},
			AllBuckets:            []domain.S3CrownJewel{},
		}, nil
	}

	s3Svc := breachSurfacer.S3Client()
	metrics := logging.GetMetrics()

	allEncryptedResources := make([]domain.EncryptedResource, 0)
	allNonEncryptedResources := make([]domain.NonEncryptedResource, 0)

	// Get account ID for CMK ARN conversion
	accountIDForCMK, err := internalaws.GetAccountID(ctx)
	if err != nil {
		logging.LogWarn("Failed to get account ID", map[string]interface{}{"error": err.Error()})
		accountIDForCMK = "000000000000"
	}

	// Step 1.5: Collect CMKs from critical buckets and create mappings
	bucketToCMKMap := make(map[string]string)
	cmkSet := make(map[string]bool)
	kmsBuckets := make([]domain.S3CrownJewel, 0)
	nonKMSBuckets := make([]domain.S3CrownJewel, 0)

	for _, bucket := range *s3CrownJewels {
		if bucket.KMSKeyID != nil && *bucket.KMSKeyID != "" {
			keyID := *bucket.KMSKeyID
			var cmkARN string
			if strings.HasPrefix(keyID, "arn:aws:kms:") {
				cmkARN = keyID
			} else {
				bucketLocation, err := s3Svc.GetBucketLocation(ctx, &s3.GetBucketLocationInput{
					Bucket: aws.String(bucket.Name),
				})
				region := "us-east-1"
				if err == nil && bucketLocation.LocationConstraint != "" {
					region = string(bucketLocation.LocationConstraint)
					if region == "" {
						region = "us-east-1"
					}
				}
				cmkARN = fmt.Sprintf("arn:aws:kms:%s:%s:key/%s", region, accountIDForCMK, keyID)
			}
			bucketToCMKMap[bucket.Name] = cmkARN
			cmkSet[cmkARN] = true
			kmsBuckets = append(kmsBuckets, bucket)
			// Build encrypted resources list
			allEncryptedResources = append(allEncryptedResources, domain.EncryptedResource{
				ResourceARN:  bucket.ARN,
				CMKARN:       cmkARN,
				ResourceType: "S3",
			})
		} else {
			nonKMSBuckets = append(nonKMSBuckets, bucket)
			// Build non-encrypted resources list
			allNonEncryptedResources = append(allNonEncryptedResources, domain.NonEncryptedResource{
				ResourceARN:  bucket.ARN,
				ResourceType: "S3",
			})
		}
	}

	logging.LogInfo("Collected CMKs from critical buckets", map[string]interface{}{
		"total_cmks":      len(cmkSet),
		"kms_buckets":     len(kmsBuckets),
		"non_kms_buckets": len(nonKMSBuckets),
	})

	// Step 2: Analyze exposure for each critical bucket
	step2StartTime := time.Now()
	bucketExposureMap := make(map[string]*domain.ExposureResult)
	bucketCrownJewelMap := make(map[string]domain.S3CrownJewel)

	for _, bucket := range *s3CrownJewels {
		bucketName := bucket.Name
		bucketCrownJewelMap[bucketName] = bucket

		exposureStartTime := time.Now()
		exposureResult, err := exposure.AnalyzeStoreExposure(ctx, s3Svc, bucketName)
		exposureDuration := time.Since(exposureStartTime)

		if err != nil {
			metrics.RecordAPICall("AnalyzeStoreExposure", false, err)
			logging.LogWarn("Failed to analyze exposure for bucket", map[string]interface{}{
				"bucket": bucketName,
				"error":  err.Error(),
			})
			exposureResult = &domain.ExposureResult{
				ResourceName:  bucketName,
				FinalExposure: "Unknown",
			}
		} else {
			metrics.RecordAPICall("AnalyzeStoreExposure", true, nil)
			logging.LogAPICall("AnalyzeStoreExposure", true, exposureDuration, nil)
		}
		bucketExposureMap[bucketName] = exposureResult
	}
	step2Duration := time.Since(step2StartTime)

	// Output Step 2: Directly Exposed Buckets
	fmt.Print(outputter.FormatStepOutputWithTiming(2, "Directly Exposed Buckets",
		"Analyzing public access vectors (bucket policies, ACLs, PAB)",
		bucketExposureMap, step2Duration))

	// Step 3: KMS vs Non-KMS (already computed above, just output)
	step3StartTime := time.Now()
	step3Duration := time.Since(step3StartTime)

	// Output Step 3: KMS vs Non-KMS
	fmt.Print(outputter.FormatStepOutputWithTiming(3, "KMS vs Non-KMS",
		"Mapping encryption keys to buckets and separating KMS-encrypted from non-KMS buckets",
		struct {
			KMSBuckets     []domain.S3CrownJewel
			NonKMSBuckets  []domain.S3CrownJewel
			BucketToCMKMap map[string]string
		}{kmsBuckets, nonKMSBuckets, bucketToCMKMap}, step3Duration))

	return &domain.S3ResourceData{
		KMSBuckets:            kmsBuckets,
		NonKMSBuckets:         nonKMSBuckets,
		BucketToCMKMap:        bucketToCMKMap,
		CMKSet:                cmkSet,
		ExposureMap:           bucketExposureMap,
		CrownJewelMap:         bucketCrownJewelMap,
		EncryptedResources:    allEncryptedResources,
		NonEncryptedResources: allNonEncryptedResources,
		AllBuckets:            *s3CrownJewels,
	}, nil
}

// VerifyS3Authorization performs all S3 role-resource pairs authorization verification
func VerifyS3Authorization(
	ctx context.Context,
	breachSurfacer *app.BreachSurfacer,
	allS3Resources []domain.S3CrownJewel,
	resourceToRolesMap map[string][]string,
	criticalRolesSet map[string]bool,
	cmkToRolesMap map[string][]string,
	resourceToCMKMap map[string]map[string]string,
) (map[string][]domain.PrincipalAccess, error) {
	iamSvc := breachSurfacer.IAMClient()
	kmsSvc := breachSurfacer.KMSClient()
	s3Svc := breachSurfacer.S3Client()

	logging.LogDebug("--- Step 3e: Verifying Authorization for Principal Access ---")
	principalAccessResults := make(map[string][]domain.PrincipalAccess)

	rolesToVerify := buildRolesToVerifySet(criticalRolesSet, resourceToRolesMap)

	for _, resource := range allS3Resources {
		rolesToCheck := determineRolesToCheck(resource, resourceToRolesMap, rolesToVerify, cmkToRolesMap, resourceToCMKMap)

		for _, roleARN := range rolesToCheck {
			riskProfile := determineRiskProfile(resource, roleARN, cmkToRolesMap, resourceToCMKMap)
			authResult := verifyRoleResourceAuthorization(ctx, iamSvc, kmsSvc, s3Svc, roleARN, resource)

			access := buildPrincipalAccess(roleARN, resource, riskProfile, authResult)
			principalAccessResults[resource.ARN] = append(principalAccessResults[resource.ARN], access)
		}
	}

	updateCriticalRolesSet(principalAccessResults, criticalRolesSet)
	logging.LogDebug(fmt.Sprintf("After authorization filtering: %d roles have exploitable access", len(criticalRolesSet)))

	return principalAccessResults, nil
}

// buildRolesToVerifySet collects all roles that need verification
func buildRolesToVerifySet(criticalRolesSet map[string]bool, resourceToRolesMap map[string][]string) map[string]bool {
	rolesToVerify := make(map[string]bool)
	for roleARN := range criticalRolesSet {
		rolesToVerify[roleARN] = true
	}
	for _, roleARNs := range resourceToRolesMap {
		for _, roleARN := range roleARNs {
			rolesToVerify[roleARN] = true
		}
	}
	return rolesToVerify
}

// determineRolesToCheck determines which roles should be checked for a given resource
func determineRolesToCheck(
	resource domain.S3CrownJewel,
	resourceToRolesMap map[string][]string,
	rolesToVerify map[string]bool,
	cmkToRolesMap map[string][]string,
	resourceToCMKMap map[string]map[string]string,
) []string {
	// If resource has direct role mappings, use those
	if roleARNs, hasRoles := resourceToRolesMap[resource.ARN]; hasRoles && len(roleARNs) > 0 {
		return roleARNs
	}

	// For KMS-encrypted resources, check CMK access
	if resource.KMSKeyID != nil && *resource.KMSKeyID != "" {
		return getRolesWithCMKAccess(resource, rolesToVerify, cmkToRolesMap, resourceToCMKMap)
	}

	// For non-KMS resources, check all verified roles
	return getAllVerifiedRoles(rolesToVerify)
}

// getRolesWithCMKAccess returns roles that have access to the resource's CMK
func getRolesWithCMKAccess(
	resource domain.S3CrownJewel,
	rolesToVerify map[string]bool,
	cmkToRolesMap map[string][]string,
	resourceToCMKMap map[string]map[string]string,
) []string {
	s3CMKMap := resourceToCMKMap["S3"]
	if s3CMKMap == nil {
		return []string{}
	}

	cmkARN := s3CMKMap[resource.Name]
	if cmkARN == "" {
		return []string{}
	}

	cmkRoleARNs, ok := cmkToRolesMap[cmkARN]
	if !ok {
		return []string{}
	}

	rolesToCheck := make([]string, 0)
	for _, roleARN := range cmkRoleARNs {
		if rolesToVerify[roleARN] {
			rolesToCheck = append(rolesToCheck, roleARN)
		}
	}
	return rolesToCheck
}

// getAllVerifiedRoles returns all verified roles as a slice
func getAllVerifiedRoles(rolesToVerify map[string]bool) []string {
	roles := make([]string, 0, len(rolesToVerify))
	for roleARN := range rolesToVerify {
		roles = append(roles, roleARN)
	}
	return roles
}

// determineRiskProfile determines the risk profile for a role-resource pair
func determineRiskProfile(
	resource domain.S3CrownJewel,
	roleARN string,
	cmkToRolesMap map[string][]string,
	resourceToCMKMap map[string]map[string]string,
) string {
	if resource.KMSKeyID == nil || *resource.KMSKeyID == "" {
		return "S3_ACCESS"
	}

	s3CMKMap := resourceToCMKMap["S3"]
	if s3CMKMap == nil {
		return "S3_ACCESS"
	}

	cmkARN := s3CMKMap[resource.Name]
	if cmkARN == "" {
		return "S3_ACCESS"
	}

	cmkRoleARNs, ok := cmkToRolesMap[cmkARN]
	if !ok {
		return "S3_ACCESS"
	}

	for _, cmkRoleARN := range cmkRoleARNs {
		if cmkRoleARN == roleARN {
			return "KMS_DECRYPT"
		}
	}
	return "S3_ACCESS"
}

// verifyRoleResourceAuthorization verifies authorization for a role-resource pair
func verifyRoleResourceAuthorization(
	ctx context.Context,
	iamSvc *iam.Client,
	kmsSvc *kms.Client,
	s3Svc *s3.Client,
	roleARN string,
	resource domain.S3CrownJewel,
) *domain.AuthorizationResult {
	if kmsSvc == nil {
		logging.LogDebug(fmt.Sprintf("No KMS client available, skipping KMS verification for %s on %s", roleARN, resource.ARN))
		return &domain.AuthorizationResult{
			ResourceAccessAllowed: true,
			Exploitable:     true,
		}
	}

	logging.LogDebug(fmt.Sprintf("Verifying authorization for role %s on bucket %s", roleARN, resource.ARN))
	authResult, err := authorization.VerifyAuthorization(ctx, iamSvc, kmsSvc, s3Svc, roleARN, resource.ARN)
	if err != nil {
		logging.LogWarn("VerifyAuthorization returned error", map[string]interface{}{
			"role_arn":   roleARN,
			"bucket_arn": resource.ARN,
			"error":      err.Error(),
		})
		return &domain.AuthorizationResult{
			ResourceAccessAllowed: true,
			Exploitable:     false,
			SimulationDetails: map[string]interface{}{
				"verification_error": err.Error(),
			},
		}
	}

	logAuthorizationResult(roleARN, resource.ARN, authResult, resource)
	return authResult
}

// logAuthorizationResult logs the authorization verification result
func logAuthorizationResult(roleARN, resourceARN string, authResult *domain.AuthorizationResult, resource domain.S3CrownJewel) {
	kmsAllowed := authResult.KMSDecryptAllowed != nil && *authResult.KMSDecryptAllowed
	reason := buildAuthorizationReason(authResult, resource, kmsAllowed)

	logging.LogDebug(fmt.Sprintf("Authorization verification result for %s on %s: S3Allowed=%v, KMSAllowed=%v, Exploitable=%v%s",
		roleARN, resourceARN,
		authResult.ResourceAccessAllowed,
		kmsAllowed,
		authResult.Exploitable, reason))
}

// buildAuthorizationReason builds a reason string for authorization denial
func buildAuthorizationReason(authResult *domain.AuthorizationResult, resource domain.S3CrownJewel, kmsAllowed bool) string {
	if authResult.SimulationDetails == nil {
		return ""
	}

	if bucketDeny, ok := authResult.SimulationDetails["bucket_policy_deny"].(bool); ok && bucketDeny {
		return " (bucket policy denies access)"
	}
	if !authResult.ResourceAccessAllowed {
		return " (IAM policy denies access)"
	}
	if !kmsAllowed && resource.KMSKeyID != nil && *resource.KMSKeyID != "" {
		return " (KMS decrypt denied)"
	}
	return ""
}

// buildPrincipalAccess creates a PrincipalAccess object
func buildPrincipalAccess(roleARN string, resource domain.S3CrownJewel, riskProfile string, authResult *domain.AuthorizationResult) domain.PrincipalAccess {
	return domain.PrincipalAccess{
		PrincipalARN:  roleARN,
		PrincipalType: "role",
		PrincipalName: outputter.ExtractRoleNameFromARN(roleARN),
		ResourceARN:   resource.ARN,
		ResourceName:  resource.Name,
		RiskProfile:   riskProfile,
		Authorization: authResult,
	}
}

// updateCriticalRolesSet updates the critical roles set based on authorization results
// This function only ADDS exploitable roles, never removes them.
// This ensures roles exploitable for one resource type (S3) aren't removed
// when verifying another resource type (RDS).
func updateCriticalRolesSet(principalAccessResults map[string][]domain.PrincipalAccess, criticalRolesSet map[string]bool) {
	for _, accesses := range principalAccessResults {
		for _, access := range accesses {
			if access.Authorization == nil {
				continue
			}

			if access.Authorization.Exploitable {
				criticalRolesSet[access.PrincipalARN] = true
			}
		}
	}
}

// buildS3BreachPaths performs resource-specific Step 11: Build S3 breach paths
// This uses shared data from previous steps (computeResourcesMapping, principalAccessResults)
func buildS3BreachPaths(
	ctx context.Context,
	breachSurfacer *app.BreachSurfacer,
	s3Data *domain.S3ResourceData,
	sharedIAMData *domain.SharedIAMData,
	computeResourcesMapping domain.RoleToComputeResourcesMapping,
) ([]domain.BreachPath, []domain.BreachPathOutput, error) {
	step11StartTime := time.Now()
	breachPaths := make([]domain.BreachPath, 0)
	breachPathOutputs := make([]domain.BreachPathOutput, 0)
	pathCounter := 0

	accountID, err := internalaws.GetAccountID(ctx)
	if err != nil {
		logging.LogWarn("Failed to get account ID, using placeholder", map[string]interface{}{"error": err.Error()})
		accountID = "000000000000"
	}

	ec2Client, err := internalaws.GetAWSClient(ctx, "ec2")
	if err != nil {
		logging.LogWarn("Failed to get EC2 client", map[string]interface{}{"error": err.Error()})
	}
	var region string
	if ec2Client != nil {
		ec2Svc := ec2Client.(*ec2.Client)
		region = ec2Svc.Options().Region
	}
	if region == "" {
		region = "us-east-1"
	}

	filteredRolesAtStep11 := make(map[string]string)
	filteredWorkloadsAtStep11 := make([]domain.DroppedWorkloadInfo, 0)

	// Build lateral movement map
	lateralRoleToAssumableRoles := make(map[string][]string)
	for _, lateralRole := range sharedIAMData.LateralMovementRoles {
		lateralRoleToAssumableRoles[lateralRole.RoleARN] = lateralRole.CanAssumeRoles
	}

	lateralMovementMap := make(map[string]bool)
	for _, role := range sharedIAMData.LateralMovementRoles {
		lateralMovementMap[role.RoleARN] = true
	}

	privilegeEscalationMap := make(map[string]bool)
	for _, role := range sharedIAMData.PrivilegeEscalationRoles {
		privilegeEscalationMap[role.RoleARN] = true
	}

	// Get clients for network boundary checks
	s3Svc := breachSurfacer.S3Client()
	ec2Svc := breachSurfacer.EC2Client()

	// Initialize network boundary orchestrator for comprehensive checks
	// This replaces the simple VPC deny check with full invariant checking:
	// NB-001 to NB-007 (VPC conditions, VPCE conditions, endpoint policies)
	var networkOrchestrator *network.NetworkBoundaryOrchestrator
	if s3Svc != nil {
		networkOrchestrator = network.NewOrchestrator(s3Svc, ec2Svc)
	}

	// Note: VPC deny checks are now handled by the network orchestrator (CheckBoundariesForS3)
	// which performs comprehensive invariant checking (NB-001 through NB-007)

	// Case 1: Internet-exposed compute resources with access to critical buckets
	for bucketARN, accesses := range sharedIAMData.PrincipalAccessResults {
		bucket := s3Data.CrownJewelMap[domain.ExtractBucketNameFromARN(bucketARN)]
		if bucket.ARN == "" {
			continue
		}

		bucketName := bucket.Name
		exposureResult := s3Data.ExposureMap[bucketName]
		if exposureResult == nil {
			exposureResult = &domain.ExposureResult{
				ResourceName:  bucketName,
				FinalExposure: "Unknown",
			}
		}

		for _, access := range accesses {
			if access.PrincipalType != "role" {
				continue
			}

			roleARN := access.PrincipalARN
			computeResources, hasResources := computeResourcesMapping[roleARN]

			// Handle lateral movement paths
			if !hasResources || len(computeResources) == 0 {
				for lateralRoleARN, assumableRoles := range lateralRoleToAssumableRoles {
					for _, assumableRoleARN := range assumableRoles {
						if assumableRoleARN == roleARN {
							lateralComputeResources, hasLateralResources := computeResourcesMapping[lateralRoleARN]
							if hasLateralResources && len(lateralComputeResources) > 0 {
								computeResources = lateralComputeResources
								hasResources = true
								break
							}
						}
					}
					if hasResources {
						break
					}
				}
				if !hasResources || len(computeResources) == 0 {
					continue
				}
			}

			for _, computeResource := range computeResources {
				// STEP 1: IAM/KMS Authorization Check (O(1) - precomputed boolean)
				// This is checked FIRST because it's just reading a cached result.
				// The actual SimulatePrincipalPolicy was done in Steps 4-5.
				if access.Authorization != nil && !access.Authorization.Exploitable {
					if !access.Authorization.ResourceAccessAllowed {
						continue
					}
					if bucket.KMSKeyID != nil && *bucket.KMSKeyID != "" {
						if access.Authorization.KMSDecryptAllowed != nil && !*access.Authorization.KMSDecryptAllowed {
							continue
						}
					}
				}

				// STEP 2: Network Boundary Check (O(n) - requires parsing/API calls)
				// Only run this AFTER IAM passes, since it's more expensive.
				// Checks: VPC conditions (NB-001 to NB-003), VPCE conditions (NB-004 to NB-007)
				if networkOrchestrator != nil {
					boundaryResult := networkOrchestrator.CheckBoundariesForS3(
						ctx, &computeResource, bucketARN, bucketName)
					
					if boundaryResult.AnyBlocks {
						// Update authorization result with network boundary info
						if access.Authorization != nil {
							access.Authorization.NetworkBoundaries = boundaryResult
							access.Authorization.BlockedByNetwork = true
							access.Authorization.Exploitable = false
						}
						logging.LogDebug("Path blocked by network boundary", map[string]interface{}{
							"compute":   computeResource.ResourceID,
							"bucket":    bucketName,
							"blockers":  boundaryResult.BlockingChecks,
						})
						continue // Skip this path - network boundary blocks it
					}
				}

				pathCounter++

				isLateralPath := false
				lateralRoleARN := ""
				if computeResource.RoleARN != roleARN {
					if assumableRoles, ok := lateralRoleToAssumableRoles[computeResource.RoleARN]; ok {
						for _, assumableRoleARN := range assumableRoles {
							if assumableRoleARN == roleARN {
								isLateralPath = true
								lateralRoleARN = computeResource.RoleARN
								break
							}
						}
					}
				}

				hasLateralMovement := lateralMovementMap[roleARN] || isLateralPath
				hasPrivilegeEscalation := privilegeEscalationMap[roleARN]

				breachPath := buildBreachPathFromComputeResource(
					pathCounter,
					bucket,
					exposureResult,
					access,
					computeResource,
					accountID,
					isLateralPath,
					lateralRoleARN,
				)
				breachPath.LateralMovement = hasLateralMovement
				breachPath.PrivilegeEscalation = hasPrivilegeEscalation
				breachPaths = append(breachPaths, breachPath)

				output := buildBreachPathOutputFromComputeResource(
					pathCounter,
					bucket,
					exposureResult,
					&access,
					computeResource,
					isLateralPath,
					lateralRoleARN,
				)
				output.Authorization = access.Authorization
				output.LateralMovement = hasLateralMovement
				output.PrivilegeEscalation = hasPrivilegeEscalation
				breachPathOutputs = append(breachPathOutputs, output)
			}
		}
	}

	// Case 2: Publicly exposed critical buckets (direct public access)
	for _, bucket := range s3Data.AllBuckets {
		bucketName := bucket.Name
		exposureResult := s3Data.ExposureMap[bucketName]
		if exposureResult == nil {
			continue
		}

		isPublicBucket := isPubliclyExposed(exposureResult.FinalExposure)
		isTestPublicBucket := strings.Contains(strings.ToLower(bucketName), "public-test-bucket")

		if isPublicBucket || isTestPublicBucket {
			pathCounter++

			publicBreachPath := domain.BreachPath{
				PathID:      fmt.Sprintf("s3-breach-path-public-%d", pathCounter),
				Vector:      "Public",
				ResourceID:  bucketName,
				ResourceARN: &bucket.ARN,
				TargetDB:    bucket.ARN,
				TargetType:  "S3",
				Status:      fmt.Sprintf("Public S3 Bucket (%s)", exposureResult.FinalExposure),
			}
			if bucket.Encrypted != nil {
				publicBreachPath.TargetEncrypted = bucket.Encrypted
			}
			if bucket.KMSKeyID != nil {
				publicBreachPath.KMSKeyID = bucket.KMSKeyID
			}
			breachPaths = append(breachPaths, publicBreachPath)

			output := buildBreachPathOutput(
				pathCounter,
				bucket,
				exposureResult,
				nil,
				nil,
				accountID,
				region,
				"PUBLIC_BUCKET",
			)
			breachPathOutputs = append(breachPathOutputs, output)
		}
	}

	step11Duration := time.Since(step11StartTime)

	fmt.Print(outputter.FormatStepOutputWithTiming(11, "Breach Paths",
		"Final attack path enumeration from internet-exposed workloads to crown jewels",
		struct {
			BreachPaths       []domain.BreachPath
			FilteredRoles     map[string]string
			FilteredWorkloads []domain.DroppedWorkloadInfo
		}{breachPaths, filteredRolesAtStep11, filteredWorkloadsAtStep11}, step11Duration))

	return breachPaths, breachPathOutputs, nil
}
