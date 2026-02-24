package breachpath

import (
	"breachmap/internal/app"
	"breachmap/internal/authorization"
	"breachmap/internal/compute"
	"breachmap/internal/domain"
	"breachmap/internal/iam"
	"breachmap/internal/logging"
	"breachmap/internal/outputter"
	"context"
	"fmt"
	"time"
)

// MapToComputeResourcesShared performs shared Step 10: Map roles to internet-exposed compute resources
func MapToComputeResourcesShared(
	ctx context.Context,
	breachSurfacer *app.BreachSurfacer,
	criticalRoles []string,
) (domain.RoleToComputeResourcesMapping, error) {
	step10StartTime := time.Now()
	logging.LogDebug("--- Step 10: Mapping Roles to EC2/Lambda and Checking Internet Exposure ---")

	ec2Mapping, err := compute.MapRolesToEC2Instances(ctx, criticalRoles)
	if err != nil {
		logging.LogWarn("Failed to map roles to EC2 instances", map[string]interface{}{"error": err.Error()})
		ec2Mapping = make(domain.RoleToInstancesMapping)
	}

	if len(ec2Mapping) > 0 {
		if err := compute.EnrichInstancesWithPublicExposure(ctx, ec2Mapping); err != nil {
			logging.LogWarn("Failed to enrich instances with public exposure info", map[string]interface{}{"error": err.Error()})
		}
	}

	lambdaMapping, err := compute.MapRolesToLambdaFunctions(ctx, criticalRoles)
	if err != nil {
		logging.LogWarn("Failed to map roles to Lambda functions", map[string]interface{}{"error": err.Error()})
		lambdaMapping = make(domain.RoleToLambdasMapping)
	}

	if len(lambdaMapping) > 0 {
		if err := compute.EnrichLambdasWithPublicExposure(ctx, lambdaMapping); err != nil {
			logging.LogWarn("Failed to enrich Lambda functions with exposure", map[string]interface{}{"error": err.Error()})
		}
	}

	computeResourcesMapping, err := compute.GetWorkloadsForRole(ctx, criticalRoles, ec2Mapping, lambdaMapping)
	if err != nil {
		logging.LogWarn("Failed to create unified compute resources mapping", map[string]interface{}{"error": err.Error()})
		computeResourcesMapping = make(domain.RoleToComputeResourcesMapping)
	}

	step10Duration := time.Since(step10StartTime)

	// Output Step 10: Internet-Exposed Workloads
	fmt.Print(outputter.FormatStepOutput(domain.Step10ComputeMapping, computeResourcesMapping, step10Duration))

	return computeResourcesMapping, nil
}

// FindNonKMSPrincipalsShared performs shared Step 5: Find roles with access to non-KMS resources
// This works for all resource types since IAM analysis is resource-agnostic
func FindNonKMSPrincipalsShared(
	ctx context.Context,
	breachSurfacer *app.BreachSurfacer,
	allNonEncryptedResources []domain.NonEncryptedResource,
) (*domain.SharedIAMData, error) {
	iamSvc := breachSurfacer.IAMClient()

	step5StartTime := time.Now()
	resourceToRolesMap := make(map[string][]string)
	criticalRolesSet := make(map[string]bool)

	// Group resources by type for efficient IAM analysis
	resourcesByType := make(map[string][]string)
	for _, res := range allNonEncryptedResources {
		resourcesByType[res.ResourceType] = append(resourcesByType[res.ResourceType], res.ResourceARN)
	}

	// S3 non-KMS analysis
	if s3ARNs, ok := resourcesByType["S3"]; ok && len(s3ARNs) > 0 {
		logging.LogDebug("--- Step 5: Non-KMS S3 Buckets - Using S3 Access Detection ---")
		s3RoleARNs, err := iam.FilterRolesForS3Access(ctx, iamSvc, s3ARNs)
		if err != nil {
			logging.LogWarn("Failed to filter S3 roles for non-KMS buckets", map[string]interface{}{"error": err.Error()})
		} else if len(s3RoleARNs) > 0 {
			nonKMSBucketToRolesMap, err := authorization.ValidateS3AccessForRoles(ctx, iamSvc, s3RoleARNs, s3ARNs)
			if err != nil {
				logging.LogWarn("Failed to validate S3 access for non-KMS buckets", map[string]interface{}{"error": err.Error()})
			} else {
				for bucketARN, roleARNs := range nonKMSBucketToRolesMap {
					resourceToRolesMap[bucketARN] = roleARNs
					for _, roleARN := range roleARNs {
						criticalRolesSet[roleARN] = true
					}
				}
			}
		}
	}

	// RDS non-KMS analysis
	if rdsARNs, ok := resourcesByType["RDS"]; ok && len(rdsARNs) > 0 {
		logging.LogDebug("--- Step 5: Non-KMS RDS Databases - Using RDS Access Detection ---")
		rdsRoleARNs, err := iam.FilterRolesForRDSAccess(ctx, iamSvc, rdsARNs)
		if err != nil {
			logging.LogWarn("Failed to filter RDS roles for non-KMS databases", map[string]interface{}{"error": err.Error()})
		} else if len(rdsRoleARNs) > 0 {
			nonKMSDBToRolesMap, err := authorization.ValidateRDSAccessForRoles(ctx, iamSvc, rdsRoleARNs, rdsARNs)
			if err != nil {
				logging.LogWarn("Failed to validate RDS access for non-KMS databases", map[string]interface{}{"error": err.Error()})
			} else {
				for dbARN, roleARNs := range nonKMSDBToRolesMap {
					resourceToRolesMap[dbARN] = roleARNs
					for _, roleARN := range roleARNs {
						criticalRolesSet[roleARN] = true
					}
				}
			}
		}
	}

	step5Duration := time.Since(step5StartTime)

	// Output Step 5: Non-KMS Principals
	fmt.Print(outputter.FormatStepOutput(domain.Step5NonKMSPrincipals, resourceToRolesMap, step5Duration))

	return &domain.SharedIAMData{
		ResourceToRolesMap: resourceToRolesMap,
		CriticalRolesSet:   criticalRolesSet,
	}, nil
}

// BuildSeedRiskyPrincipalsShared performs shared Step 6: Build seed of risky principals
func BuildSeedRiskyPrincipalsShared(criticalRoles []string) []string {
	step6StartTime := time.Now()
	seedRiskyRoles := make([]string, len(criticalRoles))
	copy(seedRiskyRoles, criticalRoles)
	step6Duration := time.Since(step6StartTime)

	fmt.Print(outputter.FormatStepOutput(domain.Step6SeedRiskyPrincipals, seedRiskyRoles, step6Duration))

	return seedRiskyRoles
}

// FindLateralRiskShared performs shared Step 7: Find roles with lateral movement capabilities
func FindLateralRiskShared(
	ctx context.Context,
	breachSurfacer *app.BreachSurfacer,
	seedRiskyRoles []string,
) ([]domain.LateralMovementRole, error) {
	iamSvc := breachSurfacer.IAMClient()

	step7StartTime := time.Now()
	logging.LogDebug("--- Step 7: Augmenting Critical Roles with Lateral Movement ---")
	lateralMovementRoles := make([]domain.LateralMovementRole, 0)

	if len(seedRiskyRoles) > 0 {
		lateralRoles, err := iam.FindLateralMovement(ctx, iamSvc, seedRiskyRoles)
		if err != nil {
			logging.LogWarn("Failed to find lateral movement roles", map[string]interface{}{"error": err.Error()})
		} else {
			lateralMovementRoles = lateralRoles
			logging.LogDebug(fmt.Sprintf("Found %d roles with lateral movement capabilities", len(lateralRoles)))
		}
	}

	step7Duration := time.Since(step7StartTime)

	fmt.Print(outputter.FormatStepOutput(domain.Step7LateralRisk, lateralMovementRoles, step7Duration))

	return lateralMovementRoles, nil
}

// FindPrivilegeEscalationRiskShared performs shared Step 8: Find roles with privilege escalation capabilities
func FindPrivilegeEscalationRiskShared(
	ctx context.Context,
	breachSurfacer *app.BreachSurfacer,
) ([]domain.PrivilegeEscalationRole, error) {
	iamSvc := breachSurfacer.IAMClient()

	step8StartTime := time.Now()
	privilegeEscalationRoles := make([]domain.PrivilegeEscalationRole, 0)

	escalationRoles, err := iam.FindPrivilegeEscalation(ctx, iamSvc)
	if err != nil {
		logging.LogWarn("Failed to find privilege escalation roles", map[string]interface{}{"error": err.Error()})
	} else {
		privilegeEscalationRoles = escalationRoles
		logging.LogDebug(fmt.Sprintf("Found %d roles with privilege escalation capabilities", len(escalationRoles)))
	}

	step8Duration := time.Since(step8StartTime)

	fmt.Print(outputter.FormatStepOutput(domain.Step8PrivilegeEscalation, privilegeEscalationRoles, step8Duration))

	return privilegeEscalationRoles, nil
}

// BuildBreachSurfaceShared performs shared Step 9: Build breach surface of principals
func BuildBreachSurfaceShared(
	seedRiskyRoles []string,
	lateralMovementRoles []domain.LateralMovementRole,
	privilegeEscalationRoles []domain.PrivilegeEscalationRole,
) []string {
	step9StartTime := time.Now()

	criticalRolesSet := make(map[string]bool)
	for _, roleARN := range seedRiskyRoles {
		criticalRolesSet[roleARN] = true
	}
	for _, role := range lateralMovementRoles {
		criticalRolesSet[role.RoleARN] = true
	}
	for _, role := range privilegeEscalationRoles {
		criticalRolesSet[role.RoleARN] = true
	}

	criticalRoles := make([]string, 0, len(criticalRolesSet))
	for roleARN := range criticalRolesSet {
		criticalRoles = append(criticalRoles, roleARN)
	}

	logging.LogDebug(fmt.Sprintf("Total risky roles (critical + lateral movement + privilege escalation): %d", len(criticalRoles)))
	step9Duration := time.Since(step9StartTime)

	fmt.Print(outputter.FormatStepOutput(domain.Step9BreachSurface, criticalRoles, step9Duration))

	return criticalRoles
}

// FindKMSPrincipalsShared performs shared Step 4: Find roles with KMS decrypt permissions
// This works for all resource types (S3, RDS, DynamoDB) since IAM analysis is resource-agnostic
func FindKMSPrincipalsShared(
	ctx context.Context,
	breachSurfacer *app.BreachSurfacer,
	allEncryptedResources []domain.EncryptedResource,
	resourceToCMKMap map[string]map[string]string, // resourceType -> resourceName -> CMKARN
) (*domain.SharedIAMData, error) {
	iamSvc := breachSurfacer.IAMClient()
	kmsSvc := breachSurfacer.KMSClient()

	step4StartTime := time.Now()
	bucketToRolesMap := make(map[string][]string)
	criticalRolesSet := make(map[string]bool)
	cmkToRolesMap := make(map[string][]string)
	roleToCMKsMap := make(map[string][]string)
	roleToActionTypeMap := make(map[string]string)
	filteredRolesAtStep4 := make([]domain.FilteredRoleInfo, 0)

	// Collect all unique CMKs from all encrypted resources
	cmkSet := make(map[string]bool)
	for _, res := range allEncryptedResources {
		cmkSet[res.CMKARN] = true
	}

	if len(allEncryptedResources) > 0 && kmsSvc != nil && len(cmkSet) > 0 {
		logging.LogDebug("--- Step 4a: KMS Resources - Starting with KMS Decrypt Detection ---")

		// Step 1: Find ALL roles with KMS action indicators
		kmsRoleARNs, err := iam.FilterRolesForKMSActions(ctx, iamSvc)
		if err != nil {
			logging.LogWarn("Failed to filter KMS roles", map[string]interface{}{"error": err.Error()})
			kmsRoleARNs = []string{}
		} else {
			logging.LogDebug(fmt.Sprintf("Found %d roles with KMS action patterns", len(kmsRoleARNs)))
		}

		// Step 2: Validate which of these roles can actually decrypt the CMKs
		if len(kmsRoleARNs) > 0 {
			logging.LogDebug(fmt.Sprintf("Validating KMS decrypt for %d roles against %d CMKs", len(kmsRoleARNs), len(cmkSet)))
			var tempRoleToActionTypeMap map[string]string
			cmkToRolesMap, roleToCMKsMap, tempRoleToActionTypeMap, err = authorization.ValidateKMSDecryptForRoles(ctx, iamSvc, kmsSvc, kmsRoleARNs, cmkSet)
			for roleARN, actionType := range tempRoleToActionTypeMap {
				roleToActionTypeMap[roleARN] = actionType
			}
			if err != nil {
				logging.LogWarn("Failed to validate KMS decrypt", map[string]interface{}{"error": err.Error()})
			} else {
				logging.LogDebug(fmt.Sprintf("KMS decrypt validation: %d roles can decrypt %d CMKs", len(roleToCMKsMap), len(cmkToRolesMap)))
				for roleARN := range roleToCMKsMap {
					criticalRolesSet[roleARN] = true
				}
			}
		}

		// Step 3: For each encrypted resource, verify resource-specific access
		// Step 4b: For S3 KMS buckets - verify S3 access for roles with KMS decrypt
		s3KMSResources := make([]domain.EncryptedResource, 0)
		s3KMSBucketARNs := make([]string, 0)
		for _, res := range allEncryptedResources {
			if res.ResourceType == "S3" {
				s3KMSResources = append(s3KMSResources, res)
				s3KMSBucketARNs = append(s3KMSBucketARNs, res.ResourceARN)
			}
		}

		if len(roleToCMKsMap) > 0 && len(s3KMSBucketARNs) > 0 {
			logging.LogDebug("--- Step 4b: Verifying S3 Access for Roles with KMS Decrypt ---")
			rolesWithDecrypt := make([]string, 0, len(roleToCMKsMap))
			for roleARN := range roleToCMKsMap {
				rolesWithDecrypt = append(rolesWithDecrypt, roleARN)
			}

			kmsBucketToRolesMap, err := authorization.ValidateS3AccessForRoles(ctx, iamSvc, rolesWithDecrypt, s3KMSBucketARNs)
			if err != nil {
				logging.LogWarn("Failed to validate S3 access for KMS decrypt roles", map[string]interface{}{"error": err.Error()})
			} else {
				for _, res := range s3KMSResources {
					bucketARN := res.ResourceARN
					cmkARN := res.CMKARN

					decryptableRoles, hasDecryptableRoles := cmkToRolesMap[cmkARN]
					if !hasDecryptableRoles {
						continue
					}

					rolesWithS3Access, hasS3Access := kmsBucketToRolesMap[bucketARN]

					decryptableRoleSet := make(map[string]bool)
					for _, roleARN := range decryptableRoles {
						decryptableRoleSet[roleARN] = true
					}

					s3AccessRoleSet := make(map[string]bool)
					if hasS3Access {
						for _, roleARN := range rolesWithS3Access {
							s3AccessRoleSet[roleARN] = true
						}
					}

					// Track filtered roles
					for _, roleARN := range decryptableRoles {
						if !s3AccessRoleSet[roleARN] {
							alreadyTracked := false
							for _, filtered := range filteredRolesAtStep4 {
								if filtered.RoleARN == roleARN && filtered.ResourceARN == bucketARN {
									alreadyTracked = true
									break
								}
							}
							if !alreadyTracked {
								filteredRolesAtStep4 = append(filteredRolesAtStep4, domain.FilteredRoleInfo{
									RoleARN:     roleARN,
									ResourceARN: bucketARN,
									Reason:      "no_s3_access",
								})
							}
						}
					}

					if hasS3Access {
						for _, roleARN := range rolesWithS3Access {
							if !decryptableRoleSet[roleARN] {
								alreadyTracked := false
								for _, filtered := range filteredRolesAtStep4 {
									if filtered.RoleARN == roleARN && filtered.ResourceARN == bucketARN {
										alreadyTracked = true
										break
									}
								}
								if !alreadyTracked {
								filteredRolesAtStep4 = append(filteredRolesAtStep4, domain.FilteredRoleInfo{
									RoleARN:     roleARN,
									ResourceARN: bucketARN,
									Reason:      "kms_decrypt_denied",
								})
								}
							}
						}
					}

					// Find intersection: roles that can decrypt AND have S3 access
					validRoles := make([]string, 0)
					if hasS3Access {
						for _, roleARN := range rolesWithS3Access {
							if decryptableRoleSet[roleARN] {
								validRoles = append(validRoles, roleARN)
							}
						}
					}

					if len(validRoles) > 0 {
						bucketToRolesMap[bucketARN] = validRoles
					}
				}
			}
		}
	}

	step4Duration := time.Since(step4StartTime)

	// Output Step 4: KMS Principals
	fmt.Print(outputter.FormatStepOutput(domain.Step4KMSPrincipals, struct {
		CMKToRolesMap       map[string][]string
		RoleToCMKsMap       map[string][]string
		RoleToActionTypeMap map[string]string
		FilteredRoles       []domain.FilteredRoleInfo
	}{cmkToRolesMap, roleToCMKsMap, roleToActionTypeMap, filteredRolesAtStep4}, step4Duration))

	return &domain.SharedIAMData{
		CMKToRolesMap:       cmkToRolesMap,
		RoleToCMKsMap:       roleToCMKsMap,
		RoleToActionTypeMap: roleToActionTypeMap,
		ResourceToRolesMap:  bucketToRolesMap,
		CriticalRolesSet:    criticalRolesSet,
		FilteredRoles:       filteredRolesAtStep4,
	}, nil
}
