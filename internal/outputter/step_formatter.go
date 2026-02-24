package outputter

import (
	"fmt"
	"strings"
	"time"

	"breachmap/internal/domain"
)

// StepOutputData contains all data needed for step-by-step output
type StepOutputData struct {
	CrownJewels              []domain.S3CrownJewel
	IgnoredBuckets           []string
	BucketExposureMap        map[string]*domain.ExposureResult
	KMSBuckets               []domain.S3CrownJewel
	NonKMSBuckets            []domain.S3CrownJewel
	BucketToCMKMap           map[string]string
	CMKToRolesMap            map[string][]string
	RoleToCMKsMap            map[string][]string
	NonKMSRoles              map[string][]string
	SeedRiskyRoles           []string
	LateralMovementRoles     []domain.LateralMovementRole
	PrivilegeEscalationRoles []domain.PrivilegeEscalationRole
	FinalRiskyRoles          []string
	InternetExposedWorkloads domain.RoleToComputeResourcesMapping
	DroppedWorkloads         []domain.DroppedWorkloadInfo
	BreachPaths              []domain.BreachPath
}

// FormatStepOutput formats a step output using a Step definition.
// This is the preferred method as it uses defined step constants instead of magic numbers.
func FormatStepOutput(step domain.Step, data interface{}, duration time.Duration) string {
	return FormatStepOutputWithTiming(step.Number, step.Name, step.Description, data, duration)
}

// FormatStepOutputWithTiming formats a step with header, description, data, and timing
// Deprecated: Use FormatStepOutput with domain.Step constants instead.
func FormatStepOutputWithTiming(stepNum int, title, description string, data interface{}, duration time.Duration) string {
	var sb strings.Builder

	sb.WriteString("\n")
	sb.WriteString(strings.Repeat("═", 79))
	sb.WriteString(fmt.Sprintf("\nSTEP %d: %s", stepNum, title))
	if duration > 0 {
		sb.WriteString(fmt.Sprintf(" ⏱️  %s", FormatDuration(duration)))
	}
	sb.WriteString("\n")
	sb.WriteString(strings.Repeat("═", 79))
	sb.WriteString(fmt.Sprintf("\n%s\n\n", description))

	switch stepNum {
	case 1:
		if stepData, ok := data.(struct {
			CrownJewels    []domain.S3CrownJewel
			IgnoredBuckets []string
		}); ok {
			sb.WriteString(FormatStep1CrownJewels(stepData.CrownJewels, stepData.IgnoredBuckets))
		}
	case 2:
		if stepData, ok := data.(map[string]*domain.ExposureResult); ok {
			sb.WriteString(FormatStep2DirectlyExposedBuckets(stepData))
		}
	case 3:
		if stepData, ok := data.(struct {
			KMSBuckets     []domain.S3CrownJewel
			NonKMSBuckets  []domain.S3CrownJewel
			BucketToCMKMap map[string]string
		}); ok {
			sb.WriteString(FormatStep3KMSvsNonKMS(stepData.KMSBuckets, stepData.NonKMSBuckets, stepData.BucketToCMKMap))
		}
	case 4:
		if stepData, ok := data.(struct {
			CMKToRolesMap       map[string][]string
			RoleToCMKsMap       map[string][]string
			RoleToActionTypeMap map[string]string
			FilteredRoles       []domain.FilteredRoleInfo
		}); ok {
			sb.WriteString(FormatStep4KMSPrincipals(stepData.CMKToRolesMap, stepData.RoleToCMKsMap, stepData.RoleToActionTypeMap, stepData.FilteredRoles))
		}
	case 5:
		if stepData, ok := data.(map[string][]string); ok {
			sb.WriteString(FormatStep5NonKMSPrincipals(stepData))
		}
	case 6:
		if stepData, ok := data.([]string); ok {
			sb.WriteString(FormatStep6SeedRiskyPrincipals(stepData))
		}
	case 7:
		if stepData, ok := data.([]domain.LateralMovementRole); ok {
			sb.WriteString(FormatStep7LateralRisk(stepData))
		}
	case 8:
		if stepData, ok := data.([]domain.PrivilegeEscalationRole); ok {
			sb.WriteString(FormatStep8PrivilegeEscalationRisk(stepData))
		}
	case 9:
		if stepData, ok := data.([]string); ok {
			sb.WriteString(FormatStep9BreachSurfacePrincipals(stepData))
		}
	case 10:
		if stepData, ok := data.(struct {
			Workloads        domain.RoleToComputeResourcesMapping
			DroppedWorkloads []domain.DroppedWorkloadInfo
		}); ok {
			sb.WriteString(FormatStep10InternetExposedWorkloads(stepData.Workloads, stepData.DroppedWorkloads))
		}
	case 11:
		if stepData, ok := data.(struct {
			BreachPaths       []domain.BreachPath
			FilteredRoles     map[string]string
			FilteredWorkloads []domain.DroppedWorkloadInfo
		}); ok {
			sb.WriteString(FormatStep11BreachPaths(stepData.BreachPaths, stepData.FilteredRoles, stepData.FilteredWorkloads))
		} else if stepData, ok := data.([]domain.BreachPath); ok {
			sb.WriteString(FormatStep11BreachPaths(stepData, nil, nil))
		}
	}

	sb.WriteString("\n")
	return sb.String()
}

// FormatStep1CrownJewels formats step 1: Detect crown jewels
func FormatStep1CrownJewels(crownJewels []domain.S3CrownJewel, ignoredBuckets []string) string {
	var sb strings.Builder

	sb.WriteString("💎 Crown Jewels Detected: ")
	sb.WriteString(fmt.Sprintf("%d bucket(s)\n", len(crownJewels)))
	if len(crownJewels) > 0 {
		for _, jewel := range crownJewels {
			sb.WriteString(fmt.Sprintf("   • %s", jewel.Name))
			if jewel.KMSKeyID != nil && *jewel.KMSKeyID != "" {
				sb.WriteString(" 🔒 (KMS-encrypted)")
			}
			sb.WriteString("\n")
		}
	}

	if len(ignoredBuckets) > 0 {
		sb.WriteString(fmt.Sprintf("\n🚫 Buckets Ignored (not crown jewels): %d bucket(s)\n", len(ignoredBuckets)))
		maxShow := 10
		for i, bucketName := range ignoredBuckets {
			if i < maxShow {
				sb.WriteString(fmt.Sprintf("   • %s (doesn't match crown jewel pattern)\n", bucketName))
			} else {
				remaining := len(ignoredBuckets) - maxShow
				sb.WriteString(fmt.Sprintf("   ... and %d more bucket(s)\n", remaining))
				break
			}
		}
	}

	return sb.String()
}

// FormatStep2DirectlyExposedBuckets formats step 2: Directly exposed buckets
func FormatStep2DirectlyExposedBuckets(bucketExposureMap map[string]*domain.ExposureResult) string {
	var sb strings.Builder

	exposedCount := 0
	for _, exposure := range bucketExposureMap {
		if exposure != nil && (exposure.FinalExposure == "Public" || exposure.FinalExposure == "PublicViaPolicy" || exposure.FinalExposure == "PublicViaACL") {
			exposedCount++
		}
	}

	sb.WriteString(fmt.Sprintf("🌐 Directly Internet-Exposed Buckets: %d bucket(s)\n", exposedCount))
	if exposedCount > 0 {
		for bucketName, exposure := range bucketExposureMap {
			if exposure != nil && (exposure.FinalExposure == "Public" || exposure.FinalExposure == "PublicViaPolicy" || exposure.FinalExposure == "PublicViaACL") {
				sb.WriteString(fmt.Sprintf("   • %s", bucketName))
				if exposure.FinalExposure == "PublicViaPolicy" {
					sb.WriteString(" (via bucket policy)")
				} else if exposure.FinalExposure == "PublicViaACL" {
					sb.WriteString(" (via ACL)")
				}
				sb.WriteString("\n")
			}
		}
	} else {
		sb.WriteString("   (none)\n")
	}

	return sb.String()
}

// FormatStep3KMSvsNonKMS formats step 3: KMS vs non-KMS
func FormatStep3KMSvsNonKMS(kmsBuckets []domain.S3CrownJewel, nonKMSBuckets []domain.S3CrownJewel, bucketToCMKMap map[string]string) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("🔒 KMS-Encrypted Buckets: %d bucket(s)\n", len(kmsBuckets)))
	if len(kmsBuckets) > 0 {
		cmkToBuckets := make(map[string][]string)
		for _, bucket := range kmsBuckets {
			if cmkARN, ok := bucketToCMKMap[bucket.Name]; ok {
				cmkToBuckets[cmkARN] = append(cmkToBuckets[cmkARN], bucket.Name)
			}
		}

		for cmkARN, buckets := range cmkToBuckets {
			keyID := cmkARN
			if parts := strings.Split(cmkARN, "/"); len(parts) > 0 {
				keyID = parts[len(parts)-1]
			}
			sb.WriteString(fmt.Sprintf("   🔑 CMK: %s\n", keyID))
			for _, bucket := range buckets {
				sb.WriteString(fmt.Sprintf("      • %s\n", bucket))
			}
		}
	}

	sb.WriteString(fmt.Sprintf("\n📦 Non-KMS Buckets: %d bucket(s)\n", len(nonKMSBuckets)))
	if len(nonKMSBuckets) > 0 {
		for _, bucket := range nonKMSBuckets {
			sb.WriteString(fmt.Sprintf("   • %s\n", bucket.Name))
		}
	}

	return sb.String()
}

// FormatStep4KMSPrincipals formats step 4: KMS principals
func FormatStep4KMSPrincipals(cmkToRolesMap map[string][]string, roleToCMKsMap map[string][]string, roleToActionTypeMap map[string]string, filteredRoles []domain.FilteredRoleInfo) string {
	var sb strings.Builder

	// Classify roles based on action type map
	directDecryptRoles := make(map[string]bool)
	indirectDecryptRoles := make(map[string]bool)
	for roleARN := range roleToCMKsMap {
		actionType := roleToActionTypeMap[roleARN]
		if actionType == "direct" {
			directDecryptRoles[roleARN] = true
		} else {
			// Default to indirect if not specified or explicitly indirect
			indirectDecryptRoles[roleARN] = true
		}
	}

	sb.WriteString(fmt.Sprintf("🔐 KMS Principals: %d role(s) with decrypt access\n", len(directDecryptRoles)+len(indirectDecryptRoles)))

	sb.WriteString(fmt.Sprintf("\n   ✅ Direct Decrypt: %d role(s)\n", len(directDecryptRoles)))
	if len(directDecryptRoles) > 0 {
		for roleARN := range directDecryptRoles {
			roleName := ExtractRoleNameFromARN(roleARN)
			sb.WriteString(fmt.Sprintf("      • %s\n", roleName))
		}
	} else {
		sb.WriteString("      (none)\n")
	}

	sb.WriteString(fmt.Sprintf("\n   🔄 Indirect Decrypt: %d role(s) (e.g. roles that generate data key)\n", len(indirectDecryptRoles)))
	if len(indirectDecryptRoles) > 0 {
		for roleARN := range indirectDecryptRoles {
			roleName := ExtractRoleNameFromARN(roleARN)
			sb.WriteString(fmt.Sprintf("      • %s\n", roleName))
		}
	} else {
		sb.WriteString("      (none)\n")
	}

	if len(roleToCMKsMap) > 0 {
		sb.WriteString("\n   📋 Role → CMK Mapping:\n")
		for roleARN, cmkARNs := range roleToCMKsMap {
			roleName := ExtractRoleNameFromARN(roleARN)
			sb.WriteString(fmt.Sprintf("      • %s → ", roleName))
			keyIDs := make([]string, 0, len(cmkARNs))
			for _, cmkARN := range cmkARNs {
				keyID := cmkARN
				if parts := strings.Split(cmkARN, "/"); len(parts) > 0 {
					keyID = parts[len(parts)-1]
				}
				keyIDs = append(keyIDs, keyID)
			}
			sb.WriteString(fmt.Sprintf("%s\n", strings.Join(keyIDs, ", ")))
		}
	}

	if len(filteredRoles) > 0 {
		noS3AccessRoles := make([]domain.FilteredRoleInfo, 0)
		kmsDeniedRoles := make([]domain.FilteredRoleInfo, 0)

		for _, filtered := range filteredRoles {
			if filtered.Reason == "no_s3_access" {
				noS3AccessRoles = append(noS3AccessRoles, filtered)
			} else if filtered.Reason == "kms_decrypt_denied" {
				kmsDeniedRoles = append(kmsDeniedRoles, filtered)
			}
		}

		sb.WriteString(fmt.Sprintf("\n   🚫 Roles Filtered (missing dual authorization): %d role(s)\n", len(filteredRoles)))

		if len(noS3AccessRoles) > 0 {
			sb.WriteString(fmt.Sprintf("\n      Missing S3 Access (can decrypt CMK but no S3 access to bucket): %d role(s)\n", len(noS3AccessRoles)))
			for _, filtered := range noS3AccessRoles {
				roleName := ExtractRoleNameFromARN(filtered.RoleARN)
				resourceName := ExtractBucketNameFromARN(filtered.ResourceARN)
				sb.WriteString(fmt.Sprintf("         • %s → %s (no S3 access to this bucket)\n", roleName, resourceName))
			}
		}

		if len(kmsDeniedRoles) > 0 {
			sb.WriteString(fmt.Sprintf("\n      KMS Decrypt Denied (has S3 access but cannot decrypt CMK): %d role(s)\n", len(kmsDeniedRoles)))
			for _, filtered := range kmsDeniedRoles {
				roleName := ExtractRoleNameFromARN(filtered.RoleARN)
				resourceName := ExtractBucketNameFromARN(filtered.ResourceARN)
				sb.WriteString(fmt.Sprintf("         • %s → %s (KMS decrypt denied for this bucket)\n", roleName, resourceName))
			}
		}
	}

	return sb.String()
}

// FormatStep5NonKMSPrincipals formats step 5: Non-KMS principals
func FormatStep5NonKMSPrincipals(nonKMSRoles map[string][]string) string {
	var sb strings.Builder

	totalRoles := make(map[string]bool)
	for _, roleARNs := range nonKMSRoles {
		for _, roleARN := range roleARNs {
			totalRoles[roleARN] = true
		}
	}

	sb.WriteString(fmt.Sprintf("🔐 Non-KMS Principals: %d role(s) with bucket access\n", len(totalRoles)))

	if len(nonKMSRoles) > 0 {
		sb.WriteString("\n   📋 Role → Bucket Mapping:\n")
		for bucketARN, roleARNs := range nonKMSRoles {
			bucketName := ExtractBucketNameFromARN(bucketARN)
			sb.WriteString(fmt.Sprintf("      • %s → ", bucketName))
			roleNames := make([]string, 0, len(roleARNs))
			for _, roleARN := range roleARNs {
				roleNames = append(roleNames, ExtractRoleNameFromARN(roleARN))
			}
			sb.WriteString(fmt.Sprintf("%s\n", strings.Join(roleNames, ", ")))
		}
	}

	return sb.String()
}

// FormatStep6SeedRiskyPrincipals formats step 6: Seed of risky principals
func FormatStep6SeedRiskyPrincipals(seedRoles []string) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("🌱 Seed of Risky Principals: %d role(s)\n", len(seedRoles)))
	if len(seedRoles) > 0 {
		sb.WriteString("\n   Roles with direct access to crown jewels:\n")
		for _, roleARN := range seedRoles {
			roleName := ExtractRoleNameFromARN(roleARN)
			sb.WriteString(fmt.Sprintf("      • %s\n", roleName))
		}
	}

	return sb.String()
}

// FormatStep7LateralRisk formats step 7: Include lateral risk
func FormatStep7LateralRisk(lateralRoles []domain.LateralMovementRole) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("🔄 Lateral Movement Risk: %d role(s)\n", len(lateralRoles)))
	if len(lateralRoles) > 0 {
		sb.WriteString("\n   Roles that can assume/pass other risky roles:\n")
		for _, role := range lateralRoles {
			roleName := ExtractRoleNameFromARN(role.RoleARN)
			sb.WriteString(fmt.Sprintf("      • %s", roleName))
			if len(role.CanAssumeRoles) > 0 {
				sb.WriteString(fmt.Sprintf(" → can assume %d role(s)", len(role.CanAssumeRoles)))
			}
			sb.WriteString("\n")
		}
	} else {
		sb.WriteString("\n   No lateral movement roles found.\n")
	}

	return sb.String()
}

// FormatStep8PrivilegeEscalationRisk formats step 8: Include privilege escalation risk
func FormatStep8PrivilegeEscalationRisk(escalationRoles []domain.PrivilegeEscalationRole) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("⬆️  Privilege Escalation Risk: %d role(s)\n", len(escalationRoles)))
	if len(escalationRoles) > 0 {
		sb.WriteString("\n   Roles that can write/grant permissions:\n")
		for _, role := range escalationRoles {
			roleName := ExtractRoleNameFromARN(role.RoleARN)
			sb.WriteString(fmt.Sprintf("      • %s", roleName))
			if len(role.DangerousActions) > 0 {
				sb.WriteString(fmt.Sprintf(" → %s", strings.Join(role.DangerousActions, ", ")))
			}
			sb.WriteString("\n")
		}
	} else {
		sb.WriteString("\n   No privilege escalation roles found.\n")
	}

	return sb.String()
}

// FormatStep9BreachSurfacePrincipals formats step 9: Breach surface of principals
func FormatStep9BreachSurfacePrincipals(finalRoles []string) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("🎯 Breach Surface of Principals: %d role(s)\n", len(finalRoles)))
	sb.WriteString("\n   Complete set of risky roles (seed + lateral + privilege escalation):\n")
	if len(finalRoles) > 0 {
		for _, roleARN := range finalRoles {
			roleName := ExtractRoleNameFromARN(roleARN)
			sb.WriteString(fmt.Sprintf("      • %s\n", roleName))
		}
	} else {
		sb.WriteString("      (none)\n")
	}

	return sb.String()
}

// FormatStep10InternetExposedWorkloads formats step 10: Internet-exposed workloads
func FormatStep10InternetExposedWorkloads(workloads domain.RoleToComputeResourcesMapping, dropped []domain.DroppedWorkloadInfo) string {
	var sb strings.Builder

	ec2Count := 0
	lambdaCount := 0
	for _, resources := range workloads {
		for _, resource := range resources {
			if resource.InternetExposed {
				if resource.RuntimeType == "EC2" {
					ec2Count++
				} else if resource.RuntimeType == "Lambda" {
					lambdaCount++
				}
			}
		}
	}

	sb.WriteString(fmt.Sprintf("🌐 Internet-Exposed Workloads: %d total\n", ec2Count+lambdaCount))
	sb.WriteString(fmt.Sprintf("   • EC2 Instances: %d\n", ec2Count))
	sb.WriteString(fmt.Sprintf("   • Lambda Functions: %d\n", lambdaCount))

	if len(workloads) > 0 {
		sb.WriteString("\n   📋 Workload → Principal Mapping:\n")
		for roleARN, resources := range workloads {
			roleName := ExtractRoleNameFromARN(roleARN)
			exposedResources := make([]string, 0)
			for _, resource := range resources {
				if resource.InternetExposed {
					exposedResources = append(exposedResources, resource.ResourceID)
				}
			}
			if len(exposedResources) > 0 {
				sb.WriteString(fmt.Sprintf("      • %s → %s\n", roleName, strings.Join(exposedResources, ", ")))
			}
		}
	}

	sb.WriteString("\n   🚫 Ignored Workloads:\n")
	if len(dropped) > 0 {
		noPublicIP := make([]domain.DroppedWorkloadInfo, 0)
		noFunctionURL := make([]domain.DroppedWorkloadInfo, 0)
		vpcDenied := make([]domain.DroppedWorkloadInfo, 0)
		other := make([]domain.DroppedWorkloadInfo, 0)

		for _, d := range dropped {
			if strings.Contains(d.Reason, "no public IP") || strings.Contains(d.Reason, "Not internet-exposed") && d.ResourceType == "EC2" {
				noPublicIP = append(noPublicIP, d)
			} else if strings.Contains(d.Reason, "no function URL") || strings.Contains(d.Reason, "Not internet-exposed") && d.ResourceType == "Lambda" {
				noFunctionURL = append(noFunctionURL, d)
			} else if strings.Contains(d.Reason, "VPC") {
				vpcDenied = append(vpcDenied, d)
			} else {
				other = append(other, d)
			}
		}

		if len(noPublicIP) > 0 {
			sb.WriteString(fmt.Sprintf("\n      Not internet-exposed (no public IP): %d EC2 instance(s)\n", len(noPublicIP)))
			for _, d := range noPublicIP {
				roleName := ExtractRoleNameFromARN(d.RoleARN)
				sb.WriteString(fmt.Sprintf("         • %s (EC2) - role %s\n", d.ResourceID, roleName))
			}
		}

		if len(noFunctionURL) > 0 {
			sb.WriteString(fmt.Sprintf("\n      Not internet-exposed (no function URL): %d Lambda function(s)\n", len(noFunctionURL)))
			for _, d := range noFunctionURL {
				roleName := ExtractRoleNameFromARN(d.RoleARN)
				sb.WriteString(fmt.Sprintf("         • %s (Lambda) - role %s\n", d.ResourceID, roleName))
			}
		}

		if len(vpcDenied) > 0 {
			sb.WriteString(fmt.Sprintf("\n      VPC denied by bucket policy: %d workload(s)\n", len(vpcDenied)))
			for _, d := range vpcDenied {
				roleName := ExtractRoleNameFromARN(d.RoleARN)
				sb.WriteString(fmt.Sprintf("         • %s (%s) - role %s - %s\n", d.ResourceID, d.ResourceType, roleName, d.Reason))
			}
		}

		if len(other) > 0 {
			for _, d := range other {
				roleName := ExtractRoleNameFromARN(d.RoleARN)
				sb.WriteString(fmt.Sprintf("      • %s (%s) - role %s - %s\n", d.ResourceID, d.ResourceType, roleName, d.Reason))
			}
		}
	} else {
		sb.WriteString("      No Internet security nor VPC deny conditions found\n")
	}

	return sb.String()
}

// FormatStep11BreachPaths formats step 11: Breach paths
func FormatStep11BreachPaths(breachPaths []domain.BreachPath, filteredRoles map[string]string, filteredWorkloads []domain.DroppedWorkloadInfo) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("🔗 Breach Paths: %d total\n", len(breachPaths)))

	// Count by vector and target type
	ec2ToS3Count := 0
	lambdaToS3Count := 0
	ec2ToRDSCount := 0
	lambdaToRDSCount := 0
	publicS3Count := 0
	publicRDSCount := 0

	for _, path := range breachPaths {
		isRDS := path.TargetType == "RDS"
		if path.Vector == "EC2" {
			if isRDS {
				ec2ToRDSCount++
			} else {
				ec2ToS3Count++
			}
		} else if path.Vector == "Lambda" {
			if isRDS {
				lambdaToRDSCount++
			} else {
				lambdaToS3Count++
			}
		} else if path.Vector == "Public" {
			if isRDS {
				publicRDSCount++
			} else {
				publicS3Count++
			}
		}
	}

	// S3 paths
	if ec2ToS3Count > 0 || lambdaToS3Count > 0 || publicS3Count > 0 {
		sb.WriteString(fmt.Sprintf("   • EC2 → S3: %d path(s)\n", ec2ToS3Count))
		sb.WriteString(fmt.Sprintf("   • Lambda → S3: %d path(s)\n", lambdaToS3Count))
		if publicS3Count > 0 {
			sb.WriteString(fmt.Sprintf("   • Public Buckets: %d bucket(s)\n", publicS3Count))
		}
	}

	// RDS paths
	if ec2ToRDSCount > 0 || lambdaToRDSCount > 0 || publicRDSCount > 0 {
		sb.WriteString(fmt.Sprintf("   • EC2 → RDS: %d path(s)\n", ec2ToRDSCount))
		sb.WriteString(fmt.Sprintf("   • Lambda → RDS: %d path(s)\n", lambdaToRDSCount))
		if publicRDSCount > 0 {
			sb.WriteString(fmt.Sprintf("   • Public Databases: %d database(s)\n", publicRDSCount))
		}
	}

	if len(breachPaths) > 0 {
		sb.WriteString("\n   📋 Breach Path Summary:\n")
		for i, path := range breachPaths {
			isRDS := path.TargetType == "RDS"
			targetName := extractTargetNameFromARN(path.TargetDB, isRDS)
			roleName := ""
			if path.RoleARN != "" {
				roleName = ExtractRoleNameFromARN(path.RoleARN)
			}

			vectorIcon := GetVectorIconForStep(path.Vector)
			exposureText := ""
			if path.Exposure != nil {
				exposureText = fmt.Sprintf(" → 🌐 %s", *path.Exposure)
			} else if path.PublicIP != nil {
				exposureText = fmt.Sprintf(" → 🌐 Public IP (%s)", *path.PublicIP)
			}

			targetIcon := "💎"
			if isRDS {
				targetIcon = "🗄️"
			}

			if path.Vector == "Public" {
				if isRDS {
					sb.WriteString(fmt.Sprintf("      %d. Internet → 🌐 Public Database → %s %s\n",
						i+1, targetIcon, targetName))
				} else {
					sb.WriteString(fmt.Sprintf("      %d. Internet → 🌐 Public Bucket → %s %s\n",
						i+1, targetIcon, targetName))
				}
			} else {
				if path.AssumedRoleARN != "" {
					assumedRoleName := ExtractRoleNameFromARN(path.AssumedRoleARN)
					sb.WriteString(fmt.Sprintf("      %d. Internet%s → %s %s → 🔐 Role (%s) → 🔐 Role (%s) → %s %s\n",
						i+1, exposureText, vectorIcon, path.ResourceID, roleName, assumedRoleName, targetIcon, targetName))
				} else {
					sb.WriteString(fmt.Sprintf("      %d. Internet%s → %s %s → 🔐 Role (%s) → %s %s\n",
						i+1, exposureText, vectorIcon, path.ResourceID, roleName, targetIcon, targetName))
				}
			}
		}
	} else {
		sb.WriteString("\n   (none)\n")
	}

	if len(filteredRoles) > 0 || len(filteredWorkloads) > 0 {
		sb.WriteString("\n   🚫 Components Dropped After Authorization Check:\n")

		if len(filteredRoles) > 0 {
			sb.WriteString(fmt.Sprintf("\n      Roles dropped: %d role(s)\n", len(filteredRoles)))
			for roleARN, reason := range filteredRoles {
				roleName := ExtractRoleNameFromARN(roleARN)
				sb.WriteString(fmt.Sprintf("         • %s - %s\n", roleName, reason))
			}
		}

		if len(filteredWorkloads) > 0 {
			sb.WriteString(fmt.Sprintf("\n      Workloads dropped: %d workload(s)\n", len(filteredWorkloads)))
			for _, workload := range filteredWorkloads {
				roleName := ExtractRoleNameFromARN(workload.RoleARN)
				sb.WriteString(fmt.Sprintf("         • %s (%s) - role %s - %s\n",
					workload.ResourceID, workload.ResourceType, roleName, workload.Reason))
			}
		}
	}

	return sb.String()
}

// extractTargetNameFromARN extracts target name from ARN based on target type
func extractTargetNameFromARN(arn string, isRDS bool) string {
	if isRDS {
		return ExtractDBNameFromARN(arn)
	}
	return ExtractBucketNameFromARN(arn)
}

// ExtractDBNameFromARN extracts database name from RDS ARN
func ExtractDBNameFromARN(arn string) string {
	// Format: arn:aws:rds:<region>:<account>:db:<db-instance-identifier>
	if strings.HasPrefix(arn, "arn:aws:rds:") {
		parts := strings.Split(arn, ":")
		if len(parts) >= 7 {
			return parts[6]
		}
	}
	return arn
}

// GetVectorIconForStep returns icon for vector type
func GetVectorIconForStep(vector string) string {
	switch vector {
	case "EC2":
		return "🖥️"
	case "Lambda":
		return "⚡"
	default:
		return "💻"
	}
}

// FormatDuration formats a duration in a human-readable way
func FormatDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	} else if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	} else {
		minutes := int(d.Minutes())
		seconds := int(d.Seconds()) % 60
		return fmt.Sprintf("%dm %ds", minutes, seconds)
	}
}

// ExtractBucketNameFromARN extracts bucket name from S3 ARN.
// For display purposes, returns the input as-is if it's not a valid S3 ARN
// (e.g., if the caller already passed a plain bucket name).
func ExtractBucketNameFromARN(bucketARN string) string {
	if name := domain.ExtractBucketNameFromARN(bucketARN); name != "" {
		return name
	}
	// Fallback: return as-is for display (e.g., already a plain bucket name)
	return bucketARN
}
