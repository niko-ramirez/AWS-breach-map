package breachpath

import (
	"breachmap/internal/app"
	internalaws "breachmap/internal/aws"
	"breachmap/internal/domain"
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
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
)

// ProcessRDSExposureAndKMSSeparation processes resource-specific steps 1.5, 2, and 3 for RDS
// Step 1.5: KMS/Non-KMS separation
// Step 2: Exposure analysis (IAMAuthenticator, PubliclyAccessible, security groups)
// Step 3: KMS vs Non-KMS output formatting
func ProcessRDSExposureAndKMSSeparation(ctx context.Context, breachSurfacer *app.BreachSurfacer, rdsCrownJewels *[]domain.RDSJewel) (*domain.RDSResourceData, error) {
	if rdsCrownJewels == nil || len(*rdsCrownJewels) == 0 {
		return &domain.RDSResourceData{
			KMSDatabases:          []domain.RDSJewel{},
			NonKMSDatabases:       []domain.RDSJewel{},
			DatabaseToCMKMap:      make(map[string]string),
			CMKSet:                make(map[string]bool),
			ExposureMap:           make(map[string]*domain.ExposureResult),
			CrownJewelMap:         make(map[string]domain.RDSJewel),
			EncryptedResources:    []domain.EncryptedResource{},
			NonEncryptedResources: []domain.NonEncryptedResource{},
			AllDatabases:          []domain.RDSJewel{},
		}, nil
	}

	allEncryptedResources := make([]domain.EncryptedResource, 0)
	allNonEncryptedResources := make([]domain.NonEncryptedResource, 0)

	// Get account ID for CMK ARN conversion
	accountIDForCMK, err := internalaws.GetAccountID(ctx)
	if err != nil {
		logging.LogWarn("Failed to get account ID", map[string]interface{}{"error": err.Error()})
		accountIDForCMK = "000000000000"
	}

	// Step 1.5: Collect CMKs from critical databases and create mappings
	databaseToCMKMap := make(map[string]string)
	cmkSet := make(map[string]bool)
	kmsDatabases := make([]domain.RDSJewel, 0)
	nonKMSDatabases := make([]domain.RDSJewel, 0)

	for _, db := range *rdsCrownJewels {
		if db.KMSKeyID != nil && *db.KMSKeyID != "" {
			keyID := *db.KMSKeyID
			var cmkARN string
			if strings.HasPrefix(keyID, "arn:aws:kms:") {
				cmkARN = keyID
			} else {
				// Extract region from ARN or use default
				region := "us-east-1"
				if strings.Contains(db.ARN, ":") {
					parts := strings.Split(db.ARN, ":")
					if len(parts) >= 4 {
						region = parts[3]
					}
				}
				cmkARN = fmt.Sprintf("arn:aws:kms:%s:%s:key/%s", region, accountIDForCMK, keyID)
			}
			databaseToCMKMap[db.Name] = cmkARN
			cmkSet[cmkARN] = true
			kmsDatabases = append(kmsDatabases, db)
			// Build encrypted resources list
			allEncryptedResources = append(allEncryptedResources, domain.EncryptedResource{
				ResourceARN:  db.ARN,
				CMKARN:       cmkARN,
				ResourceType: "RDS",
			})
		} else {
			nonKMSDatabases = append(nonKMSDatabases, db)
			// Build non-encrypted resources list
			allNonEncryptedResources = append(allNonEncryptedResources, domain.NonEncryptedResource{
				ResourceARN:  db.ARN,
				ResourceType: "RDS",
			})
		}
	}

	logging.LogInfo("Collected CMKs from critical databases", map[string]interface{}{
		"total_cmks":        len(cmkSet),
		"kms_databases":     len(kmsDatabases),
		"non_kms_databases": len(nonKMSDatabases),
	})

	// Step 2: Analyze exposure for each critical database
	// Uses pre-captured data from crown jewel detection (IAMAuthEnabled, PubliclyAccessible)
	step2StartTime := time.Now()
	databaseExposureMap := make(map[string]*domain.ExposureResult)
	databaseCrownJewelMap := make(map[string]domain.RDSJewel)

	for _, db := range *rdsCrownJewels {
		dbName := db.Name
		databaseCrownJewelMap[dbName] = db

		// Use pre-captured data from RDSJewel instead of making redundant API calls
		exposureResult := AnalyzeRDSExposureFromJewel(db)
		databaseExposureMap[dbName] = exposureResult

		// Log exposure result for debugging
		publiclyAccessible := db.PubliclyAccessible != nil && *db.PubliclyAccessible
		iamAuthEnabled := db.IAMAuthEnabled != nil && *db.IAMAuthEnabled
		logging.LogDebug(fmt.Sprintf("RDS database %s: PubliclyAccessible=%v, IAMAuthEnabled=%v, FinalExposure=%s",
			dbName, publiclyAccessible, iamAuthEnabled, exposureResult.FinalExposure))

		// Log IAM auth status for clarity
		if db.IAMAuthEnabled != nil && !*db.IAMAuthEnabled {
			logging.LogDebug("RDS database does not have IAM authentication enabled", map[string]interface{}{
				"database": dbName,
				"note":     "Authorization verification will be skipped for this database",
			})
		}
	}
	step2Duration := time.Since(step2StartTime)

	// Output Step 2: Directly Exposed Databases
	fmt.Print(outputter.FormatStepOutputWithTiming(2, "Directly Exposed Databases",
		"Analyzing public access vectors (IAMAuthenticator, PubliclyAccessible, security groups)",
		databaseExposureMap, step2Duration))

	// Step 3: KMS vs Non-KMS (already computed above, just output)
	step3StartTime := time.Now()
	step3Duration := time.Since(step3StartTime)

	// Output Step 3: KMS vs Non-KMS
	fmt.Print(outputter.FormatStepOutputWithTiming(3, "KMS vs Non-KMS",
		"Mapping encryption keys to databases and separating KMS-encrypted from non-KMS databases",
		struct {
			KMSDatabases     []domain.RDSJewel
			NonKMSDatabases  []domain.RDSJewel
			DatabaseToCMKMap map[string]string
		}{kmsDatabases, nonKMSDatabases, databaseToCMKMap}, step3Duration))

	return &domain.RDSResourceData{
		KMSDatabases:          kmsDatabases,
		NonKMSDatabases:       nonKMSDatabases,
		DatabaseToCMKMap:      databaseToCMKMap,
		CMKSet:                cmkSet,
		ExposureMap:           databaseExposureMap,
		CrownJewelMap:         databaseCrownJewelMap,
		EncryptedResources:    allEncryptedResources,
		NonEncryptedResources: allNonEncryptedResources,
		AllDatabases:          *rdsCrownJewels,
	}, nil
}

// AnalyzeRDSExposureFromJewel analyzes RDS database exposure using pre-captured data from RDSJewel
// This avoids redundant API calls since we already have the data from crown jewel detection
func AnalyzeRDSExposureFromJewel(db domain.RDSJewel) *domain.ExposureResult {
	result := &domain.ExposureResult{
		ResourceName: db.Name,
	}

	// Get pre-captured values
	iamAuthEnabled := db.IAMAuthEnabled != nil && *db.IAMAuthEnabled
	publiclyAccessible := db.PubliclyAccessible != nil && *db.PubliclyAccessible

	// Determine final exposure based on multiple factors
	exposureReasons := []string{}

	// Check public accessibility
	if publiclyAccessible {
		exposureReasons = append(exposureReasons, "PubliclyAccessible=true")
		result.FinalExposure = "Public"
	} else {
		result.FinalExposure = "Private"
	}

	// Check IAM authentication status
	if iamAuthEnabled {
		exposureReasons = append(exposureReasons, "IAMAuthenticator=true")
		// IAM authenticator enables IAM-based access
		// This is the path we can verify authorization for
		if result.FinalExposure == "Private" {
			result.FinalExposure = "IAM-Authenticated"
		}
	} else {
		exposureReasons = append(exposureReasons, "IAMAuthenticator=false (password auth only)")
		// Note: Without IAM auth, breach path depends on credential discovery
		// Authorization verification via SimulatePrincipalPolicy won't apply
	}

	// Add engine info if available
	if db.Engine != nil && *db.Engine != "" {
		exposureReasons = append(exposureReasons, fmt.Sprintf("Engine=%s", *db.Engine))
	}

	// Build details string
	if len(exposureReasons) > 0 {
		result.Details = strings.Join(exposureReasons, ", ")
	} else {
		result.Details = "No public exposure vectors detected"
	}

	// Store IAM auth metadata in PolicyStatements
	if iamAuthEnabled {
		result.PolicyStatements = []domain.PolicyStatement{
			{
				Sid:    "IAMAuthEnabled",
				Effect: "Allow",
				Action: "rds-db:connect",
			},
		}
	} else {
		// Mark as password-only authentication
		result.PolicyStatements = []domain.PolicyStatement{
			{
				Sid:    "PasswordAuthOnly",
				Effect: "Deny",
				Action: "rds-db:connect",
			},
		}
	}

	return result
}

// AnalyzeRDSExposure analyzes RDS database exposure by making an API call
// Use AnalyzeRDSExposureFromJewel when you have pre-captured RDSJewel data
func AnalyzeRDSExposure(ctx context.Context, rdsSvc *rds.Client, dbInstanceIdentifier string) (*domain.ExposureResult, error) {
	// Describe the DB instance to get detailed information
	describeOutput, err := rdsSvc.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{
		DBInstanceIdentifier: aws.String(dbInstanceIdentifier),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to describe DB instance: %w", err)
	}

	if len(describeOutput.DBInstances) == 0 {
		return &domain.ExposureResult{
			ResourceName:  dbInstanceIdentifier,
			FinalExposure: "Unknown",
			Details:       "DB instance not found",
		}, nil
	}

	dbInstance := describeOutput.DBInstances[0]

	// Convert to RDSJewel and use the shared analysis function
	encrypted := dbInstance.StorageEncrypted != nil && *dbInstance.StorageEncrypted
	iamAuthEnabled := dbInstance.IAMDatabaseAuthenticationEnabled != nil && *dbInstance.IAMDatabaseAuthenticationEnabled
	publiclyAccessible := dbInstance.PubliclyAccessible != nil && *dbInstance.PubliclyAccessible
	engine := aws.ToString(dbInstance.Engine)

	tempJewel := domain.RDSJewel{
		ARN:                aws.ToString(dbInstance.DBInstanceArn),
		ResourceType:       "RDS",
		Name:               aws.ToString(dbInstance.DBInstanceIdentifier),
		Encrypted:          &encrypted,
		KMSKeyID:           dbInstance.KmsKeyId,
		IAMAuthEnabled:     &iamAuthEnabled,
		PubliclyAccessible: &publiclyAccessible,
		Engine:             &engine,
	}

	return AnalyzeRDSExposureFromJewel(tempJewel), nil
}

// VerifyRDSAuthorization performs authorization verification for RDS databases
// Only IAM-authenticated databases can be verified via SimulatePrincipalPolicy
// Password-only databases are marked as "unverifiable" since IAM doesn't control access
func VerifyRDSAuthorization(
	ctx context.Context,
	breachSurfacer *app.BreachSurfacer,
	allRDSResources []domain.RDSJewel,
	resourceToRolesMap map[string][]string,
	criticalRolesSet map[string]bool,
	cmkToRolesMap map[string][]string,
	resourceToCMKMap map[string]map[string]string,
) (map[string][]domain.PrincipalAccess, error) {
	iamSvc := breachSurfacer.IAMClient()

	logging.LogDebug("--- Verifying RDS Authorization for Principal Access ---")
	principalAccessResults := make(map[string][]domain.PrincipalAccess)

	// Build set of roles to verify
	rolesToVerify := make(map[string]bool)
	for roleARN := range criticalRolesSet {
		rolesToVerify[roleARN] = true
	}
	for _, roleARNs := range resourceToRolesMap {
		for _, roleARN := range roleARNs {
			rolesToVerify[roleARN] = true
		}
	}

	// Count IAM-authenticated vs password-only databases
	iamAuthCount := 0
	passwordOnlyCount := 0
	for _, db := range allRDSResources {
		if db.IAMAuthEnabled != nil && *db.IAMAuthEnabled {
			iamAuthCount++
		} else {
			passwordOnlyCount++
		}
	}
	logging.LogDebug(fmt.Sprintf("RDS Authorization: %d IAM-authenticated databases, %d password-only databases", iamAuthCount, passwordOnlyCount))

	for _, db := range allRDSResources {
		// Determine which roles to check for this database
		rolesToCheck := determineRolesToCheckForRDS(db, resourceToRolesMap, rolesToVerify, cmkToRolesMap, resourceToCMKMap)

		for _, roleARN := range rolesToCheck {
			riskProfile := determineRDSRiskProfile(db, roleARN, cmkToRolesMap, resourceToCMKMap)
			authResult := verifyRDSRoleAuthorization(ctx, iamSvc, roleARN, db)

			access := buildRDSPrincipalAccess(roleARN, db, riskProfile, authResult)
			principalAccessResults[db.ARN] = append(principalAccessResults[db.ARN], access)
		}
	}

	// Update critical roles set based on authorization results
	updateRDSCriticalRolesSet(principalAccessResults, criticalRolesSet)
	logging.LogDebug(fmt.Sprintf("After RDS authorization filtering: %d roles have exploitable access", len(criticalRolesSet)))

	return principalAccessResults, nil
}

// determineRolesToCheckForRDS determines which roles should be checked for a given RDS database
func determineRolesToCheckForRDS(
	db domain.RDSJewel,
	resourceToRolesMap map[string][]string,
	rolesToVerify map[string]bool,
	cmkToRolesMap map[string][]string,
	resourceToCMKMap map[string]map[string]string,
) []string {
	// If resource has direct role mappings, use those
	if roleARNs, hasRoles := resourceToRolesMap[db.ARN]; hasRoles && len(roleARNs) > 0 {
		return roleARNs
	}

	// For KMS-encrypted resources, check CMK access
	if db.KMSKeyID != nil && *db.KMSKeyID != "" {
		return getRolesWithRDSCMKAccess(db, rolesToVerify, cmkToRolesMap, resourceToCMKMap)
	}

	// For non-KMS resources, check all verified roles
	roles := make([]string, 0, len(rolesToVerify))
	for roleARN := range rolesToVerify {
		roles = append(roles, roleARN)
	}
	return roles
}

// getRolesWithRDSCMKAccess returns roles that have access to the database's CMK
func getRolesWithRDSCMKAccess(
	db domain.RDSJewel,
	rolesToVerify map[string]bool,
	cmkToRolesMap map[string][]string,
	resourceToCMKMap map[string]map[string]string,
) []string {
	rdsCMKMap := resourceToCMKMap["RDS"]
	if rdsCMKMap == nil {
		return []string{}
	}

	cmkARN := rdsCMKMap[db.Name]
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

// determineRDSRiskProfile determines the risk profile for a role-database pair
func determineRDSRiskProfile(
	db domain.RDSJewel,
	roleARN string,
	cmkToRolesMap map[string][]string,
	resourceToCMKMap map[string]map[string]string,
) string {
	// Check if database uses IAM authentication
	if db.IAMAuthEnabled == nil || !*db.IAMAuthEnabled {
		return "PASSWORD_AUTH_ONLY" // Can't verify via IAM
	}

	// Check if database is KMS encrypted
	if db.KMSKeyID == nil || *db.KMSKeyID == "" {
		return "RDS_IAM_CONNECT"
	}

	// Check if role has KMS access
	rdsCMKMap := resourceToCMKMap["RDS"]
	if rdsCMKMap == nil {
		return "RDS_IAM_CONNECT"
	}

	cmkARN := rdsCMKMap[db.Name]
	if cmkARN == "" {
		return "RDS_IAM_CONNECT"
	}

	cmkRoleARNs, ok := cmkToRolesMap[cmkARN]
	if !ok {
		return "RDS_IAM_CONNECT"
	}

	for _, cmkRoleARN := range cmkRoleARNs {
		if cmkRoleARN == roleARN {
			return "RDS_IAM_CONNECT_WITH_KMS"
		}
	}
	return "RDS_IAM_CONNECT"
}

// verifyRDSRoleAuthorization verifies authorization for a role-database pair
func verifyRDSRoleAuthorization(
	ctx context.Context,
	iamSvc *iam.Client,
	roleARN string,
	db domain.RDSJewel,
) *domain.AuthorizationResult {
	result := &domain.AuthorizationResult{
		SimulationDetails: make(map[string]interface{}),
	}

	// Check if database has IAM authentication enabled
	if db.IAMAuthEnabled == nil || !*db.IAMAuthEnabled {
		// Password-only database - cannot verify via IAM
		// Mark as "unverifiable" but potentially exploitable if attacker finds credentials
		result.ResourceAccessAllowed = false
		result.Exploitable = false // Can't confirm via IAM
		result.SimulationDetails["auth_type"] = "password_only"
		result.SimulationDetails["note"] = "IAM authentication not enabled - access depends on database credentials"
		logging.LogDebug(fmt.Sprintf("Skipping IAM verification for %s on %s: IAM authentication not enabled", roleARN, db.ARN))
		return result
	}

	// Build the RDS database resource ARN for rds-db:connect
	// Format: arn:aws:rds-db:<region>:<account>:dbuser:<DbiResourceId>/<DatabaseUserName>
	// Since we're checking general access, we use a wildcard pattern
	// The actual dbuser ARN requires DbiResourceId which we may not have
	// Instead, we check if the role has rds-db:connect permission in general

	// Extract account ID and region from database ARN
	// Format: arn:aws:rds:<region>:<account>:db:<db-instance-identifier>
	accountID := ""
	region := ""
	if strings.Contains(db.ARN, ":") {
		parts := strings.Split(db.ARN, ":")
		if len(parts) >= 5 {
			region = parts[3]
			accountID = parts[4]
		}
	}

	// Build resource ARN for simulation
	// We simulate against a wildcard to check if role has any rds-db:connect permission
	// More specific checks would require the DbiResourceId
	resourceARN := fmt.Sprintf("arn:aws:rds-db:%s:%s:dbuser:*/*", region, accountID)

	simInput := &iam.SimulatePrincipalPolicyInput{
		PolicySourceArn: aws.String(roleARN),
		ActionNames:     []string{"rds-db:connect"},
		ResourceArns:    []string{resourceARN},
	}

	simOutput, err := iamSvc.SimulatePrincipalPolicy(ctx, simInput)
	if err != nil {
		logging.LogDebug(fmt.Sprintf("RDS IAM simulation failed for %s on %s: %v", roleARN, db.ARN, err))
		result.SimulationDetails["rds_simulation_error"] = err.Error()
		result.ResourceAccessAllowed = false
		result.Exploitable = false
		return result
	}

	// Check simulation results
	rdsAllowed := false
	explicitDeny := false
	for _, evalResult := range simOutput.EvaluationResults {
		if evalResult.EvalDecision == iamtypes.PolicyEvaluationDecisionTypeAllowed {
			rdsAllowed = true
		}
		if evalResult.EvalDecision == iamtypes.PolicyEvaluationDecisionTypeExplicitDeny {
			explicitDeny = true
		}
	}

	result.ResourceAccessAllowed = rdsAllowed && !explicitDeny
	result.SimulationDetails["rds_simulation"] = map[string]interface{}{
		"allowed":       rdsAllowed && !explicitDeny,
		"explicit_deny": explicitDeny,
		"results":       len(simOutput.EvaluationResults),
		"action":        "rds-db:connect",
	}

	logging.LogDebug(fmt.Sprintf("RDS IAM simulation for %s on %s: allowed=%v, explicitDeny=%v",
		roleARN, db.ARN, result.ResourceAccessAllowed, explicitDeny))

	// For RDS, exploitability = IAM allows rds-db:connect
	// Note: RDS handles KMS encryption transparently, so we don't need separate KMS checks
	// for reading data (unlike S3 where client needs kms:Decrypt)
	result.Exploitable = result.ResourceAccessAllowed

	return result
}

// buildRDSPrincipalAccess creates a PrincipalAccess object for RDS
func buildRDSPrincipalAccess(roleARN string, db domain.RDSJewel, riskProfile string, authResult *domain.AuthorizationResult) domain.PrincipalAccess {
	return domain.PrincipalAccess{
		PrincipalARN:  roleARN,
		PrincipalType: "role",
		PrincipalName: outputter.ExtractRoleNameFromARN(roleARN),
		ResourceARN:   db.ARN,
		ResourceName:  db.Name,
		RiskProfile:   riskProfile,
		Authorization: authResult,
	}
}

// updateRDSCriticalRolesSet updates the critical roles set based on RDS authorization results
// updateRDSCriticalRolesSet updates the critical roles set based on RDS authorization results
// This function only ADDS exploitable roles, never removes them.
// This ensures roles exploitable for one resource type (S3) aren't removed
// when verifying another resource type (RDS).
func updateRDSCriticalRolesSet(principalAccessResults map[string][]domain.PrincipalAccess, criticalRolesSet map[string]bool) {
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

// BuildRDSBreachPathsAndSave builds RDS breach paths (Step 11 for RDS)
func BuildRDSBreachPathsAndSave(
	ctx context.Context,
	breachSurfacer *app.BreachSurfacer,
	rdsData *domain.RDSResourceData,
	sharedIAMData *domain.SharedIAMData,
	computeResourcesMapping domain.RoleToComputeResourcesMapping,
) ([]domain.BreachPath, []domain.BreachPathOutput, error) {
	// Get EC2 client for security group checks
	var ec2Client *ec2.Client
	if breachSurfacer != nil {
		ec2Client = breachSurfacer.EC2Client()
	}
	return buildRDSBreachPaths(ctx, ec2Client, rdsData, sharedIAMData, computeResourcesMapping)
}

// buildRDSBreachPaths performs resource-specific Step 11: Build RDS breach paths
func buildRDSBreachPaths(
	ctx context.Context,
	ec2Client *ec2.Client,
	rdsData *domain.RDSResourceData,
	sharedIAMData *domain.SharedIAMData,
	computeResourcesMapping domain.RoleToComputeResourcesMapping,
) ([]domain.BreachPath, []domain.BreachPathOutput, error) {
	step11StartTime := time.Now()
	breachPaths := make([]domain.BreachPath, 0)
	breachPathOutputs := make([]domain.BreachPathOutput, 0)
	pathCounter := 0

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

	// Case 1: Internet-exposed compute resources with access to critical RDS databases
	for dbARN, accesses := range sharedIAMData.RDSPrincipalAccessResults {
		db := rdsData.CrownJewelMap[extractDBNameFromARN(dbARN)]
		if db.ARN == "" {
			continue
		}

		dbName := db.Name
		exposureResult := rdsData.ExposureMap[dbName]
		if exposureResult == nil {
			exposureResult = &domain.ExposureResult{
				ResourceName:  dbName,
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
				// STEP 1: IAM Authorization Check (O(1) - precomputed boolean)
				// Check this FIRST because it's just reading a cached result.
				// The actual rds-db:connect simulation was done earlier.
				if access.Authorization != nil && !access.Authorization.Exploitable {
					continue
				}

				// STEP 2: RDS Network Boundary Check (O(n) - may require API calls)
				// Only run AFTER IAM passes, since DescribeSecurityGroups is expensive.
				// Checks: Security group ingress (NR-001), VPC connectivity (NR-002), private access (NR-003)
				rdsNetCtx := network.BuildRDSNetworkContext(&db, &computeResource)
				if rdsNetCtx != nil {
					boundaryResult := network.CheckRDSNetworkBoundaries(ctx, ec2Client, rdsNetCtx)
					
					if boundaryResult.AnyBlocks {
						// Update authorization result with network boundary info
						if access.Authorization != nil {
							access.Authorization.NetworkBoundaries = boundaryResult
							access.Authorization.BlockedByNetwork = true
							access.Authorization.Exploitable = false
						}
						logging.LogDebug("RDS path blocked by network boundary", map[string]interface{}{
							"compute":   computeResource.ResourceID,
							"database":  db.Name,
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

				breachPath := buildRDSBreachPathFromComputeResource(pathCounter, db, exposureResult, access, computeResource, isLateralPath, lateralRoleARN)
				breachPath.LateralMovement = hasLateralMovement
				breachPath.PrivilegeEscalation = hasPrivilegeEscalation
				breachPaths = append(breachPaths, breachPath)

				output := buildRDSBreachPathOutput(pathCounter, db, exposureResult, &access, computeResource, isLateralPath, lateralRoleARN)
				output.Authorization = access.Authorization
				output.LateralMovement = hasLateralMovement
				output.PrivilegeEscalation = hasPrivilegeEscalation
				breachPathOutputs = append(breachPathOutputs, output)
			}
		}
	}

	// Case 2: Publicly exposed critical RDS databases (direct public access)
	logging.LogDebug(fmt.Sprintf("Case 2: Checking %d databases for public exposure", len(rdsData.AllDatabases)))
	for _, db := range rdsData.AllDatabases {
		dbName := db.Name
		exposureResult := rdsData.ExposureMap[dbName]
		if exposureResult == nil {
			logging.LogDebug(fmt.Sprintf("Case 2: Database %s has nil exposure result, skipping", dbName))
			continue
		}

		logging.LogDebug(fmt.Sprintf("Case 2: Database %s has FinalExposure=%s", dbName, exposureResult.FinalExposure))
		if exposureResult.FinalExposure == "Public" {
			pathCounter++
			logging.LogDebug(fmt.Sprintf("Case 2: Creating public breach path for database %s (path #%d)", dbName, pathCounter))

			publicBreachPath := domain.BreachPath{
				PathID:      fmt.Sprintf("rds-breach-path-public-%d", pathCounter),
				Vector:      "Public",
				ResourceID:  dbName,
				ResourceARN: &db.ARN,
				TargetDB:    db.ARN,
				TargetType:  "RDS",
				Status:      fmt.Sprintf("Public RDS Database (%s)", exposureResult.Details),
			}
			if db.Encrypted != nil {
				publicBreachPath.TargetEncrypted = db.Encrypted
			}
			if db.KMSKeyID != nil {
				publicBreachPath.KMSKeyID = db.KMSKeyID
			}
			breachPaths = append(breachPaths, publicBreachPath)

			// Build output for public RDS
			storeInfo := domain.StoreInfo{
				ResourceARN:  db.ARN,
				ResourceName: dbName,
				ResourceType: "RDS",
				Encrypted:    db.Encrypted,
				KMSKeyID:     db.KMSKeyID,
				IsCrownJewel: true,
			}
			output := domain.BreachPathOutput{
				PathID:          fmt.Sprintf("rds-breach-path-public-%d", pathCounter),
				PathString:      fmt.Sprintf("Internet → %s (RDS)", db.ARN),
				PathType:        "PUBLIC_DATABASE",
				InternetExposed: true,
				Store:           storeInfo,
				BucketExposed:   true,
				ExposureDetails: exposureResult,
			}
			breachPathOutputs = append(breachPathOutputs, output)
		}
	}

	step11Duration := time.Since(step11StartTime)

	if len(breachPaths) > 0 {
		fmt.Print(outputter.FormatStepOutputWithTiming(11, "RDS Breach Paths",
			"Final attack path enumeration from internet-exposed workloads to RDS crown jewels",
			breachPaths, step11Duration))
	}

	return breachPaths, breachPathOutputs, nil
}

// buildRDSBreachPathFromComputeResource creates a BreachPath for RDS from compute resource
func buildRDSBreachPathFromComputeResource(
	pathCounter int,
	db domain.RDSJewel,
	exposureResult *domain.ExposureResult,
	access domain.PrincipalAccess,
	computeResource domain.ComputeResource,
	isLateralPath bool,
	lateralRoleARN string,
) domain.BreachPath {
	resourceARN := computeResource.ResourceARN
	path := domain.BreachPath{
		PathID:           fmt.Sprintf("rds-breach-path-%d", pathCounter),
		Vector:           computeResource.RuntimeType,
		ResourceID:       computeResource.ResourceID,
		ResourceARN:      &resourceARN,
		Role:             access.PrincipalName,
		RoleARN:          computeResource.RoleARN,
		TargetDB:         db.ARN,
		TargetType:       "RDS",
		Status:           fmt.Sprintf("RDS Database (%s)", exposureResult.FinalExposure),
		PublicIP:         computeResource.PublicIP,
		VPCID:            computeResource.VPCID,
		SubnetIDs:        computeResource.SubnetIDs,
		SecurityGroupIDs: computeResource.SecurityGroupIDs,
		LateralMovement:  isLateralPath,
	}
	if db.Encrypted != nil {
		path.TargetEncrypted = db.Encrypted
	}
	if db.KMSKeyID != nil {
		path.KMSKeyID = db.KMSKeyID
	}
	if isLateralPath && lateralRoleARN != "" {
		path.AssumedRoleARN = access.PrincipalARN
	}
	return path
}

// buildRDSBreachPathOutput creates a BreachPathOutput for RDS
func buildRDSBreachPathOutput(
	pathCounter int,
	db domain.RDSJewel,
	exposureResult *domain.ExposureResult,
	access *domain.PrincipalAccess,
	computeResource domain.ComputeResource,
	isLateralPath bool,
	lateralRoleARN string,
) domain.BreachPathOutput {
	pathType := fmt.Sprintf("%s_TO_RDS", strings.ToUpper(computeResource.RuntimeType))

	storeInfo := domain.StoreInfo{
		ResourceARN:  db.ARN,
		ResourceName: db.Name,
		ResourceType: "RDS",
		Encrypted:    db.Encrypted,
		KMSKeyID:     db.KMSKeyID,
		IsCrownJewel: true,
	}

	output := domain.BreachPathOutput{
		PathID:          fmt.Sprintf("rds-breach-path-%d", pathCounter),
		PathType:        pathType,
		InternetExposed: computeResource.InternetExposed,
		Store:           storeInfo,
		BucketExposed:   exposureResult.FinalExposure == "Public",
		ExposureDetails: exposureResult,
	}

	// Build path string
	pathParts := []string{"Internet"}
	switch computeResource.RuntimeType {
	case "EC2":
		if computeResource.PublicIP != nil {
			pathParts = append(pathParts, fmt.Sprintf("EC2 %s (Public IP: %s)", computeResource.ResourceID, *computeResource.PublicIP))
		} else {
			pathParts = append(pathParts, fmt.Sprintf("EC2 %s", computeResource.ResourceID))
		}
	case "Lambda":
		pathParts = append(pathParts, fmt.Sprintf("Lambda %s", computeResource.ResourceID))
	default:
		pathParts = append(pathParts, fmt.Sprintf("%s %s", computeResource.RuntimeType, computeResource.ResourceID))
	}

	if access != nil {
		if isLateralPath && lateralRoleARN != "" {
			lateralRoleName := outputter.ExtractRoleNameFromARN(lateralRoleARN)
			pathParts = append(pathParts, fmt.Sprintf("role %s", lateralRoleName))
			pathParts = append(pathParts, fmt.Sprintf("(assume role %s)", access.PrincipalName))
		} else {
			pathParts = append(pathParts, fmt.Sprintf("role %s", access.PrincipalName))
		}
	}
	pathParts = append(pathParts, fmt.Sprintf("%s (RDS)", db.ARN))
	output.PathString = strings.Join(pathParts, " → ")

	// Build container info based on runtime type
	output.Container = buildRDSWorkloadInfo(computeResource)

	if access != nil {
		output.IAMRole = &domain.IAMRoleInfo{
			RoleARN:     access.PrincipalARN,
			RoleName:    access.PrincipalName,
			RiskProfile: access.RiskProfile,
		}
	}

	return output
}

// buildRDSWorkloadInfo constructs EC2WorkloadInfo from ComputeResource for RDS breach paths
func buildRDSWorkloadInfo(cr domain.ComputeResource) *domain.EC2WorkloadInfo {
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

// extractDBNameFromARN extracts the database name from an RDS ARN
func extractDBNameFromARN(arn string) string {
	// Format: arn:aws:rds:<region>:<account>:db:<db-instance-identifier>
	parts := strings.Split(arn, ":")
	if len(parts) >= 7 {
		return parts[6]
	}
	return arn
}
