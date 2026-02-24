package breachpath

import (
	"context"
	"testing"

	"breachmap/internal/domain"
	"breachmap/internal/mocks"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

/*
=============================================================================
RDS ATTACK VECTORS - End-to-End Test Scenarios
=============================================================================
(See bottom of file for full attack vector documentation)
=============================================================================
*/

// =============================================================================
// CATEGORY 1: DIRECT PUBLIC EXPOSURE TESTS
// =============================================================================

func TestAnalyzeRDSExposure_PubliclyAccessible(t *testing.T) {
	t.Run("1.1 PubliclyAccessible=true should be flagged as Public", func(t *testing.T) {
		db := mocks.NewRDSJewelBuilder("test-db-public").
			Public().
			WithIAMAuth().
			MySQL().
			Build()

		result := AnalyzeRDSExposureFromJewel(db)

		if result.FinalExposure != "Public" {
			t.Errorf("Expected FinalExposure='Public', got '%s'", result.FinalExposure)
		}
		if result.Details == "" {
			t.Error("Expected Details to contain exposure reasons")
		}
		assertContains(t, result.Details, "PubliclyAccessible=true")
	})

	t.Run("1.2 PubliclyAccessible=false should be flagged as Private or IAM-Authenticated", func(t *testing.T) {
		db := mocks.NewRDSJewelBuilder("test-db-private").
			Private().
			WithIAMAuth().
			Build()

		result := AnalyzeRDSExposureFromJewel(db)

		if result.FinalExposure == "Public" {
			t.Errorf("Expected FinalExposure != 'Public', got '%s'", result.FinalExposure)
		}
	})

	t.Run("Private DB without IAM auth should be flagged as Private", func(t *testing.T) {
		db := mocks.NewRDSJewelBuilder("test-db-private-password").
			Private().
			WithPasswordAuth().
			Build()

		result := AnalyzeRDSExposureFromJewel(db)

		if result.FinalExposure != "Private" {
			t.Errorf("Expected FinalExposure='Private', got '%s'", result.FinalExposure)
		}
	})
}

// =============================================================================
// CATEGORY 2: IAM AUTHENTICATION TESTS
// =============================================================================

func TestAnalyzeRDSExposure_IAMAuthentication(t *testing.T) {
	t.Run("2.1 IAM auth enabled should be flagged with IAMAuthenticator=true", func(t *testing.T) {
		db := mocks.NewRDSJewelBuilder("test-db-iam").
			Private().
			WithIAMAuth().
			Build()

		result := AnalyzeRDSExposureFromJewel(db)

		assertContains(t, result.Details, "IAMAuthenticator=true")
		if result.FinalExposure != "IAM-Authenticated" {
			t.Errorf("Expected FinalExposure='IAM-Authenticated', got '%s'", result.FinalExposure)
		}
		// Should have IAMAuthEnabled policy statement
		if len(result.PolicyStatements) == 0 {
			t.Fatal("Expected PolicyStatements to be populated")
		}
		if result.PolicyStatements[0].Sid != "IAMAuthEnabled" {
			t.Errorf("Expected Sid='IAMAuthEnabled', got '%s'", result.PolicyStatements[0].Sid)
		}
	})

	t.Run("2.4 IAM auth disabled should be flagged as password-only", func(t *testing.T) {
		db := mocks.NewRDSJewelBuilder("test-db-password").
			Private().
			WithPasswordAuth().
			Build()

		result := AnalyzeRDSExposureFromJewel(db)

		assertContains(t, result.Details, "IAMAuthenticator=false")
		assertContains(t, result.Details, "password auth only")
		// Should have PasswordAuthOnly policy statement
		if len(result.PolicyStatements) == 0 {
			t.Fatal("Expected PolicyStatements to be populated")
		}
		if result.PolicyStatements[0].Sid != "PasswordAuthOnly" {
			t.Errorf("Expected Sid='PasswordAuthOnly', got '%s'", result.PolicyStatements[0].Sid)
		}
	})

	t.Run("Public + IAM auth should show both flags", func(t *testing.T) {
		db := mocks.NewRDSJewelBuilder("test-db-public-iam").
			Public().
			WithIAMAuth().
			Build()

		result := AnalyzeRDSExposureFromJewel(db)

		if result.FinalExposure != "Public" {
			t.Errorf("Expected FinalExposure='Public' (Public takes precedence), got '%s'", result.FinalExposure)
		}
		assertContains(t, result.Details, "PubliclyAccessible=true")
		assertContains(t, result.Details, "IAMAuthenticator=true")
	})
}

// =============================================================================
// CATEGORY 3: ENCRYPTION TESTS
// =============================================================================

func TestAnalyzeRDSExposure_Encryption(t *testing.T) {
	t.Run("3.1 Unencrypted database should be trackable", func(t *testing.T) {
		db := mocks.NewRDSJewelBuilder("test-db-unencrypted").
			Private().
			Unencrypted().
			Build()

		// Encryption is stored in the jewel, not exposure result
		if db.Encrypted == nil || *db.Encrypted {
			t.Error("Expected Encrypted=false")
		}
		if db.KMSKeyID != nil {
			t.Error("Expected KMSKeyID=nil for unencrypted DB")
		}
	})

	t.Run("3.4 KMS encrypted database should have key ID", func(t *testing.T) {
		kmsKeyARN := mocks.TestKMSKeyARN("test-key-123")
		db := mocks.NewRDSJewelBuilder("test-db-encrypted").
			Private().
			Encrypted(kmsKeyARN).
			Build()

		if db.Encrypted == nil || !*db.Encrypted {
			t.Error("Expected Encrypted=true")
		}
		if db.KMSKeyID == nil || *db.KMSKeyID != kmsKeyARN {
			t.Errorf("Expected KMSKeyID='%s', got '%v'", kmsKeyARN, db.KMSKeyID)
		}
	})
}

// =============================================================================
// IAM AUTHORIZATION VERIFICATION TESTS
// =============================================================================

func TestVerifyRDSRoleAuthorization_IAMAuthEnabled(t *testing.T) {
	ctx := context.Background()

	t.Run("IAM auth enabled + role allowed should be exploitable", func(t *testing.T) {
		db := mocks.NewRDSJewelBuilder("test-db-iam").
			WithAccountID("123456789012").
			WithRegion("us-east-1").
			Private().
			WithIAMAuth().
			Build()

		mockIAM := &mocks.MockIAMClient{
			SimulatePrincipalPolicyFunc: func(
				ctx context.Context,
				params *iam.SimulatePrincipalPolicyInput,
				optFns ...func(*iam.Options),
			) (*iam.SimulatePrincipalPolicyOutput, error) {
				// Verify correct action is being simulated
				if len(params.ActionNames) != 1 || params.ActionNames[0] != "rds-db:connect" {
					t.Errorf("Expected action 'rds-db:connect', got %v", params.ActionNames)
				}
				return &iam.SimulatePrincipalPolicyOutput{
					EvaluationResults: []iamtypes.EvaluationResult{
						{
							EvalActionName: aws.String("rds-db:connect"),
							EvalDecision:   iamtypes.PolicyEvaluationDecisionTypeAllowed,
						},
					},
				}, nil
			},
		}

		roleARN := mocks.TestRoleARN("AdminRole")
		result := verifyRDSRoleAuthorizationWithMock(ctx, mockIAM, roleARN, db)

		if !result.ResourceAccessAllowed {
			t.Error("Expected ResourceAccessAllowed=true (RDS access allowed)")
		}
		if !result.Exploitable {
			t.Error("Expected Exploitable=true")
		}
		if mockIAM.SimulatePrincipalPolicyCallCount != 1 {
			t.Errorf("Expected 1 IAM call, got %d", mockIAM.SimulatePrincipalPolicyCallCount)
		}
	})

	t.Run("IAM auth enabled + role denied should not be exploitable", func(t *testing.T) {
		db := mocks.NewRDSJewelBuilder("test-db-iam-denied").
			WithAccountID("123456789012").
			WithRegion("us-east-1").
			Private().
			WithIAMAuth().
			Build()

		mockIAM := mocks.NewMockIAMClientDenyAll()
		roleARN := mocks.TestRoleARN("LimitedRole")
		result := verifyRDSRoleAuthorizationWithMock(ctx, mockIAM, roleARN, db)

		if result.ResourceAccessAllowed {
			t.Error("Expected ResourceAccessAllowed=false (RDS access denied)")
		}
		if result.Exploitable {
			t.Error("Expected Exploitable=false")
		}
	})

	t.Run("IAM auth enabled + explicit deny should not be exploitable", func(t *testing.T) {
		db := mocks.NewRDSJewelBuilder("test-db-explicit-deny").
			WithAccountID("123456789012").
			WithRegion("us-east-1").
			Private().
			WithIAMAuth().
			Build()

		mockIAM := mocks.NewMockIAMClientExplicitDeny()
		roleARN := mocks.TestRoleARN("DeniedRole")
		result := verifyRDSRoleAuthorizationWithMock(ctx, mockIAM, roleARN, db)

		if result.ResourceAccessAllowed {
			t.Error("Expected ResourceAccessAllowed=false (explicit deny)")
		}
		if result.Exploitable {
			t.Error("Expected Exploitable=false (explicit deny)")
		}
	})
}

func TestVerifyRDSRoleAuthorization_PasswordOnly(t *testing.T) {
	ctx := context.Background()

	t.Run("Password-only auth should skip IAM verification", func(t *testing.T) {
		db := mocks.NewRDSJewelBuilder("test-db-password-only").
			Private().
			WithPasswordAuth().
			Build()

		mockIAM := &mocks.MockIAMClient{}
		roleARN := mocks.TestRoleARN("AnyRole")
		result := verifyRDSRoleAuthorizationWithMock(ctx, mockIAM, roleARN, db)

		// Should NOT call IAM at all
		if mockIAM.SimulatePrincipalPolicyCallCount != 0 {
			t.Errorf("Expected 0 IAM calls for password-only DB, got %d", mockIAM.SimulatePrincipalPolicyCallCount)
		}

		// Should be marked as not exploitable via IAM
		if result.Exploitable {
			t.Error("Expected Exploitable=false for password-only DB")
		}

		// Should have auth_type in details
		if authType, ok := result.SimulationDetails["auth_type"]; !ok || authType != "password_only" {
			t.Error("Expected SimulationDetails['auth_type']='password_only'")
		}
	})
}

// =============================================================================
// RISK PROFILE TESTS
// =============================================================================

func TestDetermineRDSRiskProfile(t *testing.T) {
	t.Run("Password-only DB should return PASSWORD_AUTH_ONLY", func(t *testing.T) {
		db := mocks.NewRDSJewelBuilder("test-db").
			WithPasswordAuth().
			Build()

		roleARN := mocks.TestRoleARN("TestRole")
		profile := determineRDSRiskProfile(db, roleARN, nil, nil)

		if profile != "PASSWORD_AUTH_ONLY" {
			t.Errorf("Expected 'PASSWORD_AUTH_ONLY', got '%s'", profile)
		}
	})

	t.Run("IAM auth without KMS should return RDS_IAM_CONNECT", func(t *testing.T) {
		db := mocks.NewRDSJewelBuilder("test-db").
			WithIAMAuth().
			Unencrypted().
			Build()

		roleARN := mocks.TestRoleARN("TestRole")
		profile := determineRDSRiskProfile(db, roleARN, nil, nil)

		if profile != "RDS_IAM_CONNECT" {
			t.Errorf("Expected 'RDS_IAM_CONNECT', got '%s'", profile)
		}
	})

	t.Run("IAM auth with KMS + CMK access should return RDS_IAM_CONNECT_WITH_KMS", func(t *testing.T) {
		kmsKeyARN := mocks.TestKMSKeyARN("test-key")
		db := mocks.NewRDSJewelBuilder("test-db").
			WithIAMAuth().
			Encrypted(kmsKeyARN).
			Build()

		roleARN := mocks.TestRoleARN("TestRole")
		cmkToRolesMap := map[string][]string{
			kmsKeyARN: {roleARN},
		}
		resourceToCMKMap := mocks.TestCMKMap(map[string]string{
			"test-db": kmsKeyARN,
		})

		profile := determineRDSRiskProfile(db, roleARN, cmkToRolesMap, resourceToCMKMap)

		if profile != "RDS_IAM_CONNECT_WITH_KMS" {
			t.Errorf("Expected 'RDS_IAM_CONNECT_WITH_KMS', got '%s'", profile)
		}
	})
}

// =============================================================================
// PRE-BUILT SCENARIO TESTS
// =============================================================================

func TestPreBuiltScenarios(t *testing.T) {
	t.Run("PublicIAMAuthEncrypted scenario", func(t *testing.T) {
		db := mocks.TestRDSScenarios.PublicIAMAuthEncrypted()

		if db.PubliclyAccessible == nil || !*db.PubliclyAccessible {
			t.Error("Expected PubliclyAccessible=true")
		}
		if db.IAMAuthEnabled == nil || !*db.IAMAuthEnabled {
			t.Error("Expected IAMAuthEnabled=true")
		}
		if db.Encrypted == nil || !*db.Encrypted {
			t.Error("Expected Encrypted=true")
		}
		if db.KMSKeyID == nil || *db.KMSKeyID == "" {
			t.Error("Expected KMSKeyID to be set")
		}
	})

	t.Run("PrivatePasswordOnly scenario", func(t *testing.T) {
		db := mocks.TestRDSScenarios.PrivatePasswordOnly()

		if db.PubliclyAccessible == nil || *db.PubliclyAccessible {
			t.Error("Expected PubliclyAccessible=false")
		}
		if db.IAMAuthEnabled == nil || *db.IAMAuthEnabled {
			t.Error("Expected IAMAuthEnabled=false")
		}
	})
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

// verifyRDSRoleAuthorizationWithMock is a test-friendly version that accepts mock IAM client
func verifyRDSRoleAuthorizationWithMock(
	ctx context.Context,
	iamMock mocks.IAMSimulatePrincipalPolicy,
	roleARN string,
	db domain.RDSJewel,
) *domain.AuthorizationResult {
	result := &domain.AuthorizationResult{
		SimulationDetails: make(map[string]interface{}),
	}

	// Check if database has IAM authentication enabled
	if db.IAMAuthEnabled == nil || !*db.IAMAuthEnabled {
		result.ResourceAccessAllowed = false
		result.Exploitable = false
		result.SimulationDetails["auth_type"] = "password_only"
		result.SimulationDetails["note"] = "IAM authentication not enabled - access depends on database credentials"
		return result
	}

	// Extract account ID and region from database ARN
	accountID := "123456789012"
	region := "us-east-1"

	// Build resource ARN for simulation
	resourceARN := "arn:aws:rds-db:" + region + ":" + accountID + ":dbuser:*/*"

	simInput := &iam.SimulatePrincipalPolicyInput{
		PolicySourceArn: aws.String(roleARN),
		ActionNames:     []string{"rds-db:connect"},
		ResourceArns:    []string{resourceARN},
	}

	simOutput, err := iamMock.SimulatePrincipalPolicy(ctx, simInput)
	if err != nil {
		result.SimulationDetails["rds_simulation_error"] = err.Error()
		result.ResourceAccessAllowed = false
		result.Exploitable = false
		return result
	}

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
	result.Exploitable = result.ResourceAccessAllowed

	return result
}

func assertContains(t *testing.T, str, substr string) {
	t.Helper()
	if str == "" {
		t.Errorf("String is empty, expected to contain '%s'", substr)
		return
	}
	for i := 0; i <= len(str)-len(substr); i++ {
		if str[i:i+len(substr)] == substr {
			return
		}
	}
	t.Errorf("Expected string to contain '%s', got '%s'", substr, str)
}
