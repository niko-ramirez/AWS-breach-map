package breachpath

import (
	"testing"

	"breachmap/internal/domain"
	"breachmap/internal/exposure"
	"breachmap/internal/mocks"
)

// =============================================================================
// CATEGORY 1: BUCKET POLICY EXPOSURE TESTS
// =============================================================================

func TestEvaluatePolicyExposure_PublicPolicy(t *testing.T) {
	t.Run("1.1 Principal:* with no conditions should be Public", func(t *testing.T) {
		policy := &domain.BucketPolicyJSON{
			Statement: []domain.PolicyStatement{
				{
					Effect:    "Allow",
					Principal: "*",
					Action:    "s3:GetObject",
					Resource:  "arn:aws:s3:::test-bucket/*",
				},
			},
		}
		pab := &domain.PublicAccessBlockConfig{} // No blocking

		result := exposure.EvaluatePolicyExposure(policy, pab)

		if result != "Public" {
			t.Errorf("Expected 'Public', got '%s'", result)
		}
	})

	t.Run("1.4 Principal:* with PrincipalOrgID condition should be Org-Restricted", func(t *testing.T) {
		policy := &domain.BucketPolicyJSON{
			Statement: []domain.PolicyStatement{
				{
					Effect:    "Allow",
					Principal: "*",
					Action:    "s3:GetObject",
					Resource:  "arn:aws:s3:::test-bucket/*",
					Condition: map[string]interface{}{
						"StringEquals": map[string]interface{}{
							"aws:PrincipalOrgID": "o-123456789",
						},
					},
				},
			},
		}
		pab := &domain.PublicAccessBlockConfig{}

		result := exposure.EvaluatePolicyExposure(policy, pab)

		if result != "Org-Restricted" {
			t.Errorf("Expected 'Org-Restricted', got '%s'", result)
		}
	})

	t.Run("1.5 Principal:* with VPC condition should be Conditionally Public", func(t *testing.T) {
		policy := &domain.BucketPolicyJSON{
			Statement: []domain.PolicyStatement{
				{
					Effect:    "Allow",
					Principal: "*",
					Action:    "s3:GetObject",
					Resource:  "arn:aws:s3:::test-bucket/*",
					Condition: map[string]interface{}{
						"StringEquals": map[string]interface{}{
							"aws:SourceVpc": "vpc-12345678",
						},
					},
				},
			},
		}
		pab := &domain.PublicAccessBlockConfig{}

		result := exposure.EvaluatePolicyExposure(policy, pab)

		if result != "Conditionally Public" {
			t.Errorf("Expected 'Conditionally Public', got '%s'", result)
		}
	})

	t.Run("Policy blocked by PAB should be Private", func(t *testing.T) {
		policy := &domain.BucketPolicyJSON{
			Statement: []domain.PolicyStatement{
				{
					Effect:    "Allow",
					Principal: "*",
					Action:    "s3:GetObject",
					Resource:  "arn:aws:s3:::test-bucket/*",
				},
			},
		}
		pab := &domain.PublicAccessBlockConfig{
			BlockPublicPolicy: true,
		}

		result := exposure.EvaluatePolicyExposure(policy, pab)

		if result != "Private (Policy blocked by PAB)" {
			t.Errorf("Expected 'Private (Policy blocked by PAB)', got '%s'", result)
		}
	})

	t.Run("No policy should be Private", func(t *testing.T) {
		result := exposure.EvaluatePolicyExposure(nil, nil)

		if result != "Private" {
			t.Errorf("Expected 'Private', got '%s'", result)
		}
	})
}

// =============================================================================
// CATEGORY 2: ACL EXPOSURE TESTS
// =============================================================================

func TestEvaluateACLExposure_PublicACL(t *testing.T) {
	t.Run("2.1 AllUsers READ should be Public", func(t *testing.T) {
		acl := &domain.BucketACLJSON{
			Grants: []domain.ACLGrant{
				{
					Grantee: domain.ACLGrantee{
						Type: "Group",
						URI:  "http://acs.amazonaws.com/groups/global/AllUsers",
					},
					Permission: "READ",
				},
			},
		}
		pab := &domain.PublicAccessBlockConfig{}

		result := exposure.EvaluateACLExposure(acl, pab)

		if result != "Public" {
			t.Errorf("Expected 'Public', got '%s'", result)
		}
	})

	t.Run("2.4 AuthenticatedUsers READ should be AWS-Authenticated Public", func(t *testing.T) {
		acl := &domain.BucketACLJSON{
			Grants: []domain.ACLGrant{
				{
					Grantee: domain.ACLGrantee{
						Type: "Group",
						URI:  "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
					},
					Permission: "READ",
				},
			},
		}
		pab := &domain.PublicAccessBlockConfig{}

		result := exposure.EvaluateACLExposure(acl, pab)

		if result != "AWS-Authenticated Public" {
			t.Errorf("Expected 'AWS-Authenticated Public', got '%s'", result)
		}
	})

	t.Run("ACL blocked by PAB (IgnorePublicAcls) should be Private", func(t *testing.T) {
		acl := &domain.BucketACLJSON{
			Grants: []domain.ACLGrant{
				{
					Grantee: domain.ACLGrantee{
						Type: "Group",
						URI:  "http://acs.amazonaws.com/groups/global/AllUsers",
					},
					Permission: "READ",
				},
			},
		}
		pab := &domain.PublicAccessBlockConfig{
			IgnorePublicAcls: true,
		}

		result := exposure.EvaluateACLExposure(acl, pab)

		if result != "Private (ACL blocked by PAB)" {
			t.Errorf("Expected 'Private (ACL blocked by PAB)', got '%s'", result)
		}
	})

	t.Run("No public grants should be Private", func(t *testing.T) {
		acl := &domain.BucketACLJSON{
			Grants: []domain.ACLGrant{},
		}
		pab := &domain.PublicAccessBlockConfig{}

		result := exposure.EvaluateACLExposure(acl, pab)

		if result != "Private" {
			t.Errorf("Expected 'Private', got '%s'", result)
		}
	})
}

// =============================================================================
// CATEGORY 3: PUBLIC ACCESS BLOCK (PAB) TESTS
// =============================================================================

func TestEvaluatePABShortCircuit(t *testing.T) {
	t.Run("Full PAB should short-circuit to Private", func(t *testing.T) {
		pab := &domain.PublicAccessBlockConfig{
			BlockPublicAcls:       true,
			IgnorePublicAcls:      true,
			BlockPublicPolicy:     true,
			RestrictPublicBuckets: true,
		}

		blocked, message := exposure.EvaluatePABShortCircuit(pab)

		if !blocked {
			t.Error("Expected PAB to block public access")
		}
		if message != "Effectively Private (PAB Fully Blocking)" {
			t.Errorf("Expected 'Effectively Private (PAB Fully Blocking)', got '%s'", message)
		}
	})

	t.Run("Partial PAB should NOT short-circuit", func(t *testing.T) {
		// Note: EvaluatePABShortCircuit only checks BlockPublicAcls, BlockPublicPolicy,
		// and RestrictPublicBuckets (not IgnorePublicAcls)
		pab := &domain.PublicAccessBlockConfig{
			BlockPublicAcls:       true,
			IgnorePublicAcls:      true,
			BlockPublicPolicy:     true,
			RestrictPublicBuckets: false, // This one is actually checked, so false = partial
		}

		blocked, _ := exposure.EvaluatePABShortCircuit(pab)

		if blocked {
			t.Error("Partial PAB should not short-circuit")
		}
	})

	t.Run("No PAB should NOT short-circuit", func(t *testing.T) {
		blocked, _ := exposure.EvaluatePABShortCircuit(nil)

		if blocked {
			t.Error("nil PAB should not short-circuit")
		}
	})
}

// =============================================================================
// COMBINED EXPOSURE TESTS
// =============================================================================

func TestCombineExposureResults(t *testing.T) {
	t.Run("Public policy takes precedence", func(t *testing.T) {
		inputs := &domain.BucketExposureInputs{
			Policy: &domain.BucketPolicyJSON{
				Statement: []domain.PolicyStatement{
					{
						Effect:    "Allow",
						Principal: "*",
						Action:    "s3:GetObject",
						Resource:  "arn:aws:s3:::test-bucket/*",
					},
				},
			},
			ACL: &domain.BucketACLJSON{Grants: []domain.ACLGrant{}},
			PAB: &domain.PublicAccessBlockConfig{},
		}

		result := exposure.CombineExposureResults("test-bucket", inputs)

		if result.FinalExposure != "Public" {
			t.Errorf("Expected FinalExposure='Public', got '%s'", result.FinalExposure)
		}
	})

	t.Run("Full PAB blocks everything", func(t *testing.T) {
		inputs := &domain.BucketExposureInputs{
			Policy: &domain.BucketPolicyJSON{
				Statement: []domain.PolicyStatement{
					{
						Effect:    "Allow",
						Principal: "*",
						Action:    "s3:GetObject",
						Resource:  "arn:aws:s3:::test-bucket/*",
					},
				},
			},
			ACL: &domain.BucketACLJSON{
				Grants: []domain.ACLGrant{
					{
						Grantee:    domain.ACLGrantee{Type: "Group", URI: "http://acs.amazonaws.com/groups/global/AllUsers"},
						Permission: "READ",
					},
				},
			},
			PAB: &domain.PublicAccessBlockConfig{
				BlockPublicAcls:       true,
				IgnorePublicAcls:      true,
				BlockPublicPolicy:     true,
				RestrictPublicBuckets: true,
			},
		}

		result := exposure.CombineExposureResults("test-bucket", inputs)

		if result.FinalExposure != "Effectively Private (PAB Fully Blocking)" {
			t.Errorf("Expected 'Effectively Private (PAB Fully Blocking)', got '%s'", result.FinalExposure)
		}
		if !result.PABBlocking {
			t.Error("Expected PABBlocking=true")
		}
	})
}

// =============================================================================
// S3 CROWN JEWEL BUILDER TESTS
// =============================================================================

func TestS3JewelBuilder(t *testing.T) {
	t.Run("Build unencrypted bucket", func(t *testing.T) {
		jewel := mocks.NewS3JewelBuilder("test-bucket").
			Unencrypted().
			Build()

		if jewel.Name != "test-bucket" {
			t.Errorf("Expected Name='test-bucket', got '%s'", jewel.Name)
		}
		if jewel.ARN != "arn:aws:s3:::test-bucket" {
			t.Errorf("Expected ARN='arn:aws:s3:::test-bucket', got '%s'", jewel.ARN)
		}
		if jewel.Encrypted == nil || *jewel.Encrypted {
			t.Error("Expected Encrypted=false")
		}
		if jewel.KMSKeyID != nil {
			t.Error("Expected KMSKeyID=nil for unencrypted bucket")
		}
	})

	t.Run("Build KMS encrypted bucket", func(t *testing.T) {
		kmsKeyARN := "arn:aws:kms:us-east-1:123456789012:key/test-key"
		jewel := mocks.NewS3JewelBuilder("encrypted-bucket").
			Encrypted(kmsKeyARN).
			Build()

		if jewel.Encrypted == nil || !*jewel.Encrypted {
			t.Error("Expected Encrypted=true")
		}
		if jewel.KMSKeyID == nil || *jewel.KMSKeyID != kmsKeyARN {
			t.Errorf("Expected KMSKeyID='%s'", kmsKeyARN)
		}
	})

	t.Run("Build SSE-S3 encrypted bucket", func(t *testing.T) {
		jewel := mocks.NewS3JewelBuilder("sses3-bucket").
			SSES3Encrypted().
			Build()

		if jewel.Encrypted == nil || !*jewel.Encrypted {
			t.Error("Expected Encrypted=true for SSE-S3")
		}
		if jewel.KMSKeyID != nil {
			t.Error("Expected KMSKeyID=nil for SSE-S3 (not KMS)")
		}
	})
}

// =============================================================================
// EXPOSURE BUILDER TESTS
// =============================================================================

func TestBucketPolicyBuilder(t *testing.T) {
	t.Run("Build public GetObject policy", func(t *testing.T) {
		policy := mocks.NewBucketPolicyBuilder().
			AllowPublicGetObject("my-bucket").
			Build()

		if policy == "" {
			t.Error("Expected non-empty policy JSON")
		}
		// Verify it contains expected elements
		assertContainsS3(t, policy, `"Principal":"*"`)
		assertContainsS3(t, policy, `"s3:GetObject"`)
	})

	t.Run("Build org-restricted policy", func(t *testing.T) {
		policy := mocks.NewBucketPolicyBuilder().
			WithOrgCondition("o-12345", "my-bucket").
			Build()

		assertContainsS3(t, policy, `"aws:PrincipalOrgID"`)
		assertContainsS3(t, policy, `"o-12345"`)
	})
}

func TestACLBuilder(t *testing.T) {
	t.Run("Build AllUsers READ ACL", func(t *testing.T) {
		acl := mocks.NewACLBuilder().
			GrantAllUsersRead().
			Build()

		if len(acl.Grants) != 1 {
			t.Errorf("Expected 1 grant, got %d", len(acl.Grants))
		}
		if acl.Grants[0].Permission != "READ" {
			t.Errorf("Expected permission READ, got %s", acl.Grants[0].Permission)
		}
	})
}

func TestPABBuilder(t *testing.T) {
	t.Run("Build full blocking PAB", func(t *testing.T) {
		pab := mocks.NewPABBuilder().BlockAll().Build()

		config := pab.PublicAccessBlockConfiguration
		if !*config.BlockPublicAcls || !*config.IgnorePublicAcls ||
			!*config.BlockPublicPolicy || !*config.RestrictPublicBuckets {
			t.Error("Expected all PAB settings to be true")
		}
	})

	t.Run("Build allow all PAB", func(t *testing.T) {
		pab := mocks.NewPABBuilder().AllowAll().Build()

		config := pab.PublicAccessBlockConfiguration
		if *config.BlockPublicAcls || *config.IgnorePublicAcls ||
			*config.BlockPublicPolicy || *config.RestrictPublicBuckets {
			t.Error("Expected all PAB settings to be false")
		}
	})
}

// =============================================================================
// PRE-BUILT SCENARIO TESTS
// =============================================================================

func TestPreBuiltS3Scenarios(t *testing.T) {
	t.Run("PrivateKMSEncrypted scenario", func(t *testing.T) {
		jewel := mocks.TestS3Scenarios.PrivateKMSEncrypted()

		if jewel.Encrypted == nil || !*jewel.Encrypted {
			t.Error("Expected Encrypted=true")
		}
		if jewel.KMSKeyID == nil || *jewel.KMSKeyID == "" {
			t.Error("Expected KMSKeyID to be set")
		}
	})

	t.Run("PublicUnencrypted scenario", func(t *testing.T) {
		jewel := mocks.TestS3Scenarios.PublicUnencrypted()

		if jewel.Encrypted == nil || *jewel.Encrypted {
			t.Error("Expected Encrypted=false")
		}
	})
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

func assertContainsS3(t *testing.T, str, substr string) {
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
