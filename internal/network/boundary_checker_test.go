package network

import (
	"testing"

	"breachmap/internal/domain"
)

/*
Network Boundary Invariant Tests

These tests document and verify the behavior of each network boundary invariant.
Each test case demonstrates a specific scenario and expected outcome.
*/

// =============================================================================
// NB-001: VPC_DENY_EXPLICIT
// Resource policy has: Deny + StringEquals aws:SourceVpc = [vpc-xxx]
// =============================================================================

func TestNB001_VPCDenyExplicit_Blocks(t *testing.T) {
	// SCENARIO: Bucket policy explicitly denies our VPC
	// EXPECTED: Path is BLOCKED
	conditions := &domain.ResourcePolicyConditions{
		DeniedVPCs: []string{"vpc-denied-123"},
	}
	ctx := &domain.NetworkContext{
		SourceVPCID:      strPtr("vpc-denied-123"),
		TargetConditions: conditions,
	}

	result := CheckNetworkBoundaries(ctx, "arn:aws:s3:::test-bucket")

	if !result.AnyBlocks {
		t.Errorf("Expected path to be BLOCKED, but it was not")
	}
	assertContainsInvariant(t, result.BlockingChecks, domain.InvariantVPCDenyExplicit)
}

func TestNB001_VPCDenyExplicit_Allows(t *testing.T) {
	// SCENARIO: Bucket policy denies vpc-other, but we're in vpc-ours
	// EXPECTED: Path is ALLOWED
	conditions := &domain.ResourcePolicyConditions{
		DeniedVPCs: []string{"vpc-other"},
	}
	ctx := &domain.NetworkContext{
		SourceVPCID:      strPtr("vpc-ours"),
		TargetConditions: conditions,
	}

	result := CheckNetworkBoundaries(ctx, "arn:aws:s3:::test-bucket")

	if result.AnyBlocks {
		t.Errorf("Expected path to be ALLOWED, but it was blocked: %v", result.BlockingChecks)
	}
}

// =============================================================================
// NB-002: VPC_ALLOW_WHITELIST
// Resource policy has: Allow + StringEquals aws:SourceVpc = [vpc-xxx]
// =============================================================================

func TestNB002_VPCAllowWhitelist_Blocks(t *testing.T) {
	// SCENARIO: Bucket policy only allows vpc-trusted, we're in vpc-untrusted
	// EXPECTED: Path is BLOCKED
	conditions := &domain.ResourcePolicyConditions{
		AllowedVPCs: []string{"vpc-trusted"},
	}
	ctx := &domain.NetworkContext{
		SourceVPCID:      strPtr("vpc-untrusted"),
		TargetConditions: conditions,
	}

	result := CheckNetworkBoundaries(ctx, "arn:aws:s3:::test-bucket")

	if !result.AnyBlocks {
		t.Errorf("Expected path to be BLOCKED, but it was not")
	}
	assertContainsInvariant(t, result.BlockingChecks, domain.InvariantVPCAllowWhitelist)
}

func TestNB002_VPCAllowWhitelist_Allows(t *testing.T) {
	// SCENARIO: Bucket policy allows vpc-trusted, we're in vpc-trusted
	// EXPECTED: Path is ALLOWED
	conditions := &domain.ResourcePolicyConditions{
		AllowedVPCs: []string{"vpc-trusted", "vpc-also-trusted"},
	}
	ctx := &domain.NetworkContext{
		SourceVPCID:      strPtr("vpc-trusted"),
		TargetConditions: conditions,
	}

	result := CheckNetworkBoundaries(ctx, "arn:aws:s3:::test-bucket")

	if result.AnyBlocks {
		t.Errorf("Expected path to be ALLOWED, but it was blocked: %v", result.BlockingChecks)
	}
}

// =============================================================================
// NB-003: VPC_DENY_NOT_EQUALS
// Resource policy has: Deny + StringNotEquals aws:SourceVpc = [vpc-xxx]
// This is an inverse whitelist - deny everyone EXCEPT these VPCs
// =============================================================================

func TestNB003_VPCDenyNotEquals_Blocks(t *testing.T) {
	// SCENARIO: Bucket policy says "Deny if NOT vpc-allowed"
	//           We're in vpc-random (not in exception list)
	// EXPECTED: Path is BLOCKED
	conditions := &domain.ResourcePolicyConditions{
		DenyIfNotInVPCs: []string{"vpc-allowed"},
	}
	ctx := &domain.NetworkContext{
		SourceVPCID:      strPtr("vpc-random"),
		TargetConditions: conditions,
	}

	result := CheckNetworkBoundaries(ctx, "arn:aws:s3:::test-bucket")

	if !result.AnyBlocks {
		t.Errorf("Expected path to be BLOCKED, but it was not")
	}
	assertContainsInvariant(t, result.BlockingChecks, domain.InvariantVPCDenyNotEquals)
}

func TestNB003_VPCDenyNotEquals_Allows(t *testing.T) {
	// SCENARIO: Bucket policy says "Deny if NOT vpc-allowed"
	//           We're in vpc-allowed (in exception list)
	// EXPECTED: Path is ALLOWED
	conditions := &domain.ResourcePolicyConditions{
		DenyIfNotInVPCs: []string{"vpc-allowed"},
	}
	ctx := &domain.NetworkContext{
		SourceVPCID:      strPtr("vpc-allowed"),
		TargetConditions: conditions,
	}

	result := CheckNetworkBoundaries(ctx, "arn:aws:s3:::test-bucket")

	if result.AnyBlocks {
		t.Errorf("Expected path to be ALLOWED, but it was blocked: %v", result.BlockingChecks)
	}
}

// =============================================================================
// NB-004: VPCE_ALLOW_WHITELIST
// Resource policy has: Allow + StringEquals aws:SourceVpce = [vpce-xxx]
// =============================================================================

func TestNB004_VPCEAllowWhitelist_Blocks_NoEndpoint(t *testing.T) {
	// SCENARIO: Bucket requires access via vpce-required, we have no endpoint
	// EXPECTED: Path is BLOCKED
	conditions := &domain.ResourcePolicyConditions{
		AllowedVPCEs:      []string{"vpce-required"},
		HasVPCEConditions: true,
	}
	ctx := &domain.NetworkContext{
		SourceVPCID:        strPtr("vpc-123"),
		AvailableEndpoints: []domain.VPCEndpointInfo{}, // No endpoints
		TargetConditions:   conditions,
	}

	result := CheckNetworkBoundaries(ctx, "arn:aws:s3:::test-bucket")

	if !result.AnyBlocks {
		t.Errorf("Expected path to be BLOCKED, but it was not")
	}
}

func TestNB004_VPCEAllowWhitelist_Blocks_WrongEndpoint(t *testing.T) {
	// SCENARIO: Bucket requires vpce-required, we have vpce-different
	// EXPECTED: Path is BLOCKED
	conditions := &domain.ResourcePolicyConditions{
		AllowedVPCEs:      []string{"vpce-required"},
		HasVPCEConditions: true,
	}
	ctx := &domain.NetworkContext{
		SourceVPCID: strPtr("vpc-123"),
		AvailableEndpoints: []domain.VPCEndpointInfo{
			{EndpointID: "vpce-different", VpcID: "vpc-123", ServiceName: "com.amazonaws.us-east-1.s3"},
		},
		TargetConditions: conditions,
	}

	result := CheckNetworkBoundaries(ctx, "arn:aws:s3:::test-bucket")

	if !result.AnyBlocks {
		t.Errorf("Expected path to be BLOCKED, but it was not")
	}
	assertContainsInvariant(t, result.BlockingChecks, domain.InvariantVPCEAllowWhitelist)
}

func TestNB004_VPCEAllowWhitelist_Allows(t *testing.T) {
	// SCENARIO: Bucket requires vpce-required, we have vpce-required
	// EXPECTED: Path is ALLOWED
	conditions := &domain.ResourcePolicyConditions{
		AllowedVPCEs:      []string{"vpce-required"},
		HasVPCEConditions: true,
	}
	ctx := &domain.NetworkContext{
		SourceVPCID: strPtr("vpc-123"),
		AvailableEndpoints: []domain.VPCEndpointInfo{
			{EndpointID: "vpce-required", VpcID: "vpc-123", ServiceName: "com.amazonaws.us-east-1.s3"},
		},
		TargetConditions: conditions,
	}

	result := CheckNetworkBoundaries(ctx, "arn:aws:s3:::test-bucket")

	if result.AnyBlocks {
		t.Errorf("Expected path to be ALLOWED, but it was blocked: %v", result.BlockingChecks)
	}
}

// =============================================================================
// NB-005: VPCE_DENY_EXPLICIT
// Resource policy has: Deny + StringEquals aws:SourceVpce = [vpce-xxx]
// =============================================================================

func TestNB005_VPCEDenyExplicit_Blocks(t *testing.T) {
	// SCENARIO: Bucket denies vpce-bad, and that's our only endpoint
	// EXPECTED: Path is BLOCKED
	conditions := &domain.ResourcePolicyConditions{
		DeniedVPCEs:       []string{"vpce-bad"},
		HasVPCEConditions: true,
	}
	ctx := &domain.NetworkContext{
		SourceVPCID: strPtr("vpc-123"),
		AvailableEndpoints: []domain.VPCEndpointInfo{
			{EndpointID: "vpce-bad", VpcID: "vpc-123", ServiceName: "com.amazonaws.us-east-1.s3"},
		},
		TargetConditions: conditions,
	}

	result := CheckNetworkBoundaries(ctx, "arn:aws:s3:::test-bucket")

	if !result.AnyBlocks {
		t.Errorf("Expected path to be BLOCKED, but it was not")
	}
	assertContainsInvariant(t, result.BlockingChecks, domain.InvariantVPCEDenyExplicit)
}

func TestNB005_VPCEDenyExplicit_Allows(t *testing.T) {
	// SCENARIO: Bucket denies vpce-bad, but we have vpce-good
	// EXPECTED: Path is ALLOWED
	conditions := &domain.ResourcePolicyConditions{
		DeniedVPCEs:       []string{"vpce-bad"},
		HasVPCEConditions: true,
	}
	ctx := &domain.NetworkContext{
		SourceVPCID: strPtr("vpc-123"),
		AvailableEndpoints: []domain.VPCEndpointInfo{
			{EndpointID: "vpce-good", VpcID: "vpc-123", ServiceName: "com.amazonaws.us-east-1.s3"},
		},
		TargetConditions: conditions,
	}

	result := CheckNetworkBoundaries(ctx, "arn:aws:s3:::test-bucket")

	if result.AnyBlocks {
		t.Errorf("Expected path to be ALLOWED, but it was blocked: %v", result.BlockingChecks)
	}
}

// =============================================================================
// Combined scenarios
// =============================================================================

func TestCombined_MultipleConditions_AllMustPass(t *testing.T) {
	// SCENARIO: Bucket has both VPC whitelist AND VPCE whitelist
	//           We must satisfy BOTH to access
	// EXPECTED: Path is BLOCKED because we're in wrong VPC
	conditions := &domain.ResourcePolicyConditions{
		AllowedVPCs:       []string{"vpc-trusted"},
		AllowedVPCEs:      []string{"vpce-required"},
		HasVPCConditions:  true,
		HasVPCEConditions: true,
	}
	ctx := &domain.NetworkContext{
		SourceVPCID: strPtr("vpc-untrusted"), // Wrong VPC
		AvailableEndpoints: []domain.VPCEndpointInfo{
			{EndpointID: "vpce-required", VpcID: "vpc-untrusted", ServiceName: "com.amazonaws.us-east-1.s3"},
		},
		TargetConditions: conditions,
	}

	result := CheckNetworkBoundaries(ctx, "arn:aws:s3:::test-bucket")

	if !result.AnyBlocks {
		t.Errorf("Expected path to be BLOCKED (wrong VPC), but it was not")
	}
}

func TestCombined_NoConditions_Allows(t *testing.T) {
	// SCENARIO: Bucket has no network conditions
	// EXPECTED: Path is ALLOWED (network doesn't block)
	conditions := &domain.ResourcePolicyConditions{
		// Empty - no VPC or VPCE conditions
	}
	ctx := &domain.NetworkContext{
		SourceVPCID:      strPtr("vpc-any"),
		TargetConditions: conditions,
	}

	result := CheckNetworkBoundaries(ctx, "arn:aws:s3:::test-bucket")

	if result.AnyBlocks {
		t.Errorf("Expected path to be ALLOWED (no conditions), but it was blocked: %v", result.BlockingChecks)
	}
}

func TestCombined_NoVPCContext_SkipsChecks(t *testing.T) {
	// SCENARIO: Compute resource has no VPC (e.g., Lambda not in VPC)
	// EXPECTED: VPC conditions are skipped (can't evaluate)
	conditions := &domain.ResourcePolicyConditions{
		AllowedVPCs:      []string{"vpc-trusted"},
		HasVPCConditions: true,
	}
	ctx := &domain.NetworkContext{
		SourceVPCID:      nil, // No VPC context
		TargetConditions: conditions,
	}

	result := CheckNetworkBoundaries(ctx, "arn:aws:s3:::test-bucket")

	// When there's no VPC context, VPC conditions can't block
	// (This might be a finding itself - Lambda accessing without going through VPC)
	if len(result.Checks) > 0 {
		t.Errorf("Expected no checks to run without VPC context, but got: %v", result.Checks)
	}
}

// =============================================================================
// Helper functions
// =============================================================================

func strPtr(s string) *string {
	return &s
}

func assertContainsInvariant(t *testing.T, blockers []domain.NetworkInvariantID, expected domain.NetworkInvariantID) {
	t.Helper()
	for _, b := range blockers {
		if b == expected {
			return
		}
	}
	t.Errorf("Expected blocking invariants %v to contain %s", blockers, expected)
}
