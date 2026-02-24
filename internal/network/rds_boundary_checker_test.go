package network

import (
	"testing"

	"breachmap/internal/domain"
)

/*
RDS Network Boundary Invariant Tests

These tests document and verify the behavior of each RDS network boundary invariant.
*/

// =============================================================================
// NR-003: PRIVATE_RDS_EXTERNAL_COMPUTE
// Private RDS (PubliclyAccessible=false) requires compute in same VPC
// =============================================================================

func TestNR003_PrivateRDS_ComputeInSameVPC_Allows(t *testing.T) {
	// SCENARIO: Private RDS, compute in same VPC
	// EXPECTED: ALLOWED
	rdsCtx := &RDSNetworkContext{
		RDSVPCID:              "vpc-123",
		RDSPubliclyAccessible: false,
		ComputeVPCID:          strPtr("vpc-123"),
	}

	result := CheckRDSNetworkBoundaries(nil, nil, rdsCtx)

	if result.AnyBlocks {
		t.Errorf("Expected path to be ALLOWED (same VPC), but it was blocked: %v", result.BlockingChecks)
	}
}

func TestNR003_PrivateRDS_ComputeInDifferentVPC_Blocks(t *testing.T) {
	// SCENARIO: Private RDS in vpc-rds, compute in vpc-compute
	// EXPECTED: BLOCKED
	rdsCtx := &RDSNetworkContext{
		RDSVPCID:              "vpc-rds",
		RDSPubliclyAccessible: false,
		ComputeVPCID:          strPtr("vpc-compute"),
	}

	result := CheckRDSNetworkBoundaries(nil, nil, rdsCtx)

	if !result.AnyBlocks {
		t.Errorf("Expected path to be BLOCKED (different VPCs), but it was allowed")
	}
	assertContainsInvariant(t, result.BlockingChecks, domain.InvariantRDSPrivateNoVPCAccess)
}

func TestNR003_PrivateRDS_ComputeNoVPC_Blocks(t *testing.T) {
	// SCENARIO: Private RDS, compute has no VPC (Lambda not in VPC)
	// EXPECTED: BLOCKED
	rdsCtx := &RDSNetworkContext{
		RDSVPCID:              "vpc-rds",
		RDSPubliclyAccessible: false,
		ComputeVPCID:          nil, // No VPC
	}

	result := CheckRDSNetworkBoundaries(nil, nil, rdsCtx)

	if !result.AnyBlocks {
		t.Errorf("Expected path to be BLOCKED (no VPC context), but it was allowed")
	}
	assertContainsInvariant(t, result.BlockingChecks, domain.InvariantRDSPrivateNoVPCAccess)
}

func TestNR003_PublicRDS_ComputeOutsideVPC_Allows(t *testing.T) {
	// SCENARIO: Public RDS, compute outside VPC
	// EXPECTED: ALLOWED (RDS is publicly accessible)
	rdsCtx := &RDSNetworkContext{
		RDSVPCID:              "vpc-rds",
		RDSPubliclyAccessible: true,
		ComputeVPCID:          strPtr("vpc-different"),
	}

	result := CheckRDSNetworkBoundaries(nil, nil, rdsCtx)

	// Should not be blocked by NR-003 (public RDS)
	for _, check := range result.Checks {
		if check.InvariantID == domain.InvariantRDSPrivateNoVPCAccess && check.Blocks {
			t.Errorf("NR-003 should not block public RDS")
		}
	}
}

// =============================================================================
// NR-002: DIFFERENT_VPC_NO_CONNECTIVITY
// =============================================================================

func TestNR002_SameVPC_Allows(t *testing.T) {
	// SCENARIO: Compute and RDS in same VPC
	// EXPECTED: ALLOWED
	rdsCtx := &RDSNetworkContext{
		RDSVPCID:              "vpc-shared",
		RDSPubliclyAccessible: false,
		ComputeVPCID:          strPtr("vpc-shared"),
	}

	result := CheckRDSNetworkBoundaries(nil, nil, rdsCtx)

	// Should not be blocked by NR-002
	for _, check := range result.Checks {
		if check.InvariantID == domain.InvariantRDSDifferentVPCNoRoute && check.Blocks {
			t.Errorf("NR-002 should not block same VPC")
		}
	}
}

// =============================================================================
// BuildRDSNetworkContext tests
// =============================================================================

func TestBuildRDSNetworkContext_FullInfo(t *testing.T) {
	port := int32(5432)
	engine := "postgres"
	vpcID := "vpc-123"
	publiclyAccessible := false

	rds := &domain.RDSJewel{
		Name:               "my-db",
		VPCID:              &vpcID,
		SubnetIDs:          []string{"subnet-1", "subnet-2"},
		SecurityGroupIDs:   []string{"sg-rds-1"},
		Port:               &port,
		PubliclyAccessible: &publiclyAccessible,
		Engine:             &engine,
	}

	computeVPCID := "vpc-123"
	compute := &domain.ComputeResource{
		ResourceID:       "i-1234567890abcdef0",
		VPCID:            &computeVPCID,
		SecurityGroupIDs: []string{"sg-compute-1"},
	}

	ctx := BuildRDSNetworkContext(rds, compute)

	if ctx == nil {
		t.Fatal("Expected non-nil context")
	}
	if ctx.RDSVPCID != "vpc-123" {
		t.Errorf("Expected RDS VPC vpc-123, got %s", ctx.RDSVPCID)
	}
	if ctx.RDSPort != 5432 {
		t.Errorf("Expected port 5432, got %d", ctx.RDSPort)
	}
	if ctx.RDSPubliclyAccessible {
		t.Error("Expected PubliclyAccessible=false")
	}
	if ctx.ComputeVPCID == nil || *ctx.ComputeVPCID != "vpc-123" {
		t.Error("Expected compute VPC vpc-123")
	}
}

func TestBuildRDSNetworkContext_DefaultPorts(t *testing.T) {
	testCases := []struct {
		engine       string
		expectedPort int32
	}{
		{"mysql", 3306},
		{"postgres", 5432},
		{"aurora-postgresql", 5432},
		{"oracle-ee", 1521},
		{"sqlserver-se", 1433},
	}

	for _, tc := range testCases {
		t.Run(tc.engine, func(t *testing.T) {
			rds := &domain.RDSJewel{
				Engine: &tc.engine,
				// No port specified - should use default
			}

			ctx := BuildRDSNetworkContext(rds, nil)

			if ctx.RDSPort != tc.expectedPort {
				t.Errorf("Expected port %d for engine %s, got %d", tc.expectedPort, tc.engine, ctx.RDSPort)
			}
		})
	}
}

// =============================================================================
// Combined scenario tests
// =============================================================================

func TestRDS_EC2InSameVPC_WithSecurityGroup_Requires_SG_Check(t *testing.T) {
	// SCENARIO: EC2 and RDS in same VPC
	// Without EC2 client, we can't verify SG rules, so we allow
	rdsCtx := &RDSNetworkContext{
		RDSVPCID:              "vpc-123",
		RDSSecurityGroupIDs:   []string{"sg-rds"},
		RDSPort:               3306,
		RDSPubliclyAccessible: false,
		ComputeVPCID:          strPtr("vpc-123"),
		ComputeSecurityGroups: []string{"sg-compute"},
	}

	// Without EC2 client, SG check is skipped
	result := CheckRDSNetworkBoundaries(nil, nil, rdsCtx)

	// Should pass basic checks (same VPC)
	if result.AnyBlocks {
		t.Errorf("Expected basic checks to pass, but got: %v", result.BlockingChecks)
	}
}

func TestRDS_LambdaNotInVPC_ToPrivateRDS_Blocks(t *testing.T) {
	// SCENARIO: Lambda (not in VPC) trying to access private RDS
	// EXPECTED: BLOCKED - Lambda can't reach private RDS without VPC config
	rdsCtx := &RDSNetworkContext{
		RDSVPCID:              "vpc-rds",
		RDSPubliclyAccessible: false,
		ComputeVPCID:          nil, // Lambda not in VPC
	}

	result := CheckRDSNetworkBoundaries(nil, nil, rdsCtx)

	if !result.AnyBlocks {
		t.Error("Expected Lambda (no VPC) to be blocked from private RDS")
	}
}

func TestRDS_LambdaNotInVPC_ToPublicRDS_Allows(t *testing.T) {
	// SCENARIO: Lambda (not in VPC) accessing public RDS
	// EXPECTED: ALLOWED - Public RDS is reachable from internet
	rdsCtx := &RDSNetworkContext{
		RDSVPCID:              "vpc-rds",
		RDSPubliclyAccessible: true,
		ComputeVPCID:          nil, // Lambda not in VPC
	}

	result := CheckRDSNetworkBoundaries(nil, nil, rdsCtx)

	// NR-003 should not block (RDS is public)
	for _, id := range result.BlockingChecks {
		if id == domain.InvariantRDSPrivateNoVPCAccess {
			t.Error("NR-003 should not block when RDS is publicly accessible")
		}
	}
}
