package domain

/*
=============================================================================
NETWORK BOUNDARY INVARIANTS CATALOG
=============================================================================

These invariants represent network-level controls that can BLOCK a breach path
even when IAM permissions would otherwise allow access.

INVARIANT STRUCTURE:
  - Each invariant has a unique ID (NB-XXX)
  - Each invariant checks ONE specific condition
  - If the condition is TRUE, the breach path is BLOCKED

=============================================================================
INVARIANT LIST
=============================================================================

NB-001: VPC_DENY_EXPLICIT
  WHAT: Resource policy has Deny statement with aws:SourceVpc matching source VPC
  BLOCKS WHEN: Compute workload's VPC is in the deny list
  EXAMPLE: Bucket policy denies vpc-123, EC2 is in vpc-123 → BLOCKED

NB-002: VPC_ALLOW_WHITELIST
  WHAT: Resource policy has Allow with aws:SourceVpc condition (whitelist pattern)
  BLOCKS WHEN: Compute workload's VPC is NOT in the allow list
  EXAMPLE: Bucket policy allows only vpc-456, EC2 is in vpc-123 → BLOCKED

NB-003: VPC_DENY_NOT_EQUALS
  WHAT: Resource policy has Deny with StringNotEquals aws:SourceVpc
  BLOCKS WHEN: Compute workload's VPC is NOT in the "not equals" list (i.e., gets denied)
  EXAMPLE: Deny if NOT vpc-456, EC2 is in vpc-123 → BLOCKED

NB-004: VPCE_ALLOW_WHITELIST
  WHAT: Resource policy requires access via specific VPC endpoints (aws:SourceVpce)
  BLOCKS WHEN: Traffic would not traverse an allowed VPC endpoint
  EXAMPLE: Bucket requires vpce-abc, but compute VPC has no endpoint or different one → BLOCKED

NB-005: VPCE_DENY_EXPLICIT
  WHAT: Resource policy explicitly denies specific VPC endpoints
  BLOCKS WHEN: The only available VPC endpoint is in the deny list
  EXAMPLE: Bucket denies vpce-abc, compute VPC only has vpce-abc → BLOCKED

NB-006: VPC_ENDPOINT_POLICY_DENY
  WHAT: VPC endpoint's own policy denies the principal or resource
  BLOCKS WHEN: Endpoint policy blocks the role ARN or target resource ARN
  EXAMPLE: S3 endpoint policy only allows role-X, but compute has role-Y → BLOCKED

NB-007: NO_VPC_ENDPOINT_EXISTS
  WHAT: Resource requires VPCE access but no endpoint exists in source VPC
  BLOCKS WHEN: Policy requires aws:SourceVpce AND compute VPC has no endpoint for that service
  EXAMPLE: Bucket requires VPCE, Lambda VPC has no S3 endpoint → BLOCKED

=============================================================================
IMPLEMENTATION NOTES
=============================================================================

1. Invariants are checked AFTER IAM authorization succeeds
   - No point checking network if IAM already denies

2. Invariants are INDEPENDENT
   - Each can block on its own
   - A path is blocked if ANY invariant blocks

3. We need network context from ComputeResource:
   - VPCID (required for VPC conditions)
   - SubnetIDs (for route checking, future)
   - SecurityGroupIDs (for egress checking, future)

4. We need to pre-fetch:
   - Resource policies (bucket policy, KMS key policy)
   - VPC endpoints in compute's VPC
*/

// NetworkInvariantID uniquely identifies a network boundary invariant
type NetworkInvariantID string

const (
	// S3 Network Invariants (NB = Network Boundary)
	InvariantVPCDenyExplicit       NetworkInvariantID = "NB-001"
	InvariantVPCAllowWhitelist     NetworkInvariantID = "NB-002"
	InvariantVPCDenyNotEquals      NetworkInvariantID = "NB-003"
	InvariantVPCEAllowWhitelist    NetworkInvariantID = "NB-004"
	InvariantVPCEDenyExplicit      NetworkInvariantID = "NB-005"
	InvariantVPCEndpointPolicyDeny NetworkInvariantID = "NB-006"
	InvariantNoVPCEndpointExists   NetworkInvariantID = "NB-007"

	// RDS Network Invariants (NR = Network RDS)
	// RDS uses Layer 4 (TCP) security groups, not Layer 7 policies
	InvariantRDSSecurityGroupBlocked   NetworkInvariantID = "NR-001" // SG doesn't allow compute → RDS on DB port
	InvariantRDSDifferentVPCNoRoute    NetworkInvariantID = "NR-002" // Different VPCs; connectivity not verified
	InvariantRDSPrivateNoVPCAccess     NetworkInvariantID = "NR-003" // Private RDS, compute outside VPC
)

// NetworkCheckOutcome represents the evaluation outcome of a network invariant
type NetworkCheckOutcome string

const (
	OutcomeAllowed NetworkCheckOutcome = "allowed"
	OutcomeBlocked NetworkCheckOutcome = "blocked"
	OutcomeUnknown NetworkCheckOutcome = "unknown"
)

// NetworkCheckCategory helps distinguish policy vs topology checks
type NetworkCheckCategory string

const (
	CategoryPolicy   NetworkCheckCategory = "policy"
	CategoryTopology NetworkCheckCategory = "topology"
)

// NetworkBoundaryCheck represents the result of checking a single invariant
type NetworkBoundaryCheck struct {
	InvariantID NetworkInvariantID `json:"invariant_id"`
	Description string             `json:"description"`
	Category    NetworkCheckCategory `json:"category"`

	// What we checked
	SourceVPCID    *string  `json:"source_vpc_id,omitempty"`
	TargetResource string   `json:"target_resource,omitempty"`
	ConditionKey   string   `json:"condition_key,omitempty"` // e.g., "aws:SourceVpc"
	ConditionVals  []string `json:"condition_values,omitempty"`

	// Result
	Blocks    bool               `json:"blocks"`
	Outcome   NetworkCheckOutcome `json:"outcome"`
	Reasoning string             `json:"reasoning"`
}

// NetworkBoundaryResult aggregates all boundary checks for a breach path
type NetworkBoundaryResult struct {
	Checks         []NetworkBoundaryCheck `json:"checks"`
	AnyBlocks      bool                   `json:"any_blocks"`
	BlockingChecks []NetworkInvariantID   `json:"blocking_checks,omitempty"`
	AnyUnknown     bool                   `json:"any_unknown"`
	UnknownChecks  []NetworkInvariantID   `json:"unknown_checks,omitempty"`
	Summary        string                 `json:"summary,omitempty"`
}

// ResourcePolicyConditions holds extracted network conditions from a resource policy
type ResourcePolicyConditions struct {
	// VPC conditions
	AllowedVPCs        []string `json:"allowed_vpcs,omitempty"`         // From Allow + StringEquals aws:SourceVpc
	DeniedVPCs         []string `json:"denied_vpcs,omitempty"`          // From Deny + StringEquals aws:SourceVpc
	DenyIfNotInVPCs    []string `json:"deny_if_not_in_vpcs,omitempty"`  // From Deny + StringNotEquals aws:SourceVpc

	// VPC Endpoint conditions
	AllowedVPCEs       []string `json:"allowed_vpces,omitempty"`        // From Allow + StringEquals aws:SourceVpce
	DeniedVPCEs        []string `json:"denied_vpces,omitempty"`         // From Deny + StringEquals aws:SourceVpce
	DenyIfNotInVPCEs   []string `json:"deny_if_not_in_vpces,omitempty"` // From Deny + StringNotEquals aws:SourceVpce

	// Whether conditions were found at all
	HasVPCConditions   bool `json:"has_vpc_conditions"`
	HasVPCEConditions  bool `json:"has_vpce_conditions"`
}

// VPCEndpointInfo contains VPC endpoint details for boundary checking
type VPCEndpointInfo struct {
	EndpointID    string  `json:"endpoint_id"`
	VpcID         string  `json:"vpc_id"`
	ServiceName   string  `json:"service_name"`   // e.g., "com.amazonaws.us-east-1.s3"
	EndpointType  string  `json:"endpoint_type"`  // "Gateway" or "Interface"
	PolicyDocument *string `json:"policy_document,omitempty"`
}

// NetworkContext holds all network-related data needed for boundary checking
type NetworkContext struct {
	// Source compute resource context
	SourceVPCID        *string   `json:"source_vpc_id,omitempty"`
	SourceSubnetIDs    []string  `json:"source_subnet_ids,omitempty"`
	SourceSecurityGroups []string `json:"source_security_groups,omitempty"`
	SourceRoleARN      string    `json:"source_role_arn"`

	// Available VPC endpoints in source VPC
	AvailableEndpoints []VPCEndpointInfo `json:"available_endpoints,omitempty"`

	// Pre-extracted conditions from target resource policy
	TargetConditions *ResourcePolicyConditions `json:"target_conditions,omitempty"`
}
