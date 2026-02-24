package network

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"breachmap/internal/domain"
	"breachmap/internal/logging"
)

/*
Network Boundary Orchestrator

PURPOSE:
  Coordinates all network boundary checks for a breach path.
  This is the main entry point for network boundary verification.

FLOW:
  1. Build NetworkContext from compute resource and target
  2. Fetch resource policy and extract conditions
  3. Fetch VPC endpoints in source VPC (if needed)
  4. Run all boundary checkers
  5. Check VPC endpoint policy (if applicable)
  6. Return aggregated results

INVARIANTS CHECKED:
  NB-001: VPC_DENY_EXPLICIT      - Resource policy denies source VPC
  NB-002: VPC_ALLOW_WHITELIST    - Resource policy whitelist doesn't include source VPC
  NB-003: VPC_DENY_NOT_EQUALS    - Resource policy inverse whitelist excludes source VPC
  NB-004: VPCE_ALLOW_WHITELIST   - Resource policy requires VPCE we don't have
  NB-005: VPCE_DENY_EXPLICIT     - Resource policy denies our VPCE
  NB-006: VPC_ENDPOINT_POLICY    - VPC endpoint's own policy blocks access
  NB-007: NO_VPC_ENDPOINT_EXISTS - Required VPCE doesn't exist
*/

// NetworkBoundaryOrchestrator coordinates network boundary checks
type NetworkBoundaryOrchestrator struct {
	s3Client  *s3.Client
	ec2Client *ec2.Client
}

// NewOrchestrator creates a new network boundary orchestrator
func NewOrchestrator(s3Client *s3.Client, ec2Client *ec2.Client) *NetworkBoundaryOrchestrator {
	return &NetworkBoundaryOrchestrator{
		s3Client:  s3Client,
		ec2Client: ec2Client,
	}
}

// CheckBoundariesForS3 checks all network boundaries for S3 access
func (o *NetworkBoundaryOrchestrator) CheckBoundariesForS3(
	ctx context.Context,
	computeResource *domain.ComputeResource,
	bucketARN string,
	bucketName string,
) *domain.NetworkBoundaryResult {
	logging.LogDebug("Checking network boundaries", map[string]interface{}{
		"source_vpc":    computeResource.VPCID,
		"source_role":   computeResource.RoleARN,
		"target_bucket": bucketARN,
	})

	// Step 1: Build initial network context
	netCtx := &domain.NetworkContext{
		SourceVPCID:          computeResource.VPCID,
		SourceSubnetIDs:      computeResource.SubnetIDs,
		SourceSecurityGroups: computeResource.SecurityGroupIDs,
		SourceRoleARN:        computeResource.RoleARN,
	}

	// Step 2: Fetch and parse bucket policy conditions
	if o.s3Client != nil {
		policyConditions := o.extractS3PolicyConditions(ctx, bucketName)
		netCtx.TargetConditions = policyConditions
	}

	// Step 3: If there are VPCE conditions, fetch VPC endpoints
	if netCtx.TargetConditions != nil && netCtx.TargetConditions.HasVPCEConditions {
		if o.ec2Client != nil && netCtx.SourceVPCID != nil {
			endpoints := o.fetchVPCEndpoints(ctx, *netCtx.SourceVPCID, "s3")
			netCtx.AvailableEndpoints = endpoints
		}
	}

	// Step 4: Run boundary checks (NB-001 through NB-005, NB-007)
	result := CheckNetworkBoundaries(netCtx, bucketARN)

	// Step 5: Check VPC endpoint policy (NB-006) if we have an endpoint
	if len(netCtx.AvailableEndpoints) > 0 {
		endpoint := FindRelevantEndpoint(netCtx.AvailableEndpoints, "S3")
		if endpoint != nil {
			check := CheckVPCEndpointPolicy(endpoint, computeResource.RoleARN, bucketARN)
			if check != nil {
				result.Checks = append(result.Checks, *check)
				if check.Blocks {
					result.AnyBlocks = true
					result.BlockingChecks = append(result.BlockingChecks, check.InvariantID)
				}
				if check.Outcome == domain.OutcomeUnknown {
					result.AnyUnknown = true
					result.UnknownChecks = append(result.UnknownChecks, check.InvariantID)
				}
			}
		}
	}

	// Update summary if we added endpoint policy check
	if result.AnyBlocks && len(result.BlockingChecks) > 0 {
		result.Summary = buildBlockedSummary(result.BlockingChecks)
	} else if !result.AnyBlocks && result.AnyUnknown {
		result.Summary = fmt.Sprintf("Passed %d network boundary check(s) with %d unknown", len(result.Checks), len(result.UnknownChecks))
	}

	logging.LogDebug("Network boundary check complete", map[string]interface{}{
		"any_blocks":      result.AnyBlocks,
		"checks_run":      len(result.Checks),
		"blocking_checks": result.BlockingChecks,
	})

	return result
}

// extractS3PolicyConditions fetches bucket policy and extracts network conditions
func (o *NetworkBoundaryOrchestrator) extractS3PolicyConditions(ctx context.Context, bucketName string) *domain.ResourcePolicyConditions {
	if o.s3Client == nil {
		return nil
	}

	policyOutput, err := o.s3Client.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		// No policy = no conditions
		logging.LogDebug("No bucket policy or error fetching", map[string]interface{}{
			"bucket": bucketName,
			"error":  err.Error(),
		})
		return nil
	}

	if policyOutput.Policy == nil {
		return nil
	}

	conditions, err := ExtractPolicyConditions(*policyOutput.Policy)
	if err != nil {
		logging.LogWarn("Failed to parse bucket policy", map[string]interface{}{
			"bucket": bucketName,
			"error":  err.Error(),
		})
		return nil
	}

	return conditions
}

// fetchVPCEndpoints fetches VPC endpoints for a specific service in a VPC
func (o *NetworkBoundaryOrchestrator) fetchVPCEndpoints(ctx context.Context, vpcID string, serviceType string) []domain.VPCEndpointInfo {
	if o.ec2Client == nil {
		return nil
	}

	// Build service name filter (partial match)
	// e.g., for S3 in us-east-1: com.amazonaws.us-east-1.s3
	input := &ec2.DescribeVpcEndpointsInput{
		Filters: []ec2types.Filter{
			{
				Name:   aws.String("vpc-id"),
				Values: []string{vpcID},
			},
		},
	}

	output, err := o.ec2Client.DescribeVpcEndpoints(ctx, input)
	if err != nil {
		logging.LogDebug("Failed to describe VPC endpoints", map[string]interface{}{
			"vpc_id": vpcID,
			"error":  err.Error(),
		})
		return nil
	}

	var endpoints []domain.VPCEndpointInfo
	for _, ep := range output.VpcEndpoints {
		// Filter by service type if specified
		if serviceType != "" {
			serviceName := aws.ToString(ep.ServiceName)
			if !containsServiceType(serviceName, serviceType) {
				continue
			}
		}

		info := domain.VPCEndpointInfo{
			EndpointID:   aws.ToString(ep.VpcEndpointId),
			VpcID:        aws.ToString(ep.VpcId),
			ServiceName:  aws.ToString(ep.ServiceName),
			EndpointType: string(ep.VpcEndpointType),
		}

		// Capture policy document if present
		if ep.PolicyDocument != nil {
			info.PolicyDocument = ep.PolicyDocument
		}

		endpoints = append(endpoints, info)
	}

	return endpoints
}

// containsServiceType checks if a VPC endpoint service name matches the expected service type.
// AWS VPC endpoint service names follow the pattern: com.amazonaws.<region>.<service>
func containsServiceType(serviceName, serviceType string) bool {
	lowerName := strings.ToLower(serviceName)
	switch strings.ToLower(serviceType) {
	case "s3":
		return strings.HasSuffix(lowerName, ".s3")
	case "rds":
		return strings.HasSuffix(lowerName, ".rds")
	case "kms":
		return strings.HasSuffix(lowerName, ".kms")
	default:
		return true // No filter
	}
}

// buildBlockedSummary creates a human-readable summary of blocking invariants
func buildBlockedSummary(blockers []domain.NetworkInvariantID) string {
	if len(blockers) == 0 {
		return "No network boundaries block this path"
	}

	descriptions := make([]string, 0, len(blockers))
	for _, id := range blockers {
		descriptions = append(descriptions, describeInvariant(id))
	}

	return "BLOCKED: " + strings.Join(descriptions, "; ")
}

// describeInvariant returns a short description of an invariant
func describeInvariant(id domain.NetworkInvariantID) string {
	switch id {
	case domain.InvariantVPCDenyExplicit:
		return "VPC explicitly denied"
	case domain.InvariantVPCAllowWhitelist:
		return "VPC not in whitelist"
	case domain.InvariantVPCDenyNotEquals:
		return "VPC not in exception list"
	case domain.InvariantVPCEAllowWhitelist:
		return "VPC endpoint not in whitelist"
	case domain.InvariantVPCEDenyExplicit:
		return "VPC endpoint explicitly denied"
	case domain.InvariantVPCEndpointPolicyDeny:
		return "VPC endpoint policy denies access"
	case domain.InvariantNoVPCEndpointExists:
		return "Required VPC endpoint missing"
	default:
		return string(id)
	}
}

// QuickCheckVPCBlocked is a lightweight check that only looks at VPC deny conditions
// Use this for fast filtering before doing full authorization checks
func QuickCheckVPCBlocked(policyJSON string, sourceVPCID string) (bool, string) {
	if sourceVPCID == "" || policyJSON == "" {
		return false, "No VPC context or policy to check"
	}

	var policyDoc map[string]interface{}
	if err := json.Unmarshal([]byte(policyJSON), &policyDoc); err != nil {
		return false, "Could not parse policy"
	}

	conditions := ExtractConditionsFromPolicyDoc(policyDoc)

	// Check explicit deny
	for _, denied := range conditions.DeniedVPCs {
		if denied == sourceVPCID {
			return true, "VPC explicitly denied by policy"
		}
	}

	// Check inverse whitelist (Deny + StringNotEquals)
	if len(conditions.DenyIfNotInVPCs) > 0 {
		found := false
		for _, allowed := range conditions.DenyIfNotInVPCs {
			if allowed == sourceVPCID {
				found = true
				break
			}
		}
		if !found {
			return true, "VPC not in exception list (Deny + StringNotEquals)"
		}
	}

	// Check whitelist
	if len(conditions.AllowedVPCs) > 0 {
		found := false
		for _, allowed := range conditions.AllowedVPCs {
			if allowed == sourceVPCID {
				found = true
				break
			}
		}
		if !found {
			return true, "VPC not in allowed list"
		}
	}

	return false, "VPC conditions do not block"
}
