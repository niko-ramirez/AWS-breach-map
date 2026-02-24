package network

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"breachmap/internal/domain"
	"breachmap/internal/logging"
)

/*
RDS Network Boundary Checker

PURPOSE:
  RDS network security is fundamentally different from S3:
  - S3: Access via HTTPS API, controlled by bucket policies + VPC endpoint policies
  - RDS: Access via direct TCP connection, controlled by Security Groups

INVARIANTS:

  NR-001: SECURITY_GROUP_INGRESS_BLOCKED
    WHAT: RDS security group doesn't allow inbound traffic from compute resource
    CHECK: Does RDS SG have an ingress rule allowing compute's SG or IP on DB port?
    BLOCKS WHEN: No matching ingress rule found

  NR-002: DIFFERENT_VPC_NO_CONNECTIVITY
    WHAT: Compute and RDS are in different VPCs with no connectivity
    CHECK: Are VPC IDs different AND no peering/transit gateway?
    BLOCKS WHEN: Different VPCs without peering (simplified check: different VPC = blocked)

  NR-003: PRIVATE_RDS_EXTERNAL_COMPUTE
    WHAT: RDS is not publicly accessible and compute is outside the VPC
    CHECK: PubliclyAccessible=false AND compute VPC != RDS VPC
    BLOCKS WHEN: Private RDS with compute in different/no VPC
*/

// RDSNetworkContext holds network context for RDS boundary checking
type RDSNetworkContext struct {
	// RDS target info
	RDSVPCID            string
	RDSSubnetIDs        []string
	RDSSecurityGroupIDs []string
	RDSPort             int32
	RDSPubliclyAccessible bool

	// Compute source info
	ComputeVPCID          *string
	ComputeSecurityGroups []string
	ComputePrivateIP      *string
}

// CheckRDSNetworkBoundaries evaluates network invariants for RDS breach paths
func CheckRDSNetworkBoundaries(
	ctx context.Context,
	ec2Client *ec2.Client,
	rdsCtx *RDSNetworkContext,
) *domain.NetworkBoundaryResult {
	result := &domain.NetworkBoundaryResult{
		Checks:         make([]domain.NetworkBoundaryCheck, 0),
		BlockingChecks: make([]domain.NetworkInvariantID, 0),
		UnknownChecks:  make([]domain.NetworkInvariantID, 0),
	}

	if rdsCtx == nil {
		result.Summary = "No RDS network context provided"
		return result
	}

	// NR-003: Check if private RDS is accessible from compute's VPC
	if check := checkPrivateRDSAccess(rdsCtx); check != nil {
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

	// NR-002: Check VPC connectivity
	if check := checkVPCConnectivity(rdsCtx); check != nil {
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

	// NR-001: Check security group ingress (requires EC2 API call)
	if ec2Client != nil && len(rdsCtx.RDSSecurityGroupIDs) > 0 {
		if check := checkSecurityGroupIngress(ctx, ec2Client, rdsCtx); check != nil {
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

	// Build summary
	if result.AnyBlocks {
		blockers := make([]string, 0, len(result.BlockingChecks))
		for _, id := range result.BlockingChecks {
			blockers = append(blockers, describeRDSInvariant(id))
		}
		result.Summary = fmt.Sprintf("RDS BLOCKED: %s", strings.Join(blockers, "; "))
	} else if len(result.Checks) > 0 {
		if result.AnyUnknown {
			result.Summary = fmt.Sprintf("Passed %d RDS network check(s) with %d unknown", len(result.Checks), len(result.UnknownChecks))
		} else {
			result.Summary = fmt.Sprintf("Passed %d RDS network check(s)", len(result.Checks))
		}
	} else {
		result.Summary = "No RDS network checks applicable"
	}

	return result
}

// ========================================================================
// NR-003: PRIVATE_RDS_EXTERNAL_COMPUTE
// ========================================================================
// BLOCKS WHEN: RDS is private (PubliclyAccessible=false) AND compute is
// in a different VPC (or has no VPC context)

func checkPrivateRDSAccess(rdsCtx *RDSNetworkContext) *domain.NetworkBoundaryCheck {
	check := &domain.NetworkBoundaryCheck{
		InvariantID: domain.InvariantRDSPrivateNoVPCAccess,
		Description: "Private RDS requires compute in same VPC",
		Category:    domain.CategoryTopology,
	}

	// If RDS is publicly accessible, this check doesn't apply
	if rdsCtx.RDSPubliclyAccessible {
		check.Blocks = false
		check.Outcome = domain.OutcomeAllowed
		check.Reasoning = "RDS is publicly accessible, VPC location doesn't matter for connectivity"
		return check
	}

	// RDS is private - compute must be in same VPC
	if rdsCtx.ComputeVPCID == nil || *rdsCtx.ComputeVPCID == "" {
		check.Blocks = true
		check.Outcome = domain.OutcomeBlocked
		check.Reasoning = "RDS is private (PubliclyAccessible=false) but compute has no VPC context (e.g., Lambda not in VPC)"
		return check
	}

	if *rdsCtx.ComputeVPCID != rdsCtx.RDSVPCID {
		check.Blocks = true
		check.Outcome = domain.OutcomeBlocked
		check.Reasoning = fmt.Sprintf("RDS is private in VPC %s, but compute is in VPC %s", 
			rdsCtx.RDSVPCID, *rdsCtx.ComputeVPCID)
		return check
	}

	check.Blocks = false
	check.Outcome = domain.OutcomeAllowed
	check.Reasoning = fmt.Sprintf("Compute and RDS are in same VPC (%s)", rdsCtx.RDSVPCID)
	return check
}

// ========================================================================
// NR-002: DIFFERENT_VPC_NO_CONNECTIVITY  
// ========================================================================
// BLOCKS WHEN: Compute and RDS are in different VPCs
// Note: This is a simplified check. Full check would verify VPC peering/TGW.

func checkVPCConnectivity(rdsCtx *RDSNetworkContext) *domain.NetworkBoundaryCheck {
	// Skip if compute has no VPC (Lambda not in VPC accessing public RDS)
	if rdsCtx.ComputeVPCID == nil || *rdsCtx.ComputeVPCID == "" {
		return nil // NR-003 handles this case
	}

	check := &domain.NetworkBoundaryCheck{
		InvariantID: domain.InvariantRDSDifferentVPCNoRoute,
		Description: "VPC connectivity between compute and RDS",
		Category:    domain.CategoryTopology,
		SourceVPCID: rdsCtx.ComputeVPCID,
	}

	if *rdsCtx.ComputeVPCID == rdsCtx.RDSVPCID {
		check.Blocks = false
		check.Outcome = domain.OutcomeAllowed
		check.Reasoning = fmt.Sprintf("Same VPC (%s)", rdsCtx.RDSVPCID)
		return check
	}

	// Different VPCs - connectivity not verified
	check.Blocks = false
	check.Outcome = domain.OutcomeUnknown
	check.Reasoning = fmt.Sprintf("Different VPCs (compute: %s, RDS: %s) - connectivity not verified (peering/TGW/route tables)",
		*rdsCtx.ComputeVPCID, rdsCtx.RDSVPCID)

	return check
}

// ========================================================================
// NR-001: SECURITY_GROUP_INGRESS_BLOCKED
// ========================================================================
// BLOCKS WHEN: RDS security group doesn't allow ingress from compute's SG or IP

func checkSecurityGroupIngress(
	ctx context.Context,
	ec2Client *ec2.Client,
	rdsCtx *RDSNetworkContext,
) *domain.NetworkBoundaryCheck {
	check := &domain.NetworkBoundaryCheck{
		InvariantID: domain.InvariantRDSSecurityGroupBlocked,
		Description: "Security group allows compute to reach RDS on DB port",
		Category:    domain.CategoryTopology,
	}

	// Fetch RDS security group rules
	sgOutput, err := ec2Client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{
		GroupIds: rdsCtx.RDSSecurityGroupIDs,
	})
	if err != nil {
		logging.LogDebug("Failed to describe RDS security groups", map[string]interface{}{
			"security_groups": rdsCtx.RDSSecurityGroupIDs,
			"error":           err.Error(),
		})
		check.Blocks = false
		check.Outcome = domain.OutcomeUnknown
		check.Reasoning = fmt.Sprintf("Could not verify security groups: %v", err)
		return check
	}

	// Check if any RDS SG allows traffic from compute
	port := rdsCtx.RDSPort
	for _, sg := range sgOutput.SecurityGroups {
		if allowsIngress(sg.IpPermissions, rdsCtx.ComputeSecurityGroups, rdsCtx.ComputePrivateIP, port) {
			check.Blocks = false
			check.Outcome = domain.OutcomeAllowed
			check.Reasoning = fmt.Sprintf("Security group %s allows ingress on port %d from compute", 
				aws.ToString(sg.GroupId), port)
			return check
		}
	}

	// No ingress rule found
	check.Blocks = true
	check.Outcome = domain.OutcomeBlocked
	check.Reasoning = fmt.Sprintf("RDS security groups %v do not allow ingress on port %d from compute SGs %v", 
		rdsCtx.RDSSecurityGroupIDs, port, rdsCtx.ComputeSecurityGroups)
	return check
}

// allowsIngress checks if any IP permission allows traffic from source
func allowsIngress(
	permissions []ec2types.IpPermission,
	sourceSecurityGroups []string,
	sourceIP *string,
	targetPort int32,
) bool {
	sourceSGSet := make(map[string]bool)
	for _, sg := range sourceSecurityGroups {
		sourceSGSet[sg] = true
	}

	for _, perm := range permissions {
		// Check if port matches
		if !portMatches(perm, targetPort) {
			continue
		}

		// Check source security groups
		for _, userIdGroup := range perm.UserIdGroupPairs {
			if userIdGroup.GroupId != nil && sourceSGSet[*userIdGroup.GroupId] {
				return true
			}
		}

		// Check CIDR ranges (simplified - checks for 0.0.0.0/0 or compute IP)
		for _, ipRange := range perm.IpRanges {
			if ipRange.CidrIp != nil {
				cidr := *ipRange.CidrIp
				if cidr == "0.0.0.0/0" {
					return true // Wide open
				}
				// For private IPs, we'd need proper CIDR matching
				// Simplified: assume VPC CIDR allows internal traffic
				if sourceIP != nil && isPrivateIP(*sourceIP) && isVPCCIDR(cidr) {
					return true
				}
			}
		}
	}

	return false
}

// portMatches checks if the permission covers the target port
func portMatches(perm ec2types.IpPermission, targetPort int32) bool {
	// Protocol -1 means all traffic
	if perm.IpProtocol != nil && *perm.IpProtocol == "-1" {
		return true
	}

	// Check TCP (protocol 6 or "tcp")
	if perm.IpProtocol != nil && (*perm.IpProtocol == "tcp" || *perm.IpProtocol == "6") {
		// FromPort/ToPort of 0/0 with -1 protocol means all
		// Otherwise check if target port is in range
		fromPort := int32(0)
		toPort := int32(65535)
		if perm.FromPort != nil {
			fromPort = *perm.FromPort
		}
		if perm.ToPort != nil {
			toPort = *perm.ToPort
		}
		return targetPort >= fromPort && targetPort <= toPort
	}

	return false
}

// isPrivateIP checks if an IP is in private RFC1918 range
func isPrivateIP(ip string) bool {
	// Simplified check for common private ranges
	return strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "172.") || strings.HasPrefix(ip, "192.168.")
}

// isVPCCIDR checks if a CIDR looks like a VPC CIDR (private range)
func isVPCCIDR(cidr string) bool {
	return strings.HasPrefix(cidr, "10.") || strings.HasPrefix(cidr, "172.") || strings.HasPrefix(cidr, "192.168.")
}

// describeRDSInvariant returns a short description of an RDS invariant
func describeRDSInvariant(id domain.NetworkInvariantID) string {
	switch id {
	case domain.InvariantRDSSecurityGroupBlocked:
		return "Security group blocks access"
	case domain.InvariantRDSDifferentVPCNoRoute:
		return "Connectivity between VPCs not verified"
	case domain.InvariantRDSPrivateNoVPCAccess:
		return "Private RDS, compute outside VPC"
	default:
		return string(id)
	}
}

// BuildRDSNetworkContext creates network context from RDS jewel and compute resource
func BuildRDSNetworkContext(rds *domain.RDSJewel, compute *domain.ComputeResource) *RDSNetworkContext {
	if rds == nil {
		return nil
	}

	ctx := &RDSNetworkContext{
		RDSSubnetIDs:        rds.SubnetIDs,
		RDSSecurityGroupIDs: rds.SecurityGroupIDs,
		RDSPubliclyAccessible: rds.PubliclyAccessible != nil && *rds.PubliclyAccessible,
	}

	// Set VPC ID
	if rds.VPCID != nil {
		ctx.RDSVPCID = *rds.VPCID
	}

	// Set port (default to common ports if not specified)
	if rds.Port != nil {
		ctx.RDSPort = *rds.Port
	} else {
		// Default ports based on engine
		ctx.RDSPort = 3306 // MySQL default
		if rds.Engine != nil {
			switch *rds.Engine {
			case "postgres", "aurora-postgresql":
				ctx.RDSPort = 5432
			case "oracle-ee", "oracle-se", "oracle-se1", "oracle-se2":
				ctx.RDSPort = 1521
			case "sqlserver-ee", "sqlserver-se", "sqlserver-ex", "sqlserver-web":
				ctx.RDSPort = 1433
			}
		}
	}

	// Set compute info
	if compute != nil {
		ctx.ComputeVPCID = compute.VPCID
		ctx.ComputeSecurityGroups = compute.SecurityGroupIDs
		ctx.ComputePrivateIP = compute.PrivateIP
	}

	return ctx
}
