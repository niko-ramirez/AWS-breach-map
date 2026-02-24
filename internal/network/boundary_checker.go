package network

import (
	"fmt"
	"strings"

	"breachmap/internal/domain"
)

/*
Boundary Checker - Evaluates network invariants to determine if a breach path is blocked

PURPOSE:
  Given a source compute resource and target resource's policy conditions,
  determine if any network boundary BLOCKS the breach path.

INVARIANTS CHECKED:

  NB-001: VPC_DENY_EXPLICIT
    Resource policy explicitly denies the source VPC
    CHECK: Is sourceVPC in DeniedVPCs?

  NB-002: VPC_ALLOW_WHITELIST
    Resource policy only allows specific VPCs (whitelist pattern)
    CHECK: Are there AllowedVPCs AND sourceVPC is NOT in them?

  NB-003: VPC_DENY_NOT_EQUALS
    Resource policy denies all VPCs except specific ones
    CHECK: Are there DenyIfNotInVPCs AND sourceVPC is NOT in them?

  NB-004: VPCE_ALLOW_WHITELIST
    Resource policy requires specific VPC endpoints
    CHECK: Are there AllowedVPCEs AND we don't have a matching endpoint?

  NB-005: VPCE_DENY_EXPLICIT
    Resource policy explicitly denies specific VPC endpoints
    CHECK: Is our only available endpoint in DeniedVPCEs?
*/

// CheckNetworkBoundaries evaluates all network invariants for a breach path
func CheckNetworkBoundaries(ctx *domain.NetworkContext, targetARN string) *domain.NetworkBoundaryResult {
	result := &domain.NetworkBoundaryResult{
		Checks:         make([]domain.NetworkBoundaryCheck, 0),
		BlockingChecks: make([]domain.NetworkInvariantID, 0),
		UnknownChecks:  make([]domain.NetworkInvariantID, 0),
	}

	// No conditions extracted = no network boundaries to check
	if ctx.TargetConditions == nil {
		result.Summary = "No network conditions found in resource policy"
		return result
	}

	cond := ctx.TargetConditions

	// Check VPC invariants if we have VPC context
	if ctx.SourceVPCID != nil && *ctx.SourceVPCID != "" {
		// NB-001: Explicit VPC deny
		if check := checkVPCDenyExplicit(*ctx.SourceVPCID, cond.DeniedVPCs); check != nil {
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

		// NB-002: VPC whitelist
		if check := checkVPCAllowWhitelist(*ctx.SourceVPCID, cond.AllowedVPCs); check != nil {
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

		// NB-003: VPC deny-not-equals (inverse whitelist)
		if check := checkVPCDenyNotEquals(*ctx.SourceVPCID, cond.DenyIfNotInVPCs); check != nil {
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

	// Check VPCE invariants
	if cond.HasVPCEConditions {
		// NB-004: VPCE whitelist
		if check := checkVPCEAllowWhitelist(ctx.AvailableEndpoints, cond.AllowedVPCEs, targetARN); check != nil {
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

		// NB-005: VPCE explicit deny
		if check := checkVPCEDenyExplicit(ctx.AvailableEndpoints, cond.DeniedVPCEs); check != nil {
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

		// NB-007: No VPC endpoint exists but required
		if check := checkNoVPCEndpointExists(ctx.AvailableEndpoints, cond.AllowedVPCEs, targetARN); check != nil {
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
			blockers = append(blockers, string(id))
		}
		result.Summary = fmt.Sprintf("BLOCKED by %d invariant(s): %s", len(blockers), strings.Join(blockers, ", "))
	} else if len(result.Checks) > 0 {
		if result.AnyUnknown {
			result.Summary = fmt.Sprintf("Passed %d network boundary check(s) with %d unknown", len(result.Checks), len(result.UnknownChecks))
		} else {
			result.Summary = fmt.Sprintf("Passed %d network boundary check(s)", len(result.Checks))
		}
	} else {
		result.Summary = "No network conditions found in resource policy"
	}

	return result
}

// ========================================================================
// NB-001: VPC_DENY_EXPLICIT
// ========================================================================
// Resource policy has: Deny + StringEquals aws:SourceVpc = [vpc-xxx]
// BLOCKS WHEN: sourceVPC is in the deny list

func checkVPCDenyExplicit(sourceVPC string, deniedVPCs []string) *domain.NetworkBoundaryCheck {
	if len(deniedVPCs) == 0 {
		return nil // No deny condition to check
	}

	check := &domain.NetworkBoundaryCheck{
		InvariantID:   domain.InvariantVPCDenyExplicit,
		Description:   "Resource policy explicitly denies access from specific VPCs",
		Category:      domain.CategoryPolicy,
		SourceVPCID:   &sourceVPC,
		ConditionKey:  "aws:SourceVpc",
		ConditionVals: deniedVPCs,
	}

	for _, denied := range deniedVPCs {
		if denied == sourceVPC {
			check.Blocks = true
			check.Outcome = domain.OutcomeBlocked
			check.Reasoning = fmt.Sprintf("Source VPC %s is explicitly denied by resource policy", sourceVPC)
			return check
		}
	}

	check.Blocks = false
	check.Outcome = domain.OutcomeAllowed
	check.Reasoning = fmt.Sprintf("Source VPC %s is not in deny list %v", sourceVPC, deniedVPCs)
	return check
}

// ========================================================================
// NB-002: VPC_ALLOW_WHITELIST
// ========================================================================
// Resource policy has: Allow + StringEquals aws:SourceVpc = [vpc-xxx]
// BLOCKS WHEN: sourceVPC is NOT in the allow list

func checkVPCAllowWhitelist(sourceVPC string, allowedVPCs []string) *domain.NetworkBoundaryCheck {
	if len(allowedVPCs) == 0 {
		return nil // No whitelist condition to check
	}

	check := &domain.NetworkBoundaryCheck{
		InvariantID:   domain.InvariantVPCAllowWhitelist,
		Description:   "Resource policy only allows access from specific VPCs (whitelist)",
		Category:      domain.CategoryPolicy,
		SourceVPCID:   &sourceVPC,
		ConditionKey:  "aws:SourceVpc",
		ConditionVals: allowedVPCs,
	}

	for _, allowed := range allowedVPCs {
		if allowed == sourceVPC {
			check.Blocks = false
			check.Outcome = domain.OutcomeAllowed
			check.Reasoning = fmt.Sprintf("Source VPC %s is in allowed list", sourceVPC)
			return check
		}
	}

	check.Blocks = true
	check.Outcome = domain.OutcomeBlocked
	check.Reasoning = fmt.Sprintf("Source VPC %s is not in allowed list %v", sourceVPC, allowedVPCs)
	return check
}

// ========================================================================
// NB-003: VPC_DENY_NOT_EQUALS
// ========================================================================
// Resource policy has: Deny + StringNotEquals aws:SourceVpc = [vpc-xxx]
// This is an inverse whitelist - deny everyone EXCEPT these VPCs
// BLOCKS WHEN: sourceVPC is NOT in the exception list

func checkVPCDenyNotEquals(sourceVPC string, denyIfNotInVPCs []string) *domain.NetworkBoundaryCheck {
	if len(denyIfNotInVPCs) == 0 {
		return nil // No condition to check
	}

	check := &domain.NetworkBoundaryCheck{
		InvariantID:   domain.InvariantVPCDenyNotEquals,
		Description:   "Resource policy denies all VPCs except specific ones (Deny + StringNotEquals)",
		Category:      domain.CategoryPolicy,
		SourceVPCID:   &sourceVPC,
		ConditionKey:  "aws:SourceVpc (StringNotEquals)",
		ConditionVals: denyIfNotInVPCs,
	}

	// If sourceVPC IS in the "not equals" list, it's NOT denied
	for _, allowed := range denyIfNotInVPCs {
		if allowed == sourceVPC {
			check.Blocks = false
			check.Outcome = domain.OutcomeAllowed
			check.Reasoning = fmt.Sprintf("Source VPC %s is in the exception list (not denied)", sourceVPC)
			return check
		}
	}

	// sourceVPC is NOT in the exception list, so it IS denied
	check.Blocks = true
	check.Outcome = domain.OutcomeBlocked
	check.Reasoning = fmt.Sprintf("Source VPC %s is not in exception list %v (Deny + StringNotEquals blocks it)", sourceVPC, denyIfNotInVPCs)
	return check
}

// ========================================================================
// NB-004: VPCE_ALLOW_WHITELIST
// ========================================================================
// Resource policy has: Allow + StringEquals aws:SourceVpce = [vpce-xxx]
// BLOCKS WHEN: We don't have a VPC endpoint in the allowed list

func checkVPCEAllowWhitelist(availableEndpoints []domain.VPCEndpointInfo, allowedVPCEs []string, targetARN string) *domain.NetworkBoundaryCheck {
	if len(allowedVPCEs) == 0 {
		return nil // No VPCE whitelist condition
	}

	check := &domain.NetworkBoundaryCheck{
		InvariantID:   domain.InvariantVPCEAllowWhitelist,
		Description:   "Resource policy requires access via specific VPC endpoints",
		Category:      domain.CategoryPolicy,
		ConditionKey:  "aws:SourceVpce",
		ConditionVals: allowedVPCEs,
		TargetResource: targetARN,
	}

	// Check if any of our available endpoints is in the allowed list
	for _, ep := range availableEndpoints {
		for _, allowedVPCE := range allowedVPCEs {
			if ep.EndpointID == allowedVPCE {
				check.Blocks = false
				check.Outcome = domain.OutcomeAllowed
				check.Reasoning = fmt.Sprintf("VPC endpoint %s is in allowed list", ep.EndpointID)
				return check
			}
		}
	}

	// None of our endpoints are in the allowed list
	if len(availableEndpoints) == 0 {
		check.Blocks = true
		check.Outcome = domain.OutcomeBlocked
		check.Reasoning = fmt.Sprintf("Resource requires VPC endpoints %v but no endpoints available in source VPC", allowedVPCEs)
	} else {
		ourEndpoints := make([]string, 0, len(availableEndpoints))
		for _, ep := range availableEndpoints {
			ourEndpoints = append(ourEndpoints, ep.EndpointID)
		}
		check.Blocks = true
		check.Outcome = domain.OutcomeBlocked
		check.Reasoning = fmt.Sprintf("Resource requires VPC endpoints %v but our endpoints %v are not in the list", allowedVPCEs, ourEndpoints)
	}
	return check
}

// ========================================================================
// NB-005: VPCE_DENY_EXPLICIT
// ========================================================================
// Resource policy has: Deny + StringEquals aws:SourceVpce = [vpce-xxx]
// BLOCKS WHEN: Our only available endpoint is in the deny list

func checkVPCEDenyExplicit(availableEndpoints []domain.VPCEndpointInfo, deniedVPCEs []string) *domain.NetworkBoundaryCheck {
	if len(deniedVPCEs) == 0 || len(availableEndpoints) == 0 {
		return nil // No condition or no endpoints to check
	}

	check := &domain.NetworkBoundaryCheck{
		InvariantID:   domain.InvariantVPCEDenyExplicit,
		Description:   "Resource policy explicitly denies specific VPC endpoints",
		Category:      domain.CategoryPolicy,
		ConditionKey:  "aws:SourceVpce",
		ConditionVals: deniedVPCEs,
	}

	// Check if ALL our available endpoints are denied
	deniedSet := make(map[string]bool)
	for _, d := range deniedVPCEs {
		deniedSet[d] = true
	}

	allDenied := true
	for _, ep := range availableEndpoints {
		if !deniedSet[ep.EndpointID] {
			allDenied = false
			break
		}
	}

	if allDenied {
		check.Blocks = true
		check.Outcome = domain.OutcomeBlocked
		check.Reasoning = fmt.Sprintf("All available VPC endpoints are in deny list %v", deniedVPCEs)
	} else {
		check.Blocks = false
		check.Outcome = domain.OutcomeAllowed
		check.Reasoning = "At least one available VPC endpoint is not denied"
	}
	return check
}

// ========================================================================
// NB-007: NO_VPC_ENDPOINT_EXISTS
// ========================================================================
// Resource policy requires VPCE access (via conditions) but no endpoint exists
// BLOCKS WHEN: Policy has VPCE conditions AND we have no relevant endpoint

func checkNoVPCEndpointExists(availableEndpoints []domain.VPCEndpointInfo, allowedVPCEs []string, targetARN string) *domain.NetworkBoundaryCheck {
	// This is only relevant if there's a VPCE requirement
	if len(allowedVPCEs) == 0 {
		return nil
	}

	// If we already have endpoints, NB-004 handles the whitelist check
	if len(availableEndpoints) > 0 {
		return nil
	}

	check := &domain.NetworkBoundaryCheck{
		InvariantID:    domain.InvariantNoVPCEndpointExists,
		Description:    "Resource requires VPC endpoint access but no endpoint exists",
		Category:       domain.CategoryTopology,
		ConditionKey:   "aws:SourceVpce",
		ConditionVals:  allowedVPCEs,
		TargetResource: targetARN,
		Blocks:         true,
		Outcome:        domain.OutcomeBlocked,
		Reasoning:      fmt.Sprintf("Resource requires access via VPC endpoints %v but no endpoint exists in source VPC", allowedVPCEs),
	}

	return check
}
