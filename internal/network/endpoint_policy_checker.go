package network

import (
	"encoding/json"
	"fmt"
	"strings"

	"breachmap/internal/domain"
)

/*
VPC Endpoint Policy Checker - Evaluates NB-006

PURPOSE:
  VPC endpoints can have their own resource policies that restrict which
  principals can use them and which resources they can access.

  Even if IAM allows access AND the bucket policy allows access,
  the VPC endpoint policy can still BLOCK the request.

INVARIANT NB-006: VPC_ENDPOINT_POLICY_DENY
  WHAT: VPC endpoint's own policy denies the principal or resource
  BLOCKS WHEN:
    - Endpoint policy explicitly denies the role ARN, OR
    - Endpoint policy has Allow but principal is not in it, OR
    - Endpoint policy has resource restrictions that don't match target

ENDPOINT POLICY PATTERNS:

1. Default policy (or no policy) = allow all through endpoint
   {
     "Statement": [{
       "Effect": "Allow",
       "Principal": "*",
       "Action": "*",
       "Resource": "*"
     }]
   }

2. Principal restriction:
   {
     "Statement": [{
       "Effect": "Allow",
       "Principal": {"AWS": ["arn:aws:iam::123456789012:role/AllowedRole"]},
       "Action": "s3:*",
       "Resource": "*"
     }]
   }

3. Resource restriction:
   {
     "Statement": [{
       "Effect": "Allow",
       "Principal": "*",
       "Action": "s3:*",
       "Resource": ["arn:aws:s3:::allowed-bucket/*"]
     }]
   }
*/

// CheckVPCEndpointPolicy evaluates if a VPC endpoint's policy allows the request
// Returns nil if there's no endpoint or no policy to check
func CheckVPCEndpointPolicy(
	endpoint *domain.VPCEndpointInfo,
	principalARN string,
	resourceARN string,
) *domain.NetworkBoundaryCheck {
	if endpoint == nil {
		return nil
	}

	check := &domain.NetworkBoundaryCheck{
		InvariantID:    domain.InvariantVPCEndpointPolicyDeny,
		Description:    "VPC endpoint policy restriction",
		Category:       domain.CategoryPolicy,
		TargetResource: resourceARN,
	}

	// No policy or empty policy = default allow all
	if endpoint.PolicyDocument == nil || *endpoint.PolicyDocument == "" {
		check.Blocks = false
		check.Outcome = domain.OutcomeAllowed
		check.Reasoning = fmt.Sprintf("VPC endpoint %s has no custom policy (default allows all)", endpoint.EndpointID)
		return check
	}

	// Parse the endpoint policy
	var policyDoc map[string]interface{}
	if err := json.Unmarshal([]byte(*endpoint.PolicyDocument), &policyDoc); err != nil {
		// Can't parse = unknown outcome (do not fail open)
		check.Blocks = false
		check.Outcome = domain.OutcomeUnknown
		check.Reasoning = fmt.Sprintf("Could not parse VPC endpoint %s policy: %v", endpoint.EndpointID, err)
		return check
	}

	// Evaluate policy
	allowed, reason := evaluateEndpointPolicy(policyDoc, principalARN, resourceARN)

	check.Blocks = !allowed
	if allowed {
		check.Outcome = domain.OutcomeAllowed
	} else {
		check.Outcome = domain.OutcomeBlocked
	}
	check.Reasoning = fmt.Sprintf("VPC endpoint %s: %s", endpoint.EndpointID, reason)
	return check
}

// evaluateEndpointPolicy checks if policy allows principal to access resource
func evaluateEndpointPolicy(policyDoc map[string]interface{}, principalARN, resourceARN string) (bool, string) {
	statements, ok := policyDoc["Statement"].([]interface{})
	if !ok || len(statements) == 0 {
		return true, "No statements in policy (allows all)"
	}

	// Track if we found any Allow that matches
	hasMatchingAllow := false
	hasExplicitDeny := false

	for _, stmtInterface := range statements {
		stmt, ok := stmtInterface.(map[string]interface{})
		if !ok {
			continue
		}

		effect, _ := stmt["Effect"].(string)
		principalMatches := matchesPrincipal(stmt, principalARN)
		resourceMatches := matchesResource(stmt, resourceARN)

		if effect == "Deny" && principalMatches && resourceMatches {
			hasExplicitDeny = true
			return false, "Explicit Deny statement matches principal and resource"
		}

		if effect == "Allow" && principalMatches && resourceMatches {
			hasMatchingAllow = true
		}
	}

	if hasExplicitDeny {
		return false, "Explicit Deny blocks access"
	}

	if hasMatchingAllow {
		return true, "Allow statement matches principal and resource"
	}

	// No matching Allow found = implicit deny
	return false, "No Allow statement matches principal/resource (implicit deny)"
}

// matchesPrincipal checks if the statement's Principal matches the given ARN
func matchesPrincipal(stmt map[string]interface{}, principalARN string) bool {
	principal := stmt["Principal"]
	if principal == nil {
		return false
	}

	// Handle Principal: "*"
	if p, ok := principal.(string); ok {
		return p == "*"
	}

	// Handle Principal: {"AWS": ...}
	if pMap, ok := principal.(map[string]interface{}); ok {
		awsPrincipal := pMap["AWS"]
		if awsPrincipal == nil {
			return false
		}

		// AWS: "*"
		if p, ok := awsPrincipal.(string); ok {
			if p == "*" {
				return true
			}
			return matchesARN(p, principalARN)
		}

		// AWS: ["arn:...", "arn:..."]
		if pList, ok := awsPrincipal.([]interface{}); ok {
			for _, p := range pList {
				if pStr, ok := p.(string); ok {
					if pStr == "*" || matchesARN(pStr, principalARN) {
						return true
					}
				}
			}
		}
	}

	return false
}

// matchesResource checks if the statement's Resource matches the given ARN
func matchesResource(stmt map[string]interface{}, resourceARN string) bool {
	resource := stmt["Resource"]
	if resource == nil {
		return false
	}

	// Handle Resource: "*"
	if r, ok := resource.(string); ok {
		return r == "*" || matchesARN(r, resourceARN)
	}

	// Handle Resource: ["arn:...", "arn:..."]
	if rList, ok := resource.([]interface{}); ok {
		for _, r := range rList {
			if rStr, ok := r.(string); ok {
				if rStr == "*" || matchesARN(rStr, resourceARN) {
					return true
				}
			}
		}
	}

	return false
}

// matchesARN checks if a pattern ARN matches an actual ARN
// Supports wildcards: * matches anything, ? matches single char
func matchesARN(pattern, arn string) bool {
	// Exact match
	if pattern == arn {
		return true
	}

	// Simple wildcard matching
	if pattern == "*" {
		return true
	}

	// Handle trailing wildcard (common pattern: arn:aws:s3:::bucket/*)
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(arn, prefix)
	}

	// Handle account-level wildcards (arn:aws:iam::123456789012:*)
	if strings.Contains(pattern, "*") {
		// Convert to simple regex-like matching
		parts := strings.Split(pattern, "*")
		remaining := arn
		for i, part := range parts {
			if part == "" {
				continue
			}
			idx := strings.Index(remaining, part)
			if idx == -1 {
				return false
			}
			if i == 0 && idx != 0 {
				// First part must be at the beginning
				return false
			}
			remaining = remaining[idx+len(part):]
		}
		return true
	}

	return false
}

// FindRelevantEndpoint finds the VPC endpoint for a given service in the available endpoints
func FindRelevantEndpoint(endpoints []domain.VPCEndpointInfo, targetType string) *domain.VPCEndpointInfo {
	serviceSuffix := getServiceSuffix(targetType)
	if serviceSuffix == "" {
		return nil
	}

	for i := range endpoints {
		if strings.HasSuffix(endpoints[i].ServiceName, serviceSuffix) {
			return &endpoints[i]
		}
	}
	return nil
}

// getServiceSuffix returns the AWS service name suffix for a target type
func getServiceSuffix(targetType string) string {
	switch strings.ToUpper(targetType) {
	case "S3":
		return ".s3"
	case "RDS":
		return ".rds"
	case "KMS":
		return ".kms"
	case "SECRETSMANAGER":
		return ".secretsmanager"
	case "SSM":
		return ".ssm"
	default:
		return ""
	}
}
