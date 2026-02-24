package network

import (
	"encoding/json"
	"strings"

	"breachmap/internal/domain"
)

/*
Policy Parser - Extracts network conditions from IAM/resource policies

PURPOSE:
  Parse bucket policies, KMS key policies, and other resource policies to
  extract network-related conditions (aws:SourceVpc, aws:SourceVpce, etc.)

CONDITION PATTERNS WE EXTRACT:

1. Allow + StringEquals aws:SourceVpc = ["vpc-xxx"]
   → Whitelist: Only these VPCs can access (NB-002)

2. Deny + StringEquals aws:SourceVpc = ["vpc-xxx"]
   → Blacklist: These VPCs are blocked (NB-001)

3. Deny + StringNotEquals aws:SourceVpc = ["vpc-xxx"]
   → Inverse whitelist: Block everyone EXCEPT these VPCs (NB-003)
   → Commonly used pattern: "Deny all except from our VPC"

4. Same patterns for aws:SourceVpce (NB-004, NB-005)
*/

// ExtractPolicyConditions parses a policy JSON and extracts network conditions
func ExtractPolicyConditions(policyJSON string) (*domain.ResourcePolicyConditions, error) {
	if policyJSON == "" {
		return &domain.ResourcePolicyConditions{}, nil
	}

	var policyDoc map[string]interface{}
	if err := json.Unmarshal([]byte(policyJSON), &policyDoc); err != nil {
		return nil, err
	}

	return ExtractConditionsFromPolicyDoc(policyDoc), nil
}

// ExtractConditionsFromPolicyDoc extracts conditions from a parsed policy document
func ExtractConditionsFromPolicyDoc(policyDoc map[string]interface{}) *domain.ResourcePolicyConditions {
	result := &domain.ResourcePolicyConditions{}

	statements, ok := policyDoc["Statement"].([]interface{})
	if !ok {
		return result
	}

	for _, stmtInterface := range statements {
		stmt, ok := stmtInterface.(map[string]interface{})
		if !ok {
			continue
		}

		effect, _ := stmt["Effect"].(string)
		condition, hasCondition := stmt["Condition"].(map[string]interface{})
		if !hasCondition {
			continue
		}

		// Extract from each condition operator
		extractFromCondition(result, effect, condition, "StringEquals")
		extractFromCondition(result, effect, condition, "StringNotEquals")
		extractFromCondition(result, effect, condition, "ForAnyValue:StringEquals")
		extractFromCondition(result, effect, condition, "ForAllValues:StringEquals")
	}

	// Set flags
	result.HasVPCConditions = len(result.AllowedVPCs) > 0 ||
		len(result.DeniedVPCs) > 0 ||
		len(result.DenyIfNotInVPCs) > 0

	result.HasVPCEConditions = len(result.AllowedVPCEs) > 0 ||
		len(result.DeniedVPCEs) > 0 ||
		len(result.DenyIfNotInVPCEs) > 0

	return result
}

// extractFromCondition extracts VPC/VPCE values from a specific condition operator
func extractFromCondition(result *domain.ResourcePolicyConditions, effect string, condition map[string]interface{}, operator string) {
	opCondition, ok := condition[operator].(map[string]interface{})
	if !ok {
		return
	}

	// Extract aws:SourceVpc
	if vpcValues := extractConditionValues(opCondition, "aws:SourceVpc", "aws:sourcevpc"); len(vpcValues) > 0 {
		categorizeConditionValues(result, effect, operator, "vpc", vpcValues)
	}

	// Extract aws:SourceVpce
	if vpceValues := extractConditionValues(opCondition, "aws:SourceVpce", "aws:sourcevpce"); len(vpceValues) > 0 {
		categorizeConditionValues(result, effect, operator, "vpce", vpceValues)
	}
}

// extractConditionValues gets values for a condition key (handles case insensitivity and arrays)
func extractConditionValues(opCondition map[string]interface{}, keys ...string) []string {
	for _, key := range keys {
		// Try exact key
		if val, ok := opCondition[key]; ok {
			return normalizeToStringSlice(val)
		}
		// Try case-insensitive
		for k, v := range opCondition {
			if strings.EqualFold(k, key) {
				return normalizeToStringSlice(v)
			}
		}
	}
	return nil
}

// normalizeToStringSlice converts interface{} to []string
func normalizeToStringSlice(val interface{}) []string {
	switch v := val.(type) {
	case string:
		return []string{v}
	case []interface{}:
		result := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	case []string:
		return v
	}
	return nil
}

// categorizeConditionValues puts extracted values into the right bucket based on effect/operator
func categorizeConditionValues(result *domain.ResourcePolicyConditions, effect, operator, condType string, values []string) {
	isAllow := effect == "Allow"
	isDeny := effect == "Deny"
	isNotEquals := strings.Contains(operator, "NotEquals")

	switch condType {
	case "vpc":
		if isAllow && !isNotEquals {
			// Allow + StringEquals → whitelist
			result.AllowedVPCs = appendUnique(result.AllowedVPCs, values...)
		} else if isDeny && !isNotEquals {
			// Deny + StringEquals → blacklist
			result.DeniedVPCs = appendUnique(result.DeniedVPCs, values...)
		} else if isDeny && isNotEquals {
			// Deny + StringNotEquals → deny everyone except these
			result.DenyIfNotInVPCs = appendUnique(result.DenyIfNotInVPCs, values...)
		}
	case "vpce":
		if isAllow && !isNotEquals {
			result.AllowedVPCEs = appendUnique(result.AllowedVPCEs, values...)
		} else if isDeny && !isNotEquals {
			result.DeniedVPCEs = appendUnique(result.DeniedVPCEs, values...)
		} else if isDeny && isNotEquals {
			result.DenyIfNotInVPCEs = appendUnique(result.DenyIfNotInVPCEs, values...)
		}
	}
}

// appendUnique appends values to a slice, avoiding duplicates
func appendUnique(slice []string, values ...string) []string {
	seen := make(map[string]bool)
	for _, v := range slice {
		seen[v] = true
	}
	for _, v := range values {
		if !seen[v] {
			slice = append(slice, v)
			seen[v] = true
		}
	}
	return slice
}
