package exposure

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"

	"breachmap/internal/domain"
	"breachmap/internal/logging"
)

// CollectBucketMetadata collects all required metadata for a bucket
func CollectBucketMetadata(ctx context.Context, s3Svc *s3.Client, bucketName string) (*domain.BucketExposureInputs, error) {
	inputs := &domain.BucketExposureInputs{}

	// Get bucket policy
	policyOutput, err := s3Svc.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		logging.LogDebug("No bucket policy found", map[string]interface{}{"bucket": bucketName, "error": err.Error()})
	} else if policyOutput != nil && policyOutput.Policy != nil {
		var policyDoc domain.BucketPolicyJSON
		if err := json.Unmarshal([]byte(*policyOutput.Policy), &policyDoc); err == nil {
			inputs.Policy = &policyDoc
		} else {
			logging.LogDebug("Failed to parse policy", map[string]interface{}{"bucket": bucketName, "error": err.Error()})
		}
	}

	// Get bucket ACL
	aclOutput, err := s3Svc.GetBucketAcl(ctx, &s3.GetBucketAclInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		logging.LogDebug("No bucket ACL found", map[string]interface{}{"bucket": bucketName, "error": err.Error()})
	} else if aclOutput != nil {
		inputs.ACL = ConvertACLToJSON(aclOutput)
	}

	// Get Public Access Block configuration
	pabOutput, err := s3Svc.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		logging.LogDebug("No Public Access Block config", map[string]interface{}{"bucket": bucketName, "error": err.Error()})
		inputs.PAB = &domain.PublicAccessBlockConfig{
			BlockPublicAcls:       false,
			IgnorePublicAcls:      false,
			BlockPublicPolicy:     false,
			RestrictPublicBuckets: false,
		}
	} else if pabOutput != nil && pabOutput.PublicAccessBlockConfiguration != nil {
		config := pabOutput.PublicAccessBlockConfiguration
		inputs.PAB = &domain.PublicAccessBlockConfig{
			BlockPublicAcls:       aws.ToBool(config.BlockPublicAcls),
			IgnorePublicAcls:      aws.ToBool(config.IgnorePublicAcls),
			BlockPublicPolicy:     aws.ToBool(config.BlockPublicPolicy),
			RestrictPublicBuckets: aws.ToBool(config.RestrictPublicBuckets),
		}
	}

	// Get bucket policy status
	policyStatusOutput, err := s3Svc.GetBucketPolicyStatus(ctx, &s3.GetBucketPolicyStatusInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		logging.LogDebug("Could not get policy status", map[string]interface{}{"bucket": bucketName, "error": err.Error()})
	} else if policyStatusOutput != nil && policyStatusOutput.PolicyStatus != nil {
		inputs.PolicyStatus = &domain.BucketPolicyStatus{
			IsPublic: aws.ToBool(policyStatusOutput.PolicyStatus.IsPublic),
		}
	}

	return inputs, nil
}

// ConvertACLToJSON converts AWS SDK ACL output to our JSON structure
func ConvertACLToJSON(aclOutput *s3.GetBucketAclOutput) *domain.BucketACLJSON {
	if aclOutput == nil {
		return nil
	}

	aclJSON := &domain.BucketACLJSON{}

	if aclOutput.Owner != nil {
		aclJSON.Owner = &domain.ACLOwner{
			ID:          aws.ToString(aclOutput.Owner.ID),
			DisplayName: aws.ToString(aclOutput.Owner.DisplayName),
		}
	}

	if aclOutput.Grants != nil {
		aclJSON.Grants = make([]domain.ACLGrant, 0, len(aclOutput.Grants))
		for _, grant := range aclOutput.Grants {
			aclGrant := domain.ACLGrant{
				Permission: string(grant.Permission),
			}

			if grant.Grantee != nil {
				aclGrant.Grantee = domain.ACLGrantee{
					ID:          aws.ToString(grant.Grantee.ID),
					DisplayName: aws.ToString(grant.Grantee.DisplayName),
				}

				if grant.Grantee.Type == s3types.TypeCanonicalUser {
					aclGrant.Grantee.Type = "CanonicalUser"
				} else if grant.Grantee.Type == s3types.TypeGroup {
					aclGrant.Grantee.Type = "Group"
					aclGrant.Grantee.URI = aws.ToString(grant.Grantee.URI)
				}
			}

			aclJSON.Grants = append(aclJSON.Grants, aclGrant)
		}
	}

	return aclJSON
}

// EvaluatePABShortCircuit checks if PAB completely blocks public exposure
func EvaluatePABShortCircuit(pab *domain.PublicAccessBlockConfig) (bool, string) {
	if pab == nil {
		return false, ""
	}

	if pab.BlockPublicAcls && pab.IgnorePublicAcls && pab.BlockPublicPolicy && pab.RestrictPublicBuckets {
		return true, "Effectively Private (PAB Fully Blocking)"
	}

	return false, ""
}

// EvaluateACLExposure evaluates ACL-based exposure
func EvaluateACLExposure(acl *domain.BucketACLJSON, pab *domain.PublicAccessBlockConfig) string {
	if pab != nil && pab.IgnorePublicAcls {
		return "Private (ACL blocked by PAB)"
	}

	if acl == nil || len(acl.Grants) == 0 {
		return "Private"
	}

	hasPublicAccess := false
	hasAuthenticatedAccess := false

	for _, grant := range acl.Grants {
		if grant.Grantee.URI == "http://acs.amazonaws.com/groups/global/AllUsers" ||
			grant.Grantee.URI == "http://acs.amazonaws.com/groups/global/AllUsers/" {
			hasPublicAccess = true
		}

		if grant.Grantee.URI == "http://acs.amazonaws.com/groups/global/AuthenticatedUsers" ||
			grant.Grantee.URI == "http://acs.amazonaws.com/groups/global/AuthenticatedUsers/" {
			hasAuthenticatedAccess = true
		}
	}

	if hasPublicAccess {
		return "Public"
	}
	if hasAuthenticatedAccess {
		return "AWS-Authenticated Public"
	}

	return "Private"
}

// NormalizePrincipal normalizes a principal value to check if it's public
func NormalizePrincipal(principal interface{}) bool {
	if principal == nil {
		return false
	}

	switch p := principal.(type) {
	case string:
		return p == "*" || strings.Contains(p, "*")
	case map[string]interface{}:
		for key, val := range p {
			if key == "AWS" || key == "Federated" {
				if str, ok := val.(string); ok && str == "*" {
					return true
				}
				if arr, ok := val.([]interface{}); ok {
					for _, item := range arr {
						if str, ok := item.(string); ok && str == "*" {
							return true
						}
					}
				}
			}
		}
	case []interface{}:
		for _, item := range p {
			if NormalizePrincipal(item) {
				return true
			}
		}
	}

	return false
}

// NormalizeToList converts interface{} to []string
func NormalizeToList(value interface{}) []string {
	if value == nil {
		return nil
	}

	switch v := value.(type) {
	case string:
		return []string{v}
	case []interface{}:
		result := make([]string, 0, len(v))
		for _, item := range v {
			if str, ok := item.(string); ok {
				result = append(result, str)
			}
		}
		return result
	case []string:
		return v
	}

	return nil
}

// HasRestrictiveCondition checks if a condition restricts public access
func HasRestrictiveCondition(condition map[string]interface{}) bool {
	if len(condition) == 0 {
		return false
	}

	if ipAddr, ok := condition["IpAddress"].(map[string]interface{}); ok {
		if _, hasIP := ipAddr["aws:SourceIp"]; hasIP {
			return true
		}
	}

	if vpc, ok := condition["StringEquals"].(map[string]interface{}); ok {
		if _, hasVPC := vpc["aws:SourceVpc"]; hasVPC {
			return true
		}
		if _, hasVPCE := vpc["aws:SourceVpce"]; hasVPCE {
			return true
		}
		if _, hasOrgID := vpc["aws:PrincipalOrgID"]; hasOrgID {
			return true
		}
	}

	return false
}

// EvaluatePolicyExposure evaluates bucket policy-based exposure
func EvaluatePolicyExposure(policy *domain.BucketPolicyJSON, pab *domain.PublicAccessBlockConfig) string {
	if pab != nil && pab.BlockPublicPolicy {
		return "Private (Policy blocked by PAB)"
	}

	if policy == nil || len(policy.Statement) == 0 {
		return "Private"
	}

	hasPublicStatement := false
	hasConditionalStatement := false
	hasOrgRestrictedStatement := false

	for _, stmt := range policy.Statement {
		if stmt.Effect != "Allow" {
			continue
		}

		if !NormalizePrincipal(stmt.Principal) {
			continue
		}

		actions := NormalizeToList(stmt.Action)
		hasS3Action := false
		for _, action := range actions {
			if strings.HasPrefix(action, "s3:") || action == "*" || strings.Contains(action, "*") {
				hasS3Action = true
				break
			}
		}

		if !hasS3Action {
			continue
		}

		if HasRestrictiveCondition(stmt.Condition) {
			if stmt.Condition != nil {
				if strEq, ok := stmt.Condition["StringEquals"].(map[string]interface{}); ok {
					if _, hasOrgID := strEq["aws:PrincipalOrgID"]; hasOrgID {
						hasOrgRestrictedStatement = true
						continue
					}
				}
			}
			hasConditionalStatement = true
			continue
		}

		hasPublicStatement = true
	}

	if hasPublicStatement {
		return "Public"
	}
	if hasOrgRestrictedStatement {
		return "Org-Restricted"
	}
	if hasConditionalStatement {
		return "Conditionally Public"
	}

	return "Private"
}

// CombineExposureResults combines ACL and Policy results with PAB priority logic
func CombineExposureResults(bucketName string, inputs *domain.BucketExposureInputs) *domain.ExposureResult {
	result := &domain.ExposureResult{
		ResourceName: bucketName,
	}

	if inputs.PAB != nil {
		result.PABDetails = inputs.PAB
		if blocked, msg := EvaluatePABShortCircuit(inputs.PAB); blocked {
			result.FinalExposure = msg
			result.PABBlocking = true
			return result
		}
		result.PABBlocking = false
	}

	result.ACLExposure = EvaluateACLExposure(inputs.ACL, inputs.PAB)
	if inputs.ACL != nil {
		result.ACLGrants = inputs.ACL.Grants
	}

	result.PolicyExposure = EvaluatePolicyExposure(inputs.Policy, inputs.PAB)
	if inputs.Policy != nil {
		result.PolicyStatements = inputs.Policy.Statement
	}

	if result.ACLExposure == "Public" || result.PolicyExposure == "Public" {
		result.FinalExposure = "Public"
		result.Details = fmt.Sprintf("ACL: %s, Policy: %s", result.ACLExposure, result.PolicyExposure)
		return result
	}

	if result.ACLExposure == "AWS-Authenticated Public" || result.PolicyExposure == "AWS-Authenticated Public" {
		result.FinalExposure = "Public to all AWS accounts"
		result.Details = fmt.Sprintf("ACL: %s, Policy: %s", result.ACLExposure, result.PolicyExposure)
		return result
	}

	if result.PolicyExposure == "Conditionally Public" || result.PolicyExposure == "Org-Restricted" {
		result.FinalExposure = result.PolicyExposure
		result.Details = fmt.Sprintf("Policy: %s", result.PolicyExposure)
		return result
	}

	result.FinalExposure = "Private"
	result.Details = fmt.Sprintf("ACL: %s, Policy: %s", result.ACLExposure, result.PolicyExposure)
	return result
}

// AnalyzeStoreExposure is the main entry point for analyzing a single bucket
func AnalyzeStoreExposure(ctx context.Context, s3Svc *s3.Client, bucketName string) (*domain.ExposureResult, error) {
	inputs, err := CollectBucketMetadata(ctx, s3Svc, bucketName)
	if err != nil {
		return nil, fmt.Errorf("failed to collect metadata for %s: %w", bucketName, err)
	}

	result := CombineExposureResults(bucketName, inputs)
	return result, nil
}
