package iam

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"regexp"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	"breachmap/internal/domain"
	"breachmap/internal/logging"
)

// FindLateralMovement is the internal implementation
func FindLateralMovement(ctx context.Context, iamClient *iam.Client, riskyPrincipalARNs []string) ([]domain.LateralMovementRole, error) {
	if len(riskyPrincipalARNs) == 0 {
		return []domain.LateralMovementRole{}, nil
	}

	logging.LogDebug(fmt.Sprintf("Finding lateral movement roles for %d risky principals", len(riskyPrincipalARNs)))

	roles, err := EnumerateAllRoles(ctx, iamClient)
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate roles: %w", err)
	}

	candidateRoles := make(map[string]*domain.LateralMovementRole)

	for _, role := range roles {
		if role.Arn == nil || role.RoleName == nil {
			continue
		}

		roleARN := aws.ToString(role.Arn)
		roleName := aws.ToString(role.RoleName)

		policies, err := GetAllPoliciesForRole(ctx, iamClient, roleName)
		if err != nil {
			log.Printf("Warning: Failed to get policies for role %s: %v", roleName, err)
			continue
		}

		canAssumeRoles := make([]string, 0)
		canPassRoles := make([]string, 0)

		for _, policyDoc := range policies {
			assumeRoles := canAssumeRole(policyDoc, riskyPrincipalARNs)
			canAssumeRoles = append(canAssumeRoles, assumeRoles...)

			passRoles := canPassRole(policyDoc, riskyPrincipalARNs)
			canPassRoles = append(canPassRoles, passRoles...)
		}

		if len(canAssumeRoles) > 0 || len(canPassRoles) > 0 {
			canAssumeRoles = removeDuplicates(canAssumeRoles)
			canPassRoles = removeDuplicates(canPassRoles)

			candidateRoles[roleARN] = &domain.LateralMovementRole{
				RoleARN:        roleARN,
				RoleName:       roleName,
				CanAssumeRoles: canAssumeRoles,
				CanPassRoles:   canPassRoles,
			}
		}
	}

	logging.LogDebug(fmt.Sprintf("Found %d candidate roles with lateral movement policy patterns", len(candidateRoles)))

	verifiedRoles := make([]domain.LateralMovementRole, 0)

	for roleARN, candidate := range candidateRoles {
		verifiedAssumeRoles := make([]string, 0)
		verifiedPassRoles := make([]string, 0)

		if len(candidate.CanAssumeRoles) > 0 {
			for _, targetRoleARN := range candidate.CanAssumeRoles {
				canAssume, err := verifyAssumeRole(ctx, iamClient, roleARN, targetRoleARN)
				if err != nil {
					logging.LogDebug(fmt.Sprintf("Failed to verify AssumeRole for %s -> %s: %v", roleARN, targetRoleARN, err))
					verifiedAssumeRoles = append(verifiedAssumeRoles, targetRoleARN)
				} else if canAssume {
					verifiedAssumeRoles = append(verifiedAssumeRoles, targetRoleARN)
				}
			}
		}

		if len(candidate.CanPassRoles) > 0 {
			for _, targetRoleARN := range candidate.CanPassRoles {
				canPass, err := verifyPassRole(ctx, iamClient, roleARN, targetRoleARN)
				if err != nil {
					logging.LogDebug(fmt.Sprintf("Failed to verify PassRole for %s -> %s: %v", roleARN, targetRoleARN, err))
					verifiedPassRoles = append(verifiedPassRoles, targetRoleARN)
				} else if canPass {
					verifiedPassRoles = append(verifiedPassRoles, targetRoleARN)
				}
			}
		}

		if len(verifiedAssumeRoles) > 0 || len(verifiedPassRoles) > 0 {
			verifiedRoles = append(verifiedRoles, domain.LateralMovementRole{
				RoleARN:        roleARN,
				RoleName:       candidate.RoleName,
				CanAssumeRoles: verifiedAssumeRoles,
				CanPassRoles:   verifiedPassRoles,
			})
		}
	}

	logging.LogDebug(fmt.Sprintf("Verified %d roles with actual lateral movement capabilities", len(verifiedRoles)))
	return verifiedRoles, nil
}

var (
	cachedRoles    []iamtypes.Role
	cacheRolesOnce sync.Once
	cacheRolesErr  error
)

// EnumerateAllRoles lists all IAM roles in the account.
// Results are cached after the first successful call to avoid redundant API calls.
func EnumerateAllRoles(ctx context.Context, iamClient *iam.Client) ([]iamtypes.Role, error) {
	cacheRolesOnce.Do(func() {
		logging.LogDebug("Enumerating all IAM roles (first call, will be cached)")
		roles := make([]iamtypes.Role, 0)

		paginator := iam.NewListRolesPaginator(iamClient, &iam.ListRolesInput{})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				cacheRolesErr = fmt.Errorf("failed to list roles: %w", err)
				return
			}
			roles = append(roles, page.Roles...)
		}

		cachedRoles = roles
		logging.LogDebug(fmt.Sprintf("Cached %d IAM roles", len(cachedRoles)))
	})

	if cacheRolesErr != nil {
		return nil, cacheRolesErr
	}
	return cachedRoles, nil
}

// GetAllPoliciesForRole retrieves all policies for a role
func GetAllPoliciesForRole(ctx context.Context, iamClient *iam.Client, roleName string) ([]map[string]interface{}, error) {
	policies := make([]map[string]interface{}, 0)

	attachedPolicies, err := iamClient.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{
		RoleName: aws.String(roleName),
	})
	if err != nil {
		log.Printf("Warning: Failed to list attached policies for role %s: %v", roleName, err)
	} else {
		for _, policy := range attachedPolicies.AttachedPolicies {
			policyOut, err := iamClient.GetPolicy(ctx, &iam.GetPolicyInput{
				PolicyArn: policy.PolicyArn,
			})
			if err != nil {
				continue
			}

			versionOut, err := iamClient.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
				PolicyArn: policyOut.Policy.Arn,
				VersionId: policyOut.Policy.DefaultVersionId,
			})
			if err != nil {
				continue
			}

			docStr := aws.ToString(versionOut.PolicyVersion.Document)
			if strings.HasPrefix(docStr, "%") || (strings.Contains(docStr, "%") && !strings.HasPrefix(docStr, "{")) {
				decoded, err := url.QueryUnescape(docStr)
				if err == nil {
					docStr = decoded
				}
			}

			var policyDoc map[string]interface{}
			if err := json.Unmarshal([]byte(docStr), &policyDoc); err == nil {
				policies = append(policies, policyDoc)
			}
		}
	}

	inlinePolicies, err := iamClient.ListRolePolicies(ctx, &iam.ListRolePoliciesInput{
		RoleName: aws.String(roleName),
	})
	if err != nil {
		log.Printf("Warning: Failed to list inline policies for role %s: %v", roleName, err)
	} else {
		for _, policyName := range inlinePolicies.PolicyNames {
			policyOut, err := iamClient.GetRolePolicy(ctx, &iam.GetRolePolicyInput{
				RoleName:   aws.String(roleName),
				PolicyName: aws.String(policyName),
			})
			if err != nil {
				continue
			}

			policyDocStr := aws.ToString(policyOut.PolicyDocument)
			decoded, err := url.QueryUnescape(policyDocStr)
			if err != nil {
				decoded = policyDocStr
			}

			var policyDoc map[string]interface{}
			if err := json.Unmarshal([]byte(decoded), &policyDoc); err == nil {
				policies = append(policies, policyDoc)
			}
		}
	}

	return policies, nil
}

func canAssumeRole(policyDoc map[string]interface{}, targetRoleARNs []string) []string {
	matchedRoles := make([]string, 0)

	statements, ok := policyDoc["Statement"].([]interface{})
	if !ok {
		return matchedRoles
	}

	for _, stmtInterface := range statements {
		stmt, ok := stmtInterface.(map[string]interface{})
		if !ok {
			continue
		}

		if stmt["Effect"] != "Allow" {
			continue
		}

		actions := NormalizeIAMToList(stmt["Action"])
		hasAssumeRole := false
		for _, action := range actions {
			if action == "sts:AssumeRole" || action == "sts:*" || action == "*" {
				hasAssumeRole = true
				break
			}
		}

		if !hasAssumeRole {
			continue
		}

		resources := NormalizeIAMToList(stmt["Resource"])
		for _, resource := range resources {
			for _, targetARN := range targetRoleARNs {
				if resourceMatchesRoleARN(resource, targetARN) {
					matchedRoles = append(matchedRoles, targetARN)
				}
			}
		}
	}

	return matchedRoles
}

func canPassRole(policyDoc map[string]interface{}, targetRoleARNs []string) []string {
	matchedRoles := make([]string, 0)

	statements, ok := policyDoc["Statement"].([]interface{})
	if !ok {
		return matchedRoles
	}

	for _, stmtInterface := range statements {
		stmt, ok := stmtInterface.(map[string]interface{})
		if !ok {
			continue
		}

		if stmt["Effect"] != "Allow" {
			continue
		}

		actions := NormalizeIAMToList(stmt["Action"])
		hasPassRole := false
		for _, action := range actions {
			if action == "iam:PassRole" || action == "iam:*" || action == "*" {
				hasPassRole = true
				break
			}
		}

		if !hasPassRole {
			continue
		}

		resources := NormalizeIAMToList(stmt["Resource"])
		for _, resource := range resources {
			for _, targetARN := range targetRoleARNs {
				if resourceMatchesRoleARN(resource, targetARN) {
					matchedRoles = append(matchedRoles, targetARN)
				}
			}
		}
	}

	return matchedRoles
}

func resourceMatchesRoleARN(resource string, roleARN string) bool {
	if resource == roleARN {
		return true
	}
	if resource == "*" {
		return true
	}
	if !strings.ContainsAny(resource, "*?") {
		return false
	}

	// Convert IAM wildcard pattern to an anchored regex.
	// IAM wildcards: * matches any sequence of characters (including / and empty),
	// ? matches exactly one character.
	re, err := regexp.Compile(iamPatternToRegex(resource))
	if err != nil {
		return false
	}
	return re.MatchString(roleARN)
}

// iamPatternToRegex converts an IAM resource pattern with * and ? wildcards
// into an anchored regex pattern (^...$). All other characters are escaped
// so they are matched literally.
func iamPatternToRegex(pattern string) string {
	var b strings.Builder
	b.WriteString("^")
	for _, ch := range pattern {
		switch ch {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteByte('.')
		default:
			b.WriteString(regexp.QuoteMeta(string(ch)))
		}
	}
	b.WriteString("$")
	return b.String()
}

func removeDuplicates(slice []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0)
	for _, item := range slice {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	return result
}

func verifyAssumeRole(ctx context.Context, iamClient *iam.Client, sourceRoleARN string, targetRoleARN string) (bool, error) {
	simInput := &iam.SimulatePrincipalPolicyInput{
		PolicySourceArn: aws.String(sourceRoleARN),
		ActionNames:     []string{"sts:AssumeRole"},
		ResourceArns:    []string{targetRoleARN},
	}

	simOutput, err := iamClient.SimulatePrincipalPolicy(ctx, simInput)
	if err != nil {
		return false, fmt.Errorf("SimulatePrincipalPolicy failed: %w", err)
	}

	identityAllowed := false
	explicitDeny := false
	for _, evalResult := range simOutput.EvaluationResults {
		if evalResult.EvalDecision == iamtypes.PolicyEvaluationDecisionTypeAllowed {
			identityAllowed = true
		}
		if evalResult.EvalDecision == iamtypes.PolicyEvaluationDecisionTypeExplicitDeny {
			explicitDeny = true
		}
	}

	if explicitDeny {
		return false, nil
	}
	if !identityAllowed {
		return false, nil
	}

	targetRoleName := extractRoleNameFromARN(targetRoleARN)
	if targetRoleName == "" {
		return false, fmt.Errorf("failed to extract role name from ARN: %s", targetRoleARN)
	}

	targetRole, err := iamClient.GetRole(ctx, &iam.GetRoleInput{
		RoleName: aws.String(targetRoleName),
	})
	if err != nil {
		return false, fmt.Errorf("failed to get target role %s: %w", targetRoleName, err)
	}

	trustPolicyDoc := aws.ToString(targetRole.Role.AssumeRolePolicyDocument)
	if strings.Contains(trustPolicyDoc, "%") {
		decoded, err := url.QueryUnescape(trustPolicyDoc)
		if err == nil {
			trustPolicyDoc = decoded
		}
	}

	var trustPolicy map[string]interface{}
	if err := json.Unmarshal([]byte(trustPolicyDoc), &trustPolicy); err != nil {
		return false, fmt.Errorf("failed to parse trust policy: %w", err)
	}

	trustAllows := checkTrustPolicyAllowsPrincipal(trustPolicy, sourceRoleARN)
	if !trustAllows {
		return false, nil
	}

	return true, nil
}

func verifyPassRole(ctx context.Context, iamClient *iam.Client, sourceRoleARN string, targetRoleARN string) (bool, error) {
	simInput := &iam.SimulatePrincipalPolicyInput{
		PolicySourceArn: aws.String(sourceRoleARN),
		ActionNames:     []string{"iam:PassRole"},
		ResourceArns:    []string{targetRoleARN},
	}

	simOutput, err := iamClient.SimulatePrincipalPolicy(ctx, simInput)
	if err != nil {
		return false, fmt.Errorf("SimulatePrincipalPolicy failed: %w", err)
	}

	identityAllowed := false
	explicitDeny := false
	for _, evalResult := range simOutput.EvaluationResults {
		if evalResult.EvalDecision == iamtypes.PolicyEvaluationDecisionTypeAllowed {
			identityAllowed = true
		}
		if evalResult.EvalDecision == iamtypes.PolicyEvaluationDecisionTypeExplicitDeny {
			explicitDeny = true
		}
	}

	if explicitDeny {
		return false, nil
	}
	return identityAllowed, nil
}

func checkTrustPolicyAllowsPrincipal(trustPolicy map[string]interface{}, principalARN string) bool {
	statements, ok := trustPolicy["Statement"].([]interface{})
	if !ok {
		return false
	}

	for _, stmtInterface := range statements {
		stmt, ok := stmtInterface.(map[string]interface{})
		if !ok {
			continue
		}

		if stmt["Effect"] != "Allow" {
			continue
		}

		principalMatches := false
		if principal, ok := stmt["Principal"].(map[string]interface{}); ok {
			if awsPrincipal, ok := principal["AWS"].(string); ok {
				if awsPrincipal == "*" || awsPrincipal == principalARN {
					principalMatches = true
				}
			} else if awsPrincipalList, ok := principal["AWS"].([]interface{}); ok {
				for _, p := range awsPrincipalList {
					if pStr, ok := p.(string); ok {
						if pStr == "*" || pStr == principalARN {
							principalMatches = true
							break
						}
					}
				}
			}
		} else if principal, ok := stmt["Principal"].(string); ok {
			if principal == "*" || principal == principalARN {
				principalMatches = true
			}
		}

		if !principalMatches {
			continue
		}

		actions := NormalizeIAMToList(stmt["Action"])
		for _, action := range actions {
			if action == "sts:AssumeRole" || action == "sts:*" || action == "*" {
				return true
			}
		}
	}

	return false
}

// NormalizeIAMToList normalizes a value to a list of strings
func NormalizeIAMToList(value interface{}) []string {
	switch v := value.(type) {
	case string:
		return []string{v}
	case []string:
		return v
	case []interface{}:
		result := make([]string, 0, len(v))
		for _, item := range v {
			if str, ok := item.(string); ok {
				result = append(result, str)
			}
		}
		return result
	default:
		return []string{}
	}
}

func extractRoleNameFromARN(roleARN string) string {
	parts := strings.Split(roleARN, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return ""
}
