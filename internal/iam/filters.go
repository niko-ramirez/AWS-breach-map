package iam

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"

	"breachmap/internal/logging"
)

// FilterRolesForS3Access filters customer-managed IAM roles for S3 access
func FilterRolesForS3Access(ctx context.Context, iamClient *iam.Client, bucketARNs []string) ([]string, error) {
	logging.LogDebug("--- Filtering IAM Roles for S3 Access ---")

	roles, err := EnumerateAllRoles(ctx, iamClient)
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate roles: %w", err)
	}

	logging.LogDebug(fmt.Sprintf("Checking %d roles for S3 permissions", len(roles)))

	s3RoleARNs := make([]string, 0)

	s3Actions := map[string]bool{
		"s3:GetObject":    true,
		"s3:PutObject":    true,
		"s3:DeleteObject": true,
		"s3:ListBucket":   true,
		"s3:*":            true,
		"*":               true,
	}

	bucketARNSet := make(map[string]bool)
	for _, bucketARN := range bucketARNs {
		bucketARNSet[bucketARN] = true
		bucketARNSet[bucketARN+"/*"] = true
	}

	for _, role := range roles {
		if role.Arn == nil || role.RoleName == nil {
			continue
		}

		roleARN := aws.ToString(role.Arn)
		roleName := aws.ToString(role.RoleName)

		if strings.HasPrefix(roleARN, "arn:aws:iam::aws:role/") {
			continue
		}

		policies, err := GetAllPoliciesForRole(ctx, iamClient, roleName)
		if err != nil {
			logging.LogWarn("Failed to get policies for role", map[string]interface{}{
				"role":  roleName,
				"error": err.Error(),
			})
			continue
		}

		hasS3Access := false
		for _, policyDoc := range policies {
			if hasS3AccessInPolicy(policyDoc, s3Actions, bucketARNSet) {
				hasS3Access = true
				break
			}
		}

		if hasS3Access {
			s3RoleARNs = append(s3RoleARNs, roleARN)
		}
	}

	logging.LogDebug(fmt.Sprintf("Found %d roles with S3 access patterns", len(s3RoleARNs)))
	return s3RoleARNs, nil
}

func hasS3AccessInPolicy(policyDoc map[string]interface{}, s3Actions map[string]bool, bucketARNSet map[string]bool) bool {
	statements, ok := policyDoc["Statement"].([]interface{})
	if !ok {
		return false
	}

	for _, stmtInterface := range statements {
		stmt, ok := stmtInterface.(map[string]interface{})
		if !ok {
			continue
		}

		if effect, ok := stmt["Effect"].(string); !ok || effect != "Allow" {
			continue
		}

		actions := NormalizeIAMToList(stmt["Action"])
		hasS3Action := false
		for _, action := range actions {
			if s3Actions[action] {
				hasS3Action = true
				break
			}
			if strings.HasPrefix(action, "s3:") {
				hasS3Action = true
				break
			}
		}

		if !hasS3Action {
			continue
		}

		resources := NormalizeIAMToList(stmt["Resource"])
		for _, resource := range resources {
			if resource == "*" {
				return true
			}
			if bucketARNSet[resource] {
				return true
			}
			for bucketARN := range bucketARNSet {
				if resource == bucketARN+"/*" || resource == bucketARN {
					return true
				}
			}
			if strings.Contains(resource, "*") {
				for bucketARN := range bucketARNSet {
					pattern := "^" + strings.ReplaceAll(strings.ReplaceAll(resource, "*", ".*"), "?", ".")
					matched, _ := regexp.MatchString(pattern, bucketARN)
					if matched {
						return true
					}
				}
			}
		}
	}

	return false
}

// FilterRolesForRDSAccess filters customer-managed IAM roles for RDS access
func FilterRolesForRDSAccess(ctx context.Context, iamClient *iam.Client, dbARNs []string) ([]string, error) {
	logging.LogDebug("--- Filtering IAM Roles for RDS Access ---")

	roles, err := EnumerateAllRoles(ctx, iamClient)
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate roles: %w", err)
	}

	rdsActions := map[string]bool{
		"rds-db:connect":              true,
		"rds:DescribeDBInstances":     true,
		"rds:DescribeDBClusters":      true,
		"rds:*":                       true,
		"*":                           true,
	}

	dbARNSet := make(map[string]bool)
	for _, arn := range dbARNs {
		dbARNSet[arn] = true
	}

	rdsRoleARNs := make([]string, 0)
	for _, role := range roles {
		if role.Arn == nil || role.RoleName == nil {
			continue
		}
		roleARN := aws.ToString(role.Arn)
		if strings.HasPrefix(roleARN, "arn:aws:iam::aws:role/") {
			continue
		}

		policies, err := GetAllPoliciesForRole(ctx, iamClient, aws.ToString(role.RoleName))
		if err != nil {
			logging.LogWarn("Failed to get policies for role", map[string]interface{}{"role": aws.ToString(role.RoleName), "error": err.Error()})
			continue
		}

		for _, policyDoc := range policies {
			if hasActionInPolicy(policyDoc, rdsActions, dbARNSet, "rds") {
				rdsRoleARNs = append(rdsRoleARNs, roleARN)
				break
			}
		}
	}

	logging.LogDebug(fmt.Sprintf("Found %d roles with RDS access patterns", len(rdsRoleARNs)))
	return rdsRoleARNs, nil
}

// hasActionInPolicy checks if a policy document grants any of the target actions on the target resources
func hasActionInPolicy(policyDoc map[string]interface{}, targetActions map[string]bool, resourceARNSet map[string]bool, servicePrefix string) bool {
	statements, ok := policyDoc["Statement"].([]interface{})
	if !ok {
		return false
	}
	for _, stmtInterface := range statements {
		stmt, ok := stmtInterface.(map[string]interface{})
		if !ok {
			continue
		}
		if effect, ok := stmt["Effect"].(string); !ok || effect != "Allow" {
			continue
		}
		actions := NormalizeIAMToList(stmt["Action"])
		hasAction := false
		for _, action := range actions {
			if targetActions[action] || strings.HasPrefix(action, servicePrefix+":") {
				hasAction = true
				break
			}
		}
		if !hasAction {
			continue
		}
		resources := NormalizeIAMToList(stmt["Resource"])
		for _, resource := range resources {
			if resource == "*" {
				return true
			}
			if resourceARNSet[resource] {
				return true
			}
			if strings.Contains(resource, "*") {
				for arn := range resourceARNSet {
					pattern := "^" + strings.ReplaceAll(strings.ReplaceAll(resource, "*", ".*"), "?", ".")
					if matched, _ := regexp.MatchString(pattern, arn); matched {
						return true
					}
				}
			}
		}
	}
	return false
}

// FilterRolesForKMSActions filters customer-managed IAM roles for KMS actions
func FilterRolesForKMSActions(ctx context.Context, iamClient *iam.Client) ([]string, error) {
	logging.LogDebug("--- Filtering IAM Roles for KMS Actions ---")

	roles, err := EnumerateAllRoles(ctx, iamClient)
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate roles: %w", err)
	}

	logging.LogDebug(fmt.Sprintf("Checking %d roles for KMS permissions", len(roles)))

	type roleTask struct {
		roleARN  string
		roleName string
	}
	tasks := make([]roleTask, 0)
	for _, role := range roles {
		if role.Arn == nil || role.RoleName == nil {
			continue
		}

		roleARN := aws.ToString(role.Arn)
		roleName := aws.ToString(role.RoleName)

		if strings.HasPrefix(roleARN, "arn:aws:iam::aws:role/") {
			continue
		}

		tasks = append(tasks, roleTask{roleARN: roleARN, roleName: roleName})
	}

	kmsActions := map[string]bool{
		"kms:Decrypt":                         true,
		"kms:GenerateDataKey":                 true,
		"kms:Encrypt":                         true,
		"kms:ReEncrypt":                       true,
		"kms:GenerateDataKeyWithoutPlaintext": true,
		"kms:CreateGrant":                     true,
		"kms:DescribeKey":                     true,
		"kms:*":                               true,
		"*":                                   true,
	}

	type roleResult struct {
		roleARN          string
		hasKMSPermission bool
	}

	resultChan := make(chan roleResult, len(tasks))
	var wg sync.WaitGroup

	const maxConcurrentRoles = 5
	semaphore := make(chan struct{}, maxConcurrentRoles)

	for _, task := range tasks {
		wg.Add(1)
		go func(t roleTask) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			policies, err := GetAllPoliciesForRole(ctx, iamClient, t.roleName)
			if err != nil {
				logging.LogWarn("Failed to get policies for role", map[string]interface{}{
					"role":  t.roleName,
					"error": err.Error(),
				})
				resultChan <- roleResult{roleARN: t.roleARN, hasKMSPermission: false}
				return
			}

			hasKMSPermission := false
			for _, policyDoc := range policies {
				if hasKMSActionInPolicy(policyDoc, kmsActions) {
					hasKMSPermission = true
					break
				}
			}

			resultChan <- roleResult{roleARN: t.roleARN, hasKMSPermission: hasKMSPermission}
		}(task)
	}

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	kmsRoleARNs := make([]string, 0)
	for result := range resultChan {
		if result.hasKMSPermission {
			kmsRoleARNs = append(kmsRoleARNs, result.roleARN)
		}
	}

	logging.LogDebug(fmt.Sprintf("Found %d roles with KMS permissions", len(kmsRoleARNs)))
	return kmsRoleARNs, nil
}

func hasKMSActionInPolicy(policyDoc map[string]interface{}, kmsActions map[string]bool) bool {
	statements, ok := policyDoc["Statement"].([]interface{})
	if !ok {
		return false
	}

	for _, stmtInterface := range statements {
		stmt, ok := stmtInterface.(map[string]interface{})
		if !ok {
			continue
		}

		if effect, ok := stmt["Effect"].(string); !ok || effect != "Allow" {
			continue
		}

		actions := NormalizeIAMToList(stmt["Action"])
		for _, action := range actions {
			if kmsActions[action] {
				return true
			}
			if strings.HasPrefix(action, "kms:") {
				return true
			}
		}

		resources := NormalizeIAMToList(stmt["Resource"])
		for _, resource := range resources {
			if resource == "*" {
				for _, action := range actions {
					if action == "*" || strings.HasPrefix(action, "kms:") {
						return true
					}
				}
			}
			if strings.HasPrefix(resource, "arn:aws:kms:") {
				return true
			}
		}
	}

	return false
}
