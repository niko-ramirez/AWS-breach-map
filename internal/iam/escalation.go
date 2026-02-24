package iam

import (
	"context"
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"

	"breachmap/internal/domain"
	"breachmap/internal/logging"
)

// PrivilegeEscalationActions are dangerous IAM write actions
var PrivilegeEscalationActions = []string{
	"iam:PutRolePolicy",
	"iam:AttachRolePolicy",
	"iam:CreatePolicy",
	"iam:PutUserPolicy",
	"iam:AttachUserPolicy",
	"iam:UpdateAssumeRolePolicy",
	"iam:PutGroupPolicy",
	"iam:AttachGroupPolicy",
	"iam:CreateRole",
	"iam:CreateUser",
	"iam:AddUserToGroup",
}

// FindPrivilegeEscalation finds IAM roles with dangerous IAM write permissions
func FindPrivilegeEscalation(ctx context.Context, iamClient *iam.Client) ([]domain.PrivilegeEscalationRole, error) {
	logging.LogDebug("Finding roles with privilege escalation capabilities")

	roles, err := EnumerateAllRoles(ctx, iamClient)
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate roles: %w", err)
	}

	escalationRoles := make([]domain.PrivilegeEscalationRole, 0)

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

		dangerousActions := make([]string, 0)
		actionSet := make(map[string]bool)

		for _, policyDoc := range policies {
			actions := hasPrivilegeEscalationActions(policyDoc)
			for _, action := range actions {
				if !actionSet[action] {
					actionSet[action] = true
					dangerousActions = append(dangerousActions, action)
				}
			}
		}

		if len(dangerousActions) > 0 {
			escalationRoles = append(escalationRoles, domain.PrivilegeEscalationRole{
				RoleARN:          roleARN,
				RoleName:         roleName,
				DangerousActions: dangerousActions,
			})
		}
	}

	logging.LogDebug(fmt.Sprintf("Found %d roles with privilege escalation capabilities", len(escalationRoles)))
	return escalationRoles, nil
}

func hasPrivilegeEscalationActions(policyDoc map[string]interface{}) []string {
	foundActions := make([]string, 0)

	statements, ok := policyDoc["Statement"].([]interface{})
	if !ok {
		return foundActions
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
		for _, action := range actions {
			if action == "iam:*" || action == "*" {
				foundActions = append(foundActions, "iam:*")
				continue
			}

			for _, dangerousAction := range PrivilegeEscalationActions {
				if action == dangerousAction {
					foundActions = append(foundActions, action)
					break
				}
			}
		}
	}

	return foundActions
}
