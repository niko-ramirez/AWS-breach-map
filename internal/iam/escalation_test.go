package iam

import (
	"testing"
)

// =============================================================================
// hasPrivilegeEscalationActions TESTS
// =============================================================================

func TestHasPrivilegeEscalationActions(t *testing.T) {
	tests := []struct {
		name      string
		policyDoc map[string]interface{}
		want      []string
	}{
		{
			name: "iam:PutRolePolicy detected",
			policyDoc: map[string]interface{}{
				"Statement": []interface{}{
					map[string]interface{}{
						"Effect":   "Allow",
						"Action":   "iam:PutRolePolicy",
						"Resource": "*",
					},
				},
			},
			want: []string{"iam:PutRolePolicy"},
		},
		{
			name: "iam:AttachRolePolicy detected",
			policyDoc: map[string]interface{}{
				"Statement": []interface{}{
					map[string]interface{}{
						"Effect":   "Allow",
						"Action":   "iam:AttachRolePolicy",
						"Resource": "*",
					},
				},
			},
			want: []string{"iam:AttachRolePolicy"},
		},
		{
			name: "iam:CreatePolicy detected",
			policyDoc: map[string]interface{}{
				"Statement": []interface{}{
					map[string]interface{}{
						"Effect":   "Allow",
						"Action":   "iam:CreatePolicy",
						"Resource": "*",
					},
				},
			},
			want: []string{"iam:CreatePolicy"},
		},
		{
			name: "iam:UpdateAssumeRolePolicy detected",
			policyDoc: map[string]interface{}{
				"Statement": []interface{}{
					map[string]interface{}{
						"Effect":   "Allow",
						"Action":   "iam:UpdateAssumeRolePolicy",
						"Resource": "*",
					},
				},
			},
			want: []string{"iam:UpdateAssumeRolePolicy"},
		},
		{
			name: "iam:* wildcard detected",
			policyDoc: map[string]interface{}{
				"Statement": []interface{}{
					map[string]interface{}{
						"Effect":   "Allow",
						"Action":   "iam:*",
						"Resource": "*",
					},
				},
			},
			want: []string{"iam:*"},
		},
		{
			name: "full wildcard * detected",
			policyDoc: map[string]interface{}{
				"Statement": []interface{}{
					map[string]interface{}{
						"Effect":   "Allow",
						"Action":   "*",
						"Resource": "*",
					},
				},
			},
			want: []string{"iam:*"},
		},
		{
			name: "multiple dangerous actions",
			policyDoc: map[string]interface{}{
				"Statement": []interface{}{
					map[string]interface{}{
						"Effect":   "Allow",
						"Action":   []interface{}{"iam:PutRolePolicy", "iam:AttachRolePolicy", "iam:CreateRole"},
						"Resource": "*",
					},
				},
			},
			want: []string{"iam:PutRolePolicy", "iam:AttachRolePolicy", "iam:CreateRole"},
		},
		{
			name: "deny effect is ignored",
			policyDoc: map[string]interface{}{
				"Statement": []interface{}{
					map[string]interface{}{
						"Effect":   "Deny",
						"Action":   "iam:PutRolePolicy",
						"Resource": "*",
					},
				},
			},
			want: []string{},
		},
		{
			name: "non-dangerous IAM action not detected",
			policyDoc: map[string]interface{}{
				"Statement": []interface{}{
					map[string]interface{}{
						"Effect":   "Allow",
						"Action":   "iam:GetRole",
						"Resource": "*",
					},
				},
			},
			want: []string{},
		},
		{
			name: "non-IAM action not detected",
			policyDoc: map[string]interface{}{
				"Statement": []interface{}{
					map[string]interface{}{
						"Effect":   "Allow",
						"Action":   "s3:PutBucketPolicy",
						"Resource": "*",
					},
				},
			},
			want: []string{},
		},
		{
			name:      "empty policy",
			policyDoc: map[string]interface{}{},
			want:      []string{},
		},
		{
			name: "multiple statements with mixed actions",
			policyDoc: map[string]interface{}{
				"Statement": []interface{}{
					map[string]interface{}{
						"Effect":   "Allow",
						"Action":   "s3:GetObject",
						"Resource": "*",
					},
					map[string]interface{}{
						"Effect":   "Allow",
						"Action":   "iam:CreateUser",
						"Resource": "*",
					},
				},
			},
			want: []string{"iam:CreateUser"},
		},
		{
			name: "user policy actions detected",
			policyDoc: map[string]interface{}{
				"Statement": []interface{}{
					map[string]interface{}{
						"Effect":   "Allow",
						"Action":   []interface{}{"iam:PutUserPolicy", "iam:AttachUserPolicy"},
						"Resource": "*",
					},
				},
			},
			want: []string{"iam:PutUserPolicy", "iam:AttachUserPolicy"},
		},
		{
			name: "group policy actions detected",
			policyDoc: map[string]interface{}{
				"Statement": []interface{}{
					map[string]interface{}{
						"Effect":   "Allow",
						"Action":   []interface{}{"iam:PutGroupPolicy", "iam:AttachGroupPolicy", "iam:AddUserToGroup"},
						"Resource": "*",
					},
				},
			},
			want: []string{"iam:PutGroupPolicy", "iam:AttachGroupPolicy", "iam:AddUserToGroup"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasPrivilegeEscalationActions(tt.policyDoc)
			if !stringSlicesEqualEscalation(got, tt.want) {
				t.Errorf("hasPrivilegeEscalationActions() = %v, want %v", got, tt.want)
			}
		})
	}
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

func stringSlicesEqualEscalation(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	aMap := make(map[string]int)
	for _, s := range a {
		aMap[s]++
	}
	for _, s := range b {
		aMap[s]--
		if aMap[s] < 0 {
			return false
		}
	}
	return true
}

