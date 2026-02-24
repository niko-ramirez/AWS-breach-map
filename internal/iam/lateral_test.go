package iam

import (
	"testing"
)

// =============================================================================
// resourceMatchesRoleARN TESTS
// =============================================================================

func TestResourceMatchesRoleARN(t *testing.T) {
	tests := []struct {
		name     string
		resource string
		roleARN  string
		want     bool
	}{
		// Exact matches
		{
			name:     "exact match",
			resource: "arn:aws:iam::123456789012:role/AdminRole",
			roleARN:  "arn:aws:iam::123456789012:role/AdminRole",
			want:     true,
		},
		{
			name:     "exact match different role",
			resource: "arn:aws:iam::123456789012:role/AdminRole",
			roleARN:  "arn:aws:iam::123456789012:role/UserRole",
			want:     false,
		},

		// Wildcard *
		{
			name:     "wildcard star matches any role",
			resource: "*",
			roleARN:  "arn:aws:iam::123456789012:role/AnyRole",
			want:     true,
		},

		// Prefix wildcards
		{
			name:     "prefix wildcard matches role in account",
			resource: "arn:aws:iam::123456789012:role/*",
			roleARN:  "arn:aws:iam::123456789012:role/AdminRole",
			want:     true,
		},
		{
			name:     "prefix wildcard wrong account",
			resource: "arn:aws:iam::111111111111:role/*",
			roleARN:  "arn:aws:iam::123456789012:role/AdminRole",
			want:     false,
		},
		{
			name:     "prefix wildcard with partial role name",
			resource: "arn:aws:iam::123456789012:role/Admin*",
			roleARN:  "arn:aws:iam::123456789012:role/AdminRole",
			want:     true,
		},
		{
			name:     "prefix wildcard partial name no match",
			resource: "arn:aws:iam::123456789012:role/User*",
			roleARN:  "arn:aws:iam::123456789012:role/AdminRole",
			want:     false,
		},

		// Path-based roles
		{
			name:     "role with path exact match",
			resource: "arn:aws:iam::123456789012:role/service-roles/LambdaRole",
			roleARN:  "arn:aws:iam::123456789012:role/service-roles/LambdaRole",
			want:     true,
		},
		{
			name:     "wildcard matches role with path",
			resource: "arn:aws:iam::123456789012:role/*",
			roleARN:  "arn:aws:iam::123456789012:role/service-roles/LambdaRole",
			want:     true,
		},

		// Middle wildcards (previously broken — fell to substring fallback)
		{
			name:     "middle wildcard matches",
			resource: "arn:aws:iam::123456789012:role/dev-*-admin",
			roleARN:  "arn:aws:iam::123456789012:role/dev-foo-admin",
			want:     true,
		},
		{
			name:     "middle wildcard no match wrong prefix",
			resource: "arn:aws:iam::123456789012:role/dev-*-admin",
			roleARN:  "arn:aws:iam::123456789012:role/prod-foo-admin",
			want:     false,
		},
		{
			name:     "middle wildcard no match wrong suffix",
			resource: "arn:aws:iam::123456789012:role/dev-*-admin",
			roleARN:  "arn:aws:iam::123456789012:role/dev-foo-reader",
			want:     false,
		},
		{
			name:     "middle wildcard matches empty segment",
			resource: "arn:aws:iam::123456789012:role/dev-*-admin",
			roleARN:  "arn:aws:iam::123456789012:role/dev--admin",
			want:     true,
		},
		{
			name:     "middle wildcard matches multi-segment",
			resource: "arn:aws:iam::123456789012:role/dev-*-admin",
			roleARN:  "arn:aws:iam::123456789012:role/dev-foo-bar-baz-admin",
			want:     true,
		},

		// Non-standard AWS partitions (previously fell to broken fallback)
		{
			name:     "china partition wildcard",
			resource: "arn:aws-cn:iam::123456789012:role/*",
			roleARN:  "arn:aws-cn:iam::123456789012:role/SomeRole",
			want:     true,
		},
		{
			name:     "govcloud partition wildcard",
			resource: "arn:aws-us-gov:iam::123456789012:role/*",
			roleARN:  "arn:aws-us-gov:iam::123456789012:role/SomeRole",
			want:     true,
		},
		{
			name:     "china partition wrong account",
			resource: "arn:aws-cn:iam::111111111111:role/*",
			roleARN:  "arn:aws-cn:iam::123456789012:role/SomeRole",
			want:     false,
		},

		// Suffix/leading wildcards (previously returned false positives via substring)
		{
			name:     "suffix wildcard matches",
			resource: "*-admin",
			roleARN:  "arn:aws:iam::123456789012:role/SomeRole-admin",
			want:     true,
		},
		{
			name:     "suffix wildcard no match — admin not at end",
			resource: "*-admin",
			roleARN:  "arn:aws:iam::123456789012:role/not-admin-really",
			want:     false,
		},

		// Question mark wildcard (IAM supports ? for single char)
		{
			name:     "question mark matches single char",
			resource: "arn:aws:iam::123456789012:role/Role?",
			roleARN:  "arn:aws:iam::123456789012:role/RoleA",
			want:     true,
		},
		{
			name:     "question mark no match on zero chars",
			resource: "arn:aws:iam::123456789012:role/Role?",
			roleARN:  "arn:aws:iam::123456789012:role/Role",
			want:     false,
		},
		{
			name:     "question mark no match on two chars",
			resource: "arn:aws:iam::123456789012:role/Role?",
			roleARN:  "arn:aws:iam::123456789012:role/RoleAB",
			want:     false,
		},

		// Edge cases
		{
			name:     "empty resource",
			resource: "",
			roleARN:  "arn:aws:iam::123456789012:role/AdminRole",
			want:     false,
		},
		{
			name:     "empty role ARN",
			resource: "arn:aws:iam::123456789012:role/AdminRole",
			roleARN:  "",
			want:     false,
		},
		{
			name:     "both empty",
			resource: "",
			roleARN:  "",
			want:     true, // exact match: "" == ""
		},
		{
			name:     "wildcard star matches empty roleARN",
			resource: "*",
			roleARN:  "",
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resourceMatchesRoleARN(tt.resource, tt.roleARN)
			if got != tt.want {
				t.Errorf("resourceMatchesRoleARN(%q, %q) = %v, want %v",
					tt.resource, tt.roleARN, got, tt.want)
			}
		})
	}
}

// =============================================================================
// canAssumeRole TESTS (policy parsing)
// =============================================================================

func TestCanAssumeRole(t *testing.T) {
	tests := []struct {
		name           string
		policyDoc      map[string]interface{}
		targetRoleARNs []string
		want           []string
	}{
		{
			name: "allows sts:AssumeRole on specific role",
			policyDoc: map[string]interface{}{
				"Statement": []interface{}{
					map[string]interface{}{
						"Effect":   "Allow",
						"Action":   "sts:AssumeRole",
						"Resource": "arn:aws:iam::123456789012:role/TargetRole",
					},
				},
			},
			targetRoleARNs: []string{"arn:aws:iam::123456789012:role/TargetRole"},
			want:           []string{"arn:aws:iam::123456789012:role/TargetRole"},
		},
		{
			name: "allows sts:AssumeRole with wildcard resource",
			policyDoc: map[string]interface{}{
				"Statement": []interface{}{
					map[string]interface{}{
						"Effect":   "Allow",
						"Action":   "sts:AssumeRole",
						"Resource": "*",
					},
				},
			},
			targetRoleARNs: []string{
				"arn:aws:iam::123456789012:role/RoleA",
				"arn:aws:iam::123456789012:role/RoleB",
			},
			want: []string{
				"arn:aws:iam::123456789012:role/RoleA",
				"arn:aws:iam::123456789012:role/RoleB",
			},
		},
		{
			name: "allows sts:* (wildcard action)",
			policyDoc: map[string]interface{}{
				"Statement": []interface{}{
					map[string]interface{}{
						"Effect":   "Allow",
						"Action":   "sts:*",
						"Resource": "arn:aws:iam::123456789012:role/TargetRole",
					},
				},
			},
			targetRoleARNs: []string{"arn:aws:iam::123456789012:role/TargetRole"},
			want:           []string{"arn:aws:iam::123456789012:role/TargetRole"},
		},
		{
			name: "allows * (full wildcard)",
			policyDoc: map[string]interface{}{
				"Statement": []interface{}{
					map[string]interface{}{
						"Effect":   "Allow",
						"Action":   "*",
						"Resource": "*",
					},
				},
			},
			targetRoleARNs: []string{"arn:aws:iam::123456789012:role/AnyRole"},
			want:           []string{"arn:aws:iam::123456789012:role/AnyRole"},
		},
		{
			name: "deny effect is ignored",
			policyDoc: map[string]interface{}{
				"Statement": []interface{}{
					map[string]interface{}{
						"Effect":   "Deny",
						"Action":   "sts:AssumeRole",
						"Resource": "*",
					},
				},
			},
			targetRoleARNs: []string{"arn:aws:iam::123456789012:role/TargetRole"},
			want:           []string{},
		},
		{
			name: "different action is ignored",
			policyDoc: map[string]interface{}{
				"Statement": []interface{}{
					map[string]interface{}{
						"Effect":   "Allow",
						"Action":   "s3:GetObject",
						"Resource": "*",
					},
				},
			},
			targetRoleARNs: []string{"arn:aws:iam::123456789012:role/TargetRole"},
			want:           []string{},
		},
		{
			name: "action as array",
			policyDoc: map[string]interface{}{
				"Statement": []interface{}{
					map[string]interface{}{
						"Effect":   "Allow",
						"Action":   []interface{}{"sts:AssumeRole", "sts:GetCallerIdentity"},
						"Resource": "arn:aws:iam::123456789012:role/TargetRole",
					},
				},
			},
			targetRoleARNs: []string{"arn:aws:iam::123456789012:role/TargetRole"},
			want:           []string{"arn:aws:iam::123456789012:role/TargetRole"},
		},
		{
			name: "resource as array",
			policyDoc: map[string]interface{}{
				"Statement": []interface{}{
					map[string]interface{}{
						"Effect": "Allow",
						"Action": "sts:AssumeRole",
						"Resource": []interface{}{
							"arn:aws:iam::123456789012:role/RoleA",
							"arn:aws:iam::123456789012:role/RoleB",
						},
					},
				},
			},
			targetRoleARNs: []string{
				"arn:aws:iam::123456789012:role/RoleA",
				"arn:aws:iam::123456789012:role/RoleC",
			},
			want: []string{"arn:aws:iam::123456789012:role/RoleA"},
		},
		{
			name:           "empty policy",
			policyDoc:      map[string]interface{}{},
			targetRoleARNs: []string{"arn:aws:iam::123456789012:role/TargetRole"},
			want:           []string{},
		},
		{
			name: "no matching targets",
			policyDoc: map[string]interface{}{
				"Statement": []interface{}{
					map[string]interface{}{
						"Effect":   "Allow",
						"Action":   "sts:AssumeRole",
						"Resource": "arn:aws:iam::123456789012:role/OtherRole",
					},
				},
			},
			targetRoleARNs: []string{"arn:aws:iam::123456789012:role/TargetRole"},
			want:           []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := canAssumeRole(tt.policyDoc, tt.targetRoleARNs)
			if !stringSlicesEqual(got, tt.want) {
				t.Errorf("canAssumeRole() = %v, want %v", got, tt.want)
			}
		})
	}
}

// =============================================================================
// canPassRole TESTS
// =============================================================================

func TestCanPassRole(t *testing.T) {
	tests := []struct {
		name           string
		policyDoc      map[string]interface{}
		targetRoleARNs []string
		want           []string
	}{
		{
			name: "allows iam:PassRole on specific role",
			policyDoc: map[string]interface{}{
				"Statement": []interface{}{
					map[string]interface{}{
						"Effect":   "Allow",
						"Action":   "iam:PassRole",
						"Resource": "arn:aws:iam::123456789012:role/TargetRole",
					},
				},
			},
			targetRoleARNs: []string{"arn:aws:iam::123456789012:role/TargetRole"},
			want:           []string{"arn:aws:iam::123456789012:role/TargetRole"},
		},
		{
			name: "allows iam:PassRole with wildcard",
			policyDoc: map[string]interface{}{
				"Statement": []interface{}{
					map[string]interface{}{
						"Effect":   "Allow",
						"Action":   "iam:PassRole",
						"Resource": "*",
					},
				},
			},
			targetRoleARNs: []string{"arn:aws:iam::123456789012:role/AnyRole"},
			want:           []string{"arn:aws:iam::123456789012:role/AnyRole"},
		},
		{
			name: "allows iam:* (wildcard action)",
			policyDoc: map[string]interface{}{
				"Statement": []interface{}{
					map[string]interface{}{
						"Effect":   "Allow",
						"Action":   "iam:*",
						"Resource": "arn:aws:iam::123456789012:role/TargetRole",
					},
				},
			},
			targetRoleARNs: []string{"arn:aws:iam::123456789012:role/TargetRole"},
			want:           []string{"arn:aws:iam::123456789012:role/TargetRole"},
		},
		{
			name: "deny effect is ignored",
			policyDoc: map[string]interface{}{
				"Statement": []interface{}{
					map[string]interface{}{
						"Effect":   "Deny",
						"Action":   "iam:PassRole",
						"Resource": "*",
					},
				},
			},
			targetRoleARNs: []string{"arn:aws:iam::123456789012:role/TargetRole"},
			want:           []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := canPassRole(tt.policyDoc, tt.targetRoleARNs)
			if !stringSlicesEqual(got, tt.want) {
				t.Errorf("canPassRole() = %v, want %v", got, tt.want)
			}
		})
	}
}

// =============================================================================
// checkTrustPolicyAllowsPrincipal TESTS
// =============================================================================

func TestCheckTrustPolicyAllowsPrincipal(t *testing.T) {
	tests := []struct {
		name         string
		trustPolicy  map[string]interface{}
		principalARN string
		want         bool
	}{
		{
			name: "exact principal match with AWS key",
			trustPolicy: map[string]interface{}{
				"Statement": []interface{}{
					map[string]interface{}{
						"Effect": "Allow",
						"Principal": map[string]interface{}{
							"AWS": "arn:aws:iam::123456789012:role/TrustedRole",
						},
						"Action": "sts:AssumeRole",
					},
				},
			},
			principalARN: "arn:aws:iam::123456789012:role/TrustedRole",
			want:         true,
		},
		{
			name: "wildcard principal allows any",
			trustPolicy: map[string]interface{}{
				"Statement": []interface{}{
					map[string]interface{}{
						"Effect": "Allow",
						"Principal": map[string]interface{}{
							"AWS": "*",
						},
						"Action": "sts:AssumeRole",
					},
				},
			},
			principalARN: "arn:aws:iam::123456789012:role/AnyRole",
			want:         true,
		},
		{
			name: "principal as string *",
			trustPolicy: map[string]interface{}{
				"Statement": []interface{}{
					map[string]interface{}{
						"Effect":    "Allow",
						"Principal": "*",
						"Action":    "sts:AssumeRole",
					},
				},
			},
			principalARN: "arn:aws:iam::123456789012:role/AnyRole",
			want:         true,
		},
		{
			name: "principal in array",
			trustPolicy: map[string]interface{}{
				"Statement": []interface{}{
					map[string]interface{}{
						"Effect": "Allow",
						"Principal": map[string]interface{}{
							"AWS": []interface{}{
								"arn:aws:iam::111111111111:root",
								"arn:aws:iam::123456789012:role/TrustedRole",
							},
						},
						"Action": "sts:AssumeRole",
					},
				},
			},
			principalARN: "arn:aws:iam::123456789012:role/TrustedRole",
			want:         true,
		},
		{
			name: "principal not in array",
			trustPolicy: map[string]interface{}{
				"Statement": []interface{}{
					map[string]interface{}{
						"Effect": "Allow",
						"Principal": map[string]interface{}{
							"AWS": []interface{}{
								"arn:aws:iam::111111111111:root",
								"arn:aws:iam::222222222222:role/OtherRole",
							},
						},
						"Action": "sts:AssumeRole",
					},
				},
			},
			principalARN: "arn:aws:iam::123456789012:role/TrustedRole",
			want:         false,
		},
		{
			name: "deny effect is not matched",
			trustPolicy: map[string]interface{}{
				"Statement": []interface{}{
					map[string]interface{}{
						"Effect": "Deny",
						"Principal": map[string]interface{}{
							"AWS": "*",
						},
						"Action": "sts:AssumeRole",
					},
				},
			},
			principalARN: "arn:aws:iam::123456789012:role/AnyRole",
			want:         false,
		},
		{
			name: "wrong action is not matched",
			trustPolicy: map[string]interface{}{
				"Statement": []interface{}{
					map[string]interface{}{
						"Effect": "Allow",
						"Principal": map[string]interface{}{
							"AWS": "*",
						},
						"Action": "s3:GetObject",
					},
				},
			},
			principalARN: "arn:aws:iam::123456789012:role/AnyRole",
			want:         false,
		},
		{
			name: "sts:* action is matched",
			trustPolicy: map[string]interface{}{
				"Statement": []interface{}{
					map[string]interface{}{
						"Effect": "Allow",
						"Principal": map[string]interface{}{
							"AWS": "arn:aws:iam::123456789012:role/TrustedRole",
						},
						"Action": "sts:*",
					},
				},
			},
			principalARN: "arn:aws:iam::123456789012:role/TrustedRole",
			want:         true,
		},
		{
			name:         "empty trust policy",
			trustPolicy:  map[string]interface{}{},
			principalARN: "arn:aws:iam::123456789012:role/AnyRole",
			want:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := checkTrustPolicyAllowsPrincipal(tt.trustPolicy, tt.principalARN)
			if got != tt.want {
				t.Errorf("checkTrustPolicyAllowsPrincipal() = %v, want %v", got, tt.want)
			}
		})
	}
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

func stringSlicesEqual(a, b []string) bool {
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
