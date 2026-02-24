package iam

import (
	"testing"
)

// =============================================================================
// hasS3AccessInPolicy TESTS
// =============================================================================

func TestHasS3AccessInPolicy(t *testing.T) {
	// Define standard S3 actions map used by the function
	s3Actions := map[string]bool{
		"s3:GetObject":    true,
		"s3:PutObject":    true,
		"s3:DeleteObject": true,
		"s3:ListBucket":   true,
		"s3:*":            true,
		"*":               true,
	}

	tests := []struct {
		name         string
		policyDoc    map[string]interface{}
		bucketARNSet map[string]bool
		want         bool
	}{
		// Basic Allow cases
		{
			name: "s3:GetObject on specific bucket",
			policyDoc: map[string]interface{}{
				"Statement": []interface{}{
					map[string]interface{}{
						"Effect":   "Allow",
						"Action":   "s3:GetObject",
						"Resource": "arn:aws:s3:::my-bucket/*",
					},
				},
			},
			bucketARNSet: map[string]bool{
				"arn:aws:s3:::my-bucket":   true,
				"arn:aws:s3:::my-bucket/*": true,
			},
			want: true,
		},
		{
			name: "s3:* on wildcard resource",
			policyDoc: map[string]interface{}{
				"Statement": []interface{}{
					map[string]interface{}{
						"Effect":   "Allow",
						"Action":   "s3:*",
						"Resource": "*",
					},
				},
			},
			bucketARNSet: map[string]bool{
				"arn:aws:s3:::any-bucket":   true,
				"arn:aws:s3:::any-bucket/*": true,
			},
			want: true,
		},
		{
			name: "full wildcard action and resource",
			policyDoc: map[string]interface{}{
				"Statement": []interface{}{
					map[string]interface{}{
						"Effect":   "Allow",
						"Action":   "*",
						"Resource": "*",
					},
				},
			},
			bucketARNSet: map[string]bool{
				"arn:aws:s3:::my-bucket":   true,
				"arn:aws:s3:::my-bucket/*": true,
			},
			want: true,
		},

		// Action as array
		{
			name: "actions as array including s3:GetObject",
			policyDoc: map[string]interface{}{
				"Statement": []interface{}{
					map[string]interface{}{
						"Effect":   "Allow",
						"Action":   []interface{}{"s3:GetObject", "s3:PutObject"},
						"Resource": "arn:aws:s3:::my-bucket/*",
					},
				},
			},
			bucketARNSet: map[string]bool{
				"arn:aws:s3:::my-bucket":   true,
				"arn:aws:s3:::my-bucket/*": true,
			},
			want: true,
		},

		// Resource as array
		{
			name: "resources as array",
			policyDoc: map[string]interface{}{
				"Statement": []interface{}{
					map[string]interface{}{
						"Effect": "Allow",
						"Action": "s3:GetObject",
						"Resource": []interface{}{
							"arn:aws:s3:::bucket-a/*",
							"arn:aws:s3:::bucket-b/*",
						},
					},
				},
			},
			bucketARNSet: map[string]bool{
				"arn:aws:s3:::bucket-a":   true,
				"arn:aws:s3:::bucket-a/*": true,
			},
			want: true,
		},

		// Deny effect should be ignored (function only checks Allow)
		{
			name: "deny effect is ignored",
			policyDoc: map[string]interface{}{
				"Statement": []interface{}{
					map[string]interface{}{
						"Effect":   "Deny",
						"Action":   "s3:*",
						"Resource": "*",
					},
				},
			},
			bucketARNSet: map[string]bool{
				"arn:aws:s3:::my-bucket":   true,
				"arn:aws:s3:::my-bucket/*": true,
			},
			want: false,
		},

		// Non-S3 actions
		{
			name: "non-S3 action does not match",
			policyDoc: map[string]interface{}{
				"Statement": []interface{}{
					map[string]interface{}{
						"Effect":   "Allow",
						"Action":   "ec2:DescribeInstances",
						"Resource": "*",
					},
				},
			},
			bucketARNSet: map[string]bool{
				"arn:aws:s3:::my-bucket":   true,
				"arn:aws:s3:::my-bucket/*": true,
			},
			want: false,
		},

		// S3 action but wrong bucket
		{
			name: "s3 action on different bucket",
			policyDoc: map[string]interface{}{
				"Statement": []interface{}{
					map[string]interface{}{
						"Effect":   "Allow",
						"Action":   "s3:GetObject",
						"Resource": "arn:aws:s3:::other-bucket/*",
					},
				},
			},
			bucketARNSet: map[string]bool{
				"arn:aws:s3:::my-bucket":   true,
				"arn:aws:s3:::my-bucket/*": true,
			},
			want: false,
		},

		// Wildcard patterns in resource
		{
			name: "wildcard pattern in resource ARN",
			policyDoc: map[string]interface{}{
				"Statement": []interface{}{
					map[string]interface{}{
						"Effect":   "Allow",
						"Action":   "s3:GetObject",
						"Resource": "arn:aws:s3:::prod-*",
					},
				},
			},
			bucketARNSet: map[string]bool{
				"arn:aws:s3:::prod-data":   true,
				"arn:aws:s3:::prod-data/*": true,
			},
			want: true,
		},
		{
			name: "wildcard pattern no match",
			policyDoc: map[string]interface{}{
				"Statement": []interface{}{
					map[string]interface{}{
						"Effect":   "Allow",
						"Action":   "s3:GetObject",
						"Resource": "arn:aws:s3:::dev-*",
					},
				},
			},
			bucketARNSet: map[string]bool{
				"arn:aws:s3:::prod-data":   true,
				"arn:aws:s3:::prod-data/*": true,
			},
			want: false,
		},

		// S3 prefix actions (not in map but start with s3:)
		{
			name: "s3 prefix action matches",
			policyDoc: map[string]interface{}{
				"Statement": []interface{}{
					map[string]interface{}{
						"Effect":   "Allow",
						"Action":   "s3:GetObjectVersion",
						"Resource": "*",
					},
				},
			},
			bucketARNSet: map[string]bool{
				"arn:aws:s3:::my-bucket":   true,
				"arn:aws:s3:::my-bucket/*": true,
			},
			want: true,
		},

		// Empty policy
		{
			name:      "empty policy",
			policyDoc: map[string]interface{}{},
			bucketARNSet: map[string]bool{
				"arn:aws:s3:::my-bucket":   true,
				"arn:aws:s3:::my-bucket/*": true,
			},
			want: false,
		},

		// Multiple statements, one matches
		{
			name: "multiple statements one matches",
			policyDoc: map[string]interface{}{
				"Statement": []interface{}{
					map[string]interface{}{
						"Effect":   "Allow",
						"Action":   "ec2:DescribeInstances",
						"Resource": "*",
					},
					map[string]interface{}{
						"Effect":   "Allow",
						"Action":   "s3:GetObject",
						"Resource": "arn:aws:s3:::my-bucket/*",
					},
				},
			},
			bucketARNSet: map[string]bool{
				"arn:aws:s3:::my-bucket":   true,
				"arn:aws:s3:::my-bucket/*": true,
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasS3AccessInPolicy(tt.policyDoc, s3Actions, tt.bucketARNSet)
			if got != tt.want {
				t.Errorf("hasS3AccessInPolicy() = %v, want %v", got, tt.want)
			}
		})
	}
}

// =============================================================================
// hasKMSActionInPolicy TESTS
// =============================================================================

func TestHasKMSActionInPolicy(t *testing.T) {
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

	tests := []struct {
		name      string
		policyDoc map[string]interface{}
		want      bool
	}{
		{
			name: "kms:Decrypt action",
			policyDoc: map[string]interface{}{
				"Statement": []interface{}{
					map[string]interface{}{
						"Effect":   "Allow",
						"Action":   "kms:Decrypt",
						"Resource": "*",
					},
				},
			},
			want: true,
		},
		{
			name: "kms:GenerateDataKey action",
			policyDoc: map[string]interface{}{
				"Statement": []interface{}{
					map[string]interface{}{
						"Effect":   "Allow",
						"Action":   "kms:GenerateDataKey",
						"Resource": "*",
					},
				},
			},
			want: true,
		},
		{
			name: "kms:* wildcard",
			policyDoc: map[string]interface{}{
				"Statement": []interface{}{
					map[string]interface{}{
						"Effect":   "Allow",
						"Action":   "kms:*",
						"Resource": "*",
					},
				},
			},
			want: true,
		},
		{
			name: "full wildcard *",
			policyDoc: map[string]interface{}{
				"Statement": []interface{}{
					map[string]interface{}{
						"Effect":   "Allow",
						"Action":   "*",
						"Resource": "*",
					},
				},
			},
			want: true,
		},
		{
			name: "kms prefix action (kms:ListKeys)",
			policyDoc: map[string]interface{}{
				"Statement": []interface{}{
					map[string]interface{}{
						"Effect":   "Allow",
						"Action":   "kms:ListKeys",
						"Resource": "*",
					},
				},
			},
			want: true, // Any kms: prefix counts
		},
		{
			name: "resource is KMS key ARN",
			policyDoc: map[string]interface{}{
				"Statement": []interface{}{
					map[string]interface{}{
						"Effect":   "Allow",
						"Action":   "kms:Decrypt",
						"Resource": "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
					},
				},
			},
			want: true,
		},
		{
			name: "deny effect is ignored",
			policyDoc: map[string]interface{}{
				"Statement": []interface{}{
					map[string]interface{}{
						"Effect":   "Deny",
						"Action":   "kms:Decrypt",
						"Resource": "*",
					},
				},
			},
			want: false,
		},
		{
			name: "non-KMS action does not match",
			policyDoc: map[string]interface{}{
				"Statement": []interface{}{
					map[string]interface{}{
						"Effect":   "Allow",
						"Action":   "s3:GetObject",
						"Resource": "*",
					},
				},
			},
			want: false,
		},
		{
			name:      "empty policy",
			policyDoc: map[string]interface{}{},
			want:      false,
		},
		{
			name: "actions as array",
			policyDoc: map[string]interface{}{
				"Statement": []interface{}{
					map[string]interface{}{
						"Effect":   "Allow",
						"Action":   []interface{}{"s3:GetObject", "kms:Decrypt"},
						"Resource": "*",
					},
				},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasKMSActionInPolicy(tt.policyDoc, kmsActions)
			if got != tt.want {
				t.Errorf("hasKMSActionInPolicy() = %v, want %v", got, tt.want)
			}
		})
	}
}

// =============================================================================
// NormalizeIAMToList TESTS
// =============================================================================

func TestNormalizeIAMToList(t *testing.T) {
	tests := []struct {
		name  string
		value interface{}
		want  []string
	}{
		{
			name:  "string value",
			value: "s3:GetObject",
			want:  []string{"s3:GetObject"},
		},
		{
			name:  "string slice",
			value: []string{"s3:GetObject", "s3:PutObject"},
			want:  []string{"s3:GetObject", "s3:PutObject"},
		},
		{
			name:  "interface slice",
			value: []interface{}{"s3:GetObject", "s3:PutObject"},
			want:  []string{"s3:GetObject", "s3:PutObject"},
		},
		{
			name:  "interface slice with non-strings filtered",
			value: []interface{}{"s3:GetObject", 123, "s3:PutObject"},
			want:  []string{"s3:GetObject", "s3:PutObject"},
		},
		{
			name:  "nil value",
			value: nil,
			want:  []string{},
		},
		{
			name:  "empty string",
			value: "",
			want:  []string{""},
		},
		{
			name:  "unsupported type returns empty",
			value: 123,
			want:  []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeIAMToList(tt.value)
			if !stringSlicesEqualOrdered(got, tt.want) {
				t.Errorf("NormalizeIAMToList(%v) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

func stringSlicesEqualOrdered(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

