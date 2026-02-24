package network

import (
	"testing"
)

/*
Policy Parser Tests

These tests verify that we correctly extract network conditions from
various bucket policy patterns.
*/

func TestExtractPolicyConditions_DenyWithVPC(t *testing.T) {
	// Common pattern: Deny access from specific VPCs
	policy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Deny",
			"Principal": "*",
			"Action": "s3:*",
			"Resource": "arn:aws:s3:::my-bucket/*",
			"Condition": {
				"StringEquals": {
					"aws:SourceVpc": "vpc-untrusted"
				}
			}
		}]
	}`

	conditions, err := ExtractPolicyConditions(policy)
	if err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}

	if !conditions.HasVPCConditions {
		t.Error("Expected HasVPCConditions to be true")
	}
	if len(conditions.DeniedVPCs) != 1 || conditions.DeniedVPCs[0] != "vpc-untrusted" {
		t.Errorf("Expected DeniedVPCs=[vpc-untrusted], got %v", conditions.DeniedVPCs)
	}
}

func TestExtractPolicyConditions_AllowWithVPCWhitelist(t *testing.T) {
	// Common pattern: Only allow access from trusted VPCs
	policy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": "*",
			"Action": "s3:GetObject",
			"Resource": "arn:aws:s3:::my-bucket/*",
			"Condition": {
				"StringEquals": {
					"aws:SourceVpc": ["vpc-prod", "vpc-staging"]
				}
			}
		}]
	}`

	conditions, err := ExtractPolicyConditions(policy)
	if err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}

	if !conditions.HasVPCConditions {
		t.Error("Expected HasVPCConditions to be true")
	}
	if len(conditions.AllowedVPCs) != 2 {
		t.Errorf("Expected 2 AllowedVPCs, got %v", conditions.AllowedVPCs)
	}
}

func TestExtractPolicyConditions_DenyNotEqualsVPC(t *testing.T) {
	// Common pattern: "Deny all except from our VPC"
	// This is the inverse whitelist pattern
	policy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Deny",
			"Principal": "*",
			"Action": "s3:*",
			"Resource": "arn:aws:s3:::my-bucket/*",
			"Condition": {
				"StringNotEquals": {
					"aws:SourceVpc": "vpc-trusted"
				}
			}
		}]
	}`

	conditions, err := ExtractPolicyConditions(policy)
	if err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}

	if !conditions.HasVPCConditions {
		t.Error("Expected HasVPCConditions to be true")
	}
	if len(conditions.DenyIfNotInVPCs) != 1 || conditions.DenyIfNotInVPCs[0] != "vpc-trusted" {
		t.Errorf("Expected DenyIfNotInVPCs=[vpc-trusted], got %v", conditions.DenyIfNotInVPCs)
	}
}

func TestExtractPolicyConditions_VPCEWhitelist(t *testing.T) {
	// Pattern: Require access via specific VPC endpoint
	policy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": "*",
			"Action": "s3:GetObject",
			"Resource": "arn:aws:s3:::my-bucket/*",
			"Condition": {
				"StringEquals": {
					"aws:SourceVpce": "vpce-abc123"
				}
			}
		}]
	}`

	conditions, err := ExtractPolicyConditions(policy)
	if err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}

	if !conditions.HasVPCEConditions {
		t.Error("Expected HasVPCEConditions to be true")
	}
	if len(conditions.AllowedVPCEs) != 1 || conditions.AllowedVPCEs[0] != "vpce-abc123" {
		t.Errorf("Expected AllowedVPCEs=[vpce-abc123], got %v", conditions.AllowedVPCEs)
	}
}

func TestExtractPolicyConditions_CombinedConditions(t *testing.T) {
	// Complex pattern: Multiple conditions
	policy := `{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Effect": "Allow",
				"Principal": "*",
				"Action": "s3:GetObject",
				"Resource": "arn:aws:s3:::my-bucket/*",
				"Condition": {
					"StringEquals": {
						"aws:SourceVpc": "vpc-prod"
					}
				}
			},
			{
				"Effect": "Deny",
				"Principal": "*",
				"Action": "s3:*",
				"Resource": "arn:aws:s3:::my-bucket/*",
				"Condition": {
					"StringEquals": {
						"aws:SourceVpc": "vpc-bad"
					}
				}
			}
		]
	}`

	conditions, err := ExtractPolicyConditions(policy)
	if err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}

	if len(conditions.AllowedVPCs) != 1 {
		t.Errorf("Expected 1 AllowedVPC, got %v", conditions.AllowedVPCs)
	}
	if len(conditions.DeniedVPCs) != 1 {
		t.Errorf("Expected 1 DeniedVPC, got %v", conditions.DeniedVPCs)
	}
}

func TestExtractPolicyConditions_NoConditions(t *testing.T) {
	// Policy with no network conditions
	policy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": "*",
			"Action": "s3:GetObject",
			"Resource": "arn:aws:s3:::my-bucket/*"
		}]
	}`

	conditions, err := ExtractPolicyConditions(policy)
	if err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}

	if conditions.HasVPCConditions {
		t.Error("Expected HasVPCConditions to be false")
	}
	if conditions.HasVPCEConditions {
		t.Error("Expected HasVPCEConditions to be false")
	}
}

func TestExtractPolicyConditions_EmptyPolicy(t *testing.T) {
	conditions, err := ExtractPolicyConditions("")
	if err != nil {
		t.Fatalf("Expected no error for empty policy, got: %v", err)
	}

	if conditions == nil {
		t.Error("Expected non-nil conditions")
	}
}
