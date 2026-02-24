package crownjewels

import (
	"testing"
)

// =============================================================================
// IsCrownJewel TESTS
// =============================================================================

func TestIsCrownJewel(t *testing.T) {
	tests := []struct {
		name         string
		arn          string
		resourceName string
		tags         []map[string]string
		kmsEncrypted bool
		want         bool
	}{
		// KMS encryption always makes it a crown jewel
		{
			name:         "KMS encrypted bucket is crown jewel",
			arn:          "",
			resourceName: "random-bucket-12345",
			tags:         nil,
			kmsEncrypted: true,
			want:         true,
		},
		{
			name:         "KMS encrypted even with dev name",
			arn:          "",
			resourceName: "dev-test-bucket",
			tags:         nil,
			kmsEncrypted: true,
			want:         true,
		},

		// Positive regex matches in name
		{
			name:         "production in name",
			arn:          "",
			resourceName: "production-data-bucket",
			tags:         nil,
			kmsEncrypted: false,
			want:         true,
		},
		{
			name:         "prod prefix in name",
			arn:          "",
			resourceName: "prod-customer-data",
			tags:         nil,
			kmsEncrypted: false,
			want:         true,
		},
		{
			name:         "customer in name",
			arn:          "",
			resourceName: "customer-uploads",
			tags:         nil,
			kmsEncrypted: false,
			want:         true,
		},
		{
			name:         "pii in name",
			arn:          "",
			resourceName: "pii-data-bucket",
			tags:         nil,
			kmsEncrypted: false,
			want:         true,
		},
		{
			name:         "sensitive in name",
			arn:          "",
			resourceName: "sensitive-records",
			tags:         nil,
			kmsEncrypted: false,
			want:         true,
		},
		{
			name:         "secret in name",
			arn:          "",
			resourceName: "app-secrets",
			tags:         nil,
			kmsEncrypted: false,
			want:         true,
		},
		{
			name:         "credential in name",
			arn:          "",
			resourceName: "user-credentials-store",
			tags:         nil,
			kmsEncrypted: false,
			want:         true,
		},
		{
			name:         "password in name",
			arn:          "",
			resourceName: "password-vault",
			tags:         nil,
			kmsEncrypted: false,
			want:         true,
		},
		{
			name:         "payment in name",
			arn:          "",
			resourceName: "payment-processing",
			tags:         nil,
			kmsEncrypted: false,
			want:         true,
		},
		{
			name:         "financial in name",
			arn:          "",
			resourceName: "financial-reports",
			tags:         nil,
			kmsEncrypted: false,
			want:         true,
		},
		{
			name:         "hipaa in name",
			arn:          "",
			resourceName: "hipaa-compliant-data",
			tags:         nil,
			kmsEncrypted: false,
			want:         true,
		},
		{
			name:         "gdpr in name",
			arn:          "",
			resourceName: "gdpr-protected-data",
			tags:         nil,
			kmsEncrypted: false,
			want:         true,
		},
		{
			name:         "model weights in name",
			arn:          "",
			resourceName: "ml-model-weights",
			tags:         nil,
			kmsEncrypted: false,
			want:         true,
		},

		// Positive matches in tags
		{
			name:         "production tag value",
			arn:          "",
			resourceName: "generic-bucket",
			tags:         []map[string]string{{"Key": "Environment", "Value": "production"}},
			kmsEncrypted: false,
			want:         true,
		},
		{
			name:         "pii classification tag",
			arn:          "",
			resourceName: "generic-bucket",
			tags:         []map[string]string{{"Key": "Classification", "Value": "PII"}},
			kmsEncrypted: false,
			want:         true,
		},

		// Negative regex matches override positives
		{
			name:         "test environment overrides positive",
			arn:          "",
			resourceName: "test-customer-data",
			tags:         nil,
			kmsEncrypted: false,
			want:         false,
		},
		{
			name:         "dev environment overrides positive",
			arn:          "",
			resourceName: "dev-production-backup",
			tags:         nil,
			kmsEncrypted: false,
			want:         false,
		},
		{
			name:         "staging overrides positive",
			arn:          "",
			resourceName: "staging-customer-bucket",
			tags:         nil,
			kmsEncrypted: false,
			want:         false,
		},
		{
			name:         "sandbox overrides positive",
			arn:          "",
			resourceName: "sandbox-pii-test",
			tags:         nil,
			kmsEncrypted: false,
			want:         false,
		},
		{
			name:         "demo overrides positive",
			arn:          "",
			resourceName: "demo-financial-app",
			tags:         nil,
			kmsEncrypted: false,
			want:         false,
		},
		{
			name:         "backup overrides positive",
			arn:          "",
			resourceName: "backup-old-credentials",
			tags:         nil,
			kmsEncrypted: false,
			want:         false,
		},
		{
			name:         "archive overrides positive",
			arn:          "",
			resourceName: "archive-production-2020",
			tags:         nil,
			kmsEncrypted: false,
			want:         false,
		},
		{
			name:         "tmp overrides positive",
			arn:          "",
			resourceName: "tmp-customer-upload",
			tags:         nil,
			kmsEncrypted: false,
			want:         false,
		},
		{
			name:         "training overrides model weights",
			arn:          "",
			resourceName: "training-model-weights",
			tags:         nil,
			kmsEncrypted: false,
			want:         false,
		},

		// Negative tag overrides positive name
		{
			name:         "test tag overrides production name",
			arn:          "",
			resourceName: "production-data",
			tags:         []map[string]string{{"Key": "Environment", "Value": "test"}},
			kmsEncrypted: false,
			want:         false,
		},
		{
			name:         "dev tag overrides customer name",
			arn:          "",
			resourceName: "customer-data",
			tags:         []map[string]string{{"Key": "Stage", "Value": "development"}},
			kmsEncrypted: false,
			want:         false,
		},

		// No match cases
		{
			name:         "generic bucket name no tags",
			arn:          "",
			resourceName: "my-app-bucket-12345",
			tags:         nil,
			kmsEncrypted: false,
			want:         false,
		},
		{
			name:         "logs bucket",
			arn:          "",
			resourceName: "access-logs-2024",
			tags:         nil,
			kmsEncrypted: false,
			want:         false,
		},
		{
			name:         "static assets bucket",
			arn:          "",
			resourceName: "static-assets-cdn",
			tags:         nil,
			kmsEncrypted: false,
			want:         false,
		},

		// Edge cases
		{
			name:         "empty name no tags no encryption",
			arn:          "",
			resourceName: "",
			tags:         nil,
			kmsEncrypted: false,
			want:         false,
		},
		{
			name:         "underscore separator production",
			arn:          "",
			resourceName: "app_production_data",
			tags:         nil,
			kmsEncrypted: false,
			want:         true,
		},
		{
			name:         "case insensitive PRODUCTION",
			arn:          "",
			resourceName: "PRODUCTION-DATA",
			tags:         nil,
			kmsEncrypted: false,
			want:         true,
		},
		{
			name:         "case insensitive PII",
			arn:          "",
			resourceName: "data-with-PII",
			tags:         nil,
			kmsEncrypted: false,
			want:         true,
		},

		// Complex scenarios
		{
			name:         "prod-test combination (negative wins)",
			arn:          "",
			resourceName: "prod-test-data",
			tags:         nil,
			kmsEncrypted: false,
			want:         false,
		},
		{
			name:         "main database",
			arn:          "",
			resourceName: "main-database-backup",
			tags:         nil,
			kmsEncrypted: false,
			want:         false, // backup negates main
		},
		{
			name:         "primary data store",
			arn:          "",
			resourceName: "primary-data-store",
			tags:         nil,
			kmsEncrypted: false,
			want:         true,
		},
		// User-specified ARN jewels
		{
			name:         "user-specified ARN jewel",
			arn:          "arn:aws:s3:::my-sensitive-data-bucket",
			resourceName: "testing-bucket",
			tags:         nil,
			kmsEncrypted: false,
			want:         true,
		},
		{
			name:         "user-specified ARN jewel",
			arn:          "arn:aws:rds:::my-sensitive-data-db",
			resourceName: "testing-db",
			tags:         nil,
			kmsEncrypted: false,
			want:         true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsCrownJewel(tt.arn, tt.resourceName, tt.tags, tt.kmsEncrypted)
			if got != tt.want {
				t.Errorf("IsCrownJewel(%q, %v, %v) = %v, want %v",
					tt.resourceName, tt.tags, tt.kmsEncrypted, got, tt.want)
			}
		})
	}
}

// =============================================================================
// REGEX PATTERN TESTS
// =============================================================================

func TestCrownJewelPositiveRegex(t *testing.T) {
	positivePatterns := []string{
		// Environment indicators
		"prod", "production", "live", "main", "master", "primary", "real",
		// Data sensitivity indicators
		"customer", "cust", "client", "user", "userdata",
		"pii", "phi", "sensitive", "secret", "confidential", "classified",
		"secure", "vault", "keystore", "token", "credentials", "password",
		// Financial indicators
		"payment", "billing", "finance", "financial", "revenue", "salary", "payroll",
		"ssn", "creditcard", "transaction", "order", "invoice",
		// Healthcare/legal
		"policy", "claim", "medical", "health", "record",
		// Identity
		"account", "personal", "identity", "authentication", "authorization", "login", "passport",
		// Compliance
		"gov", "tax", "irs", "pci", "hipaa", "gdpr", "restricted", "critical",
		// Infrastructure
		"core", "backend", "mainframe", "ledger", "bank", "crypto", "wallet",
		// ML/IP
		"model", "weights", "ip",
	}

	for _, pattern := range positivePatterns {
		t.Run("matches_"+pattern, func(t *testing.T) {
			// Test with word boundary (underscore)
			testName := "bucket_" + pattern + "_data"
			if !GetPositiveRegex().MatchString(testName) {
				t.Errorf("Expected positive regex to match %q", testName)
			}
		})
	}
}

func TestCrownJewelNegativeRegex(t *testing.T) {
	negativePatterns := []string{
		// Environment indicators
		"test", "testing", "tests", "dev", "development", "staging", "sandbox",
		"sample", "demo", "training", "train",
		// Temporary/old
		"tmp", "temp", "backup", "old", "archive",
		// Non-production
		"mock", "example", "prototype", "practice", "draft",
		"qa", "uat", "performance", "perf", "loadtest",
		"experiment", "scratch", "trial",
	}

	for _, pattern := range negativePatterns {
		t.Run("matches_"+pattern, func(t *testing.T) {
			// Test with word boundary (underscore)
			testName := "bucket_" + pattern + "_data"
			if !GetNegativeRegex().MatchString(testName) {
				t.Errorf("Expected negative regex to match %q", testName)
			}
		})
	}
}
