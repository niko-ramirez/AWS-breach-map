// Package mocks provides test helpers for building S3 test scenarios.
package mocks

import (
	"context"
	"fmt"

	"breachmap/internal/domain"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// =============================================================================
// S3CrownJewel Builder - Fluent API for creating test S3CrownJewel objects
// =============================================================================

// S3JewelBuilder provides a fluent API for building test S3CrownJewel objects.
type S3JewelBuilder struct {
	jewel domain.S3CrownJewel
}

// NewS3JewelBuilder creates a new builder with default values.
// Default: unencrypted bucket
func NewS3JewelBuilder(name string) *S3JewelBuilder {
	encrypted := false

	return &S3JewelBuilder{
		jewel: domain.S3CrownJewel{
			ARN:          fmt.Sprintf("arn:aws:s3:::%s", name),
			ResourceType: "S3",
			Name:         name,
			Encrypted:    &encrypted,
		},
	}
}

// WithARN sets a custom ARN
func (b *S3JewelBuilder) WithARN(arn string) *S3JewelBuilder {
	b.jewel.ARN = arn
	return b
}

// Encrypted marks the bucket as KMS encrypted
func (b *S3JewelBuilder) Encrypted(kmsKeyID string) *S3JewelBuilder {
	encrypted := true
	b.jewel.Encrypted = &encrypted
	b.jewel.KMSKeyID = &kmsKeyID
	return b
}

// Unencrypted marks the bucket as unencrypted (default)
func (b *S3JewelBuilder) Unencrypted() *S3JewelBuilder {
	encrypted := false
	b.jewel.Encrypted = &encrypted
	b.jewel.KMSKeyID = nil
	return b
}

// SSES3Encrypted marks the bucket as SSE-S3 encrypted (AES-256)
func (b *S3JewelBuilder) SSES3Encrypted() *S3JewelBuilder {
	encrypted := true
	b.jewel.Encrypted = &encrypted
	b.jewel.KMSKeyID = nil // SSE-S3 doesn't have a KMS key ID
	return b
}

// Build returns the constructed S3CrownJewel
func (b *S3JewelBuilder) Build() domain.S3CrownJewel {
	return b.jewel
}

// =============================================================================
// Pre-built Test Scenarios
// =============================================================================

// TestS3Scenarios contains pre-built S3CrownJewel objects for common test cases
var TestS3Scenarios = struct {
	// PublicUnencrypted: Worst case - public bucket, no encryption
	PublicUnencrypted func() domain.S3CrownJewel
	// PublicKMSEncrypted: Public bucket with KMS encryption
	PublicKMSEncrypted func() domain.S3CrownJewel
	// PrivateUnencrypted: Private but no encryption
	PrivateUnencrypted func() domain.S3CrownJewel
	// PrivateKMSEncrypted: Ideal case - private with KMS encryption
	PrivateKMSEncrypted func() domain.S3CrownJewel
	// PrivateSSES3Encrypted: Private with SSE-S3 (AES-256) encryption
	PrivateSSES3Encrypted func() domain.S3CrownJewel
}{
	PublicUnencrypted: func() domain.S3CrownJewel {
		return NewS3JewelBuilder("public-unencrypted-bucket").
			Unencrypted().
			Build()
	},
	PublicKMSEncrypted: func() domain.S3CrownJewel {
		return NewS3JewelBuilder("public-kms-encrypted-bucket").
			Encrypted("arn:aws:kms:us-east-1:123456789012:key/test-key-1").
			Build()
	},
	PrivateUnencrypted: func() domain.S3CrownJewel {
		return NewS3JewelBuilder("private-unencrypted-bucket").
			Unencrypted().
			Build()
	},
	PrivateKMSEncrypted: func() domain.S3CrownJewel {
		return NewS3JewelBuilder("private-kms-encrypted-bucket").
			Encrypted("arn:aws:kms:us-east-1:123456789012:key/test-key-2").
			Build()
	},
	PrivateSSES3Encrypted: func() domain.S3CrownJewel {
		return NewS3JewelBuilder("private-sses3-encrypted-bucket").
			SSES3Encrypted().
			Build()
	},
}

// =============================================================================
// Mock S3 Client Helpers
// =============================================================================

// NewMockS3ClientWithBuckets creates a mock that returns the specified buckets from ListBuckets
func NewMockS3ClientWithBuckets(bucketNames ...string) *MockS3Client {
	buckets := make([]s3types.Bucket, len(bucketNames))
	for i, name := range bucketNames {
		buckets[i] = s3types.Bucket{
			Name: aws.String(name),
		}
	}

	return &MockS3Client{
		ListBucketsFunc: func(
			ctx context.Context,
			params *s3.ListBucketsInput,
			optFns ...func(*s3.Options),
		) (*s3.ListBucketsOutput, error) {
			return &s3.ListBucketsOutput{
				Buckets: buckets,
			}, nil
		},
	}
}

// NewMockS3ClientNoPAB creates a mock that returns no Public Access Block config
// This simulates a bucket without PAB (attack vector 3.1)
func NewMockS3ClientNoPAB() *MockS3Client {
	return &MockS3Client{
		GetPublicAccessBlockFunc: func(
			ctx context.Context,
			params *s3.GetPublicAccessBlockInput,
			optFns ...func(*s3.Options),
		) (*s3.GetPublicAccessBlockOutput, error) {
			// Return config with all flags false (no blocking)
			return &s3.GetPublicAccessBlockOutput{
				PublicAccessBlockConfiguration: &s3types.PublicAccessBlockConfiguration{
					BlockPublicAcls:       aws.Bool(false),
					IgnorePublicAcls:      aws.Bool(false),
					BlockPublicPolicy:     aws.Bool(false),
					RestrictPublicBuckets: aws.Bool(false),
				},
			}, nil
		},
	}
}

// NewMockS3ClientFullPAB creates a mock that returns fully blocking PAB config
// This simulates a secure bucket configuration
func NewMockS3ClientFullPAB() *MockS3Client {
	return &MockS3Client{
		GetPublicAccessBlockFunc: func(
			ctx context.Context,
			params *s3.GetPublicAccessBlockInput,
			optFns ...func(*s3.Options),
		) (*s3.GetPublicAccessBlockOutput, error) {
			return &s3.GetPublicAccessBlockOutput{
				PublicAccessBlockConfiguration: &s3types.PublicAccessBlockConfiguration{
					BlockPublicAcls:       aws.Bool(true),
					IgnorePublicAcls:      aws.Bool(true),
					BlockPublicPolicy:     aws.Bool(true),
					RestrictPublicBuckets: aws.Bool(true),
				},
			}, nil
		},
	}
}

// =============================================================================
// Test Data Helpers
// =============================================================================

// TestBucketARN generates a test bucket ARN
func TestBucketARN(bucketName string) string {
	return fmt.Sprintf("arn:aws:s3:::%s", bucketName)
}

// TestObjectARN generates a test object ARN (bucket/*)
func TestObjectARN(bucketName string) string {
	return fmt.Sprintf("arn:aws:s3:::%s/*", bucketName)
}

// TestS3CMKMap creates a resource-to-CMK mapping for S3 testing
func TestS3CMKMap(mappings map[string]string) map[string]map[string]string {
	return map[string]map[string]string{
		"S3": mappings,
	}
}

// TestBucketToRolesMap creates a bucket-to-roles mapping for testing
func TestBucketToRolesMap(bucketARN string, roleARNs ...string) map[string][]string {
	return map[string][]string{
		bucketARN: roleARNs,
	}
}

// S3EncryptionConfig creates an S3 encryption configuration for mocking
func S3EncryptionConfig(sseAlgorithm string, kmsKeyID *string) *s3.GetBucketEncryptionOutput {
	return &s3.GetBucketEncryptionOutput{
		ServerSideEncryptionConfiguration: &s3types.ServerSideEncryptionConfiguration{
			Rules: []s3types.ServerSideEncryptionRule{
				{
					ApplyServerSideEncryptionByDefault: &s3types.ServerSideEncryptionByDefault{
						SSEAlgorithm:   s3types.ServerSideEncryption(sseAlgorithm),
						KMSMasterKeyID: kmsKeyID,
					},
				},
			},
		},
	}
}

// S3KMSEncryptionConfig creates KMS encryption configuration
func S3KMSEncryptionConfig(kmsKeyID string) *s3.GetBucketEncryptionOutput {
	return S3EncryptionConfig("aws:kms", aws.String(kmsKeyID))
}

// S3SSES3EncryptionConfig creates SSE-S3 (AES256) encryption configuration
func S3SSES3EncryptionConfig() *s3.GetBucketEncryptionOutput {
	return S3EncryptionConfig("AES256", nil)
}
