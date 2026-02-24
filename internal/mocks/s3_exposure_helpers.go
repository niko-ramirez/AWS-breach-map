// Package mocks provides test helpers for building S3 exposure test scenarios.
package mocks

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// =============================================================================
// Bucket Policy Builder
// =============================================================================

// BucketPolicyBuilder provides a fluent API for building test bucket policies.
type BucketPolicyBuilder struct {
	statements []map[string]interface{}
}

// NewBucketPolicyBuilder creates a new bucket policy builder.
func NewBucketPolicyBuilder() *BucketPolicyBuilder {
	return &BucketPolicyBuilder{
		statements: make([]map[string]interface{}, 0),
	}
}

// AllowPublicGetObject adds a statement allowing public s3:GetObject (attack vector 1.1)
func (b *BucketPolicyBuilder) AllowPublicGetObject(bucketName string) *BucketPolicyBuilder {
	b.statements = append(b.statements, map[string]interface{}{
		"Sid":       "PublicReadGetObject",
		"Effect":    "Allow",
		"Principal": "*",
		"Action":    "s3:GetObject",
		"Resource":  fmt.Sprintf("arn:aws:s3:::%s/*", bucketName),
	})
	return b
}

// AllowPublicAll adds a statement allowing all S3 actions publicly (attack vector 1.3)
func (b *BucketPolicyBuilder) AllowPublicAll(bucketName string) *BucketPolicyBuilder {
	b.statements = append(b.statements, map[string]interface{}{
		"Sid":       "PublicFullAccess",
		"Effect":    "Allow",
		"Principal": "*",
		"Action":    "s3:*",
		"Resource": []string{
			fmt.Sprintf("arn:aws:s3:::%s", bucketName),
			fmt.Sprintf("arn:aws:s3:::%s/*", bucketName),
		},
	})
	return b
}

// AllowPrincipal adds a statement allowing a specific principal
func (b *BucketPolicyBuilder) AllowPrincipal(principalARN string, actions []string, bucketName string) *BucketPolicyBuilder {
	b.statements = append(b.statements, map[string]interface{}{
		"Sid":       "AllowSpecificPrincipal",
		"Effect":    "Allow",
		"Principal": map[string]interface{}{"AWS": principalARN},
		"Action":    actions,
		"Resource": []string{
			fmt.Sprintf("arn:aws:s3:::%s", bucketName),
			fmt.Sprintf("arn:aws:s3:::%s/*", bucketName),
		},
	})
	return b
}

// DenyPrincipal adds a statement denying a specific principal (attack vector 9.1)
func (b *BucketPolicyBuilder) DenyPrincipal(principalARN string, actions []string, bucketName string) *BucketPolicyBuilder {
	b.statements = append(b.statements, map[string]interface{}{
		"Sid":       "DenySpecificPrincipal",
		"Effect":    "Deny",
		"Principal": map[string]interface{}{"AWS": principalARN},
		"Action":    actions,
		"Resource": []string{
			fmt.Sprintf("arn:aws:s3:::%s", bucketName),
			fmt.Sprintf("arn:aws:s3:::%s/*", bucketName),
		},
	})
	return b
}

// WithOrgCondition adds an org restriction condition (attack vector 1.4)
func (b *BucketPolicyBuilder) WithOrgCondition(orgID string, bucketName string) *BucketPolicyBuilder {
	b.statements = append(b.statements, map[string]interface{}{
		"Sid":       "OrgRestricted",
		"Effect":    "Allow",
		"Principal": "*",
		"Action":    "s3:GetObject",
		"Resource":  fmt.Sprintf("arn:aws:s3:::%s/*", bucketName),
		"Condition": map[string]interface{}{
			"StringEquals": map[string]interface{}{
				"aws:PrincipalOrgID": orgID,
			},
		},
	})
	return b
}

// WithVPCCondition adds a VPC restriction condition (attack vector 1.5)
func (b *BucketPolicyBuilder) WithVPCCondition(vpcID string, bucketName string) *BucketPolicyBuilder {
	b.statements = append(b.statements, map[string]interface{}{
		"Sid":       "VPCRestricted",
		"Effect":    "Allow",
		"Principal": "*",
		"Action":    "s3:GetObject",
		"Resource":  fmt.Sprintf("arn:aws:s3:::%s/*", bucketName),
		"Condition": map[string]interface{}{
			"StringEquals": map[string]interface{}{
				"aws:SourceVpc": vpcID,
			},
		},
	})
	return b
}

// WithIPCondition adds an IP restriction condition (attack vector 1.6)
func (b *BucketPolicyBuilder) WithIPCondition(ipRange string, bucketName string) *BucketPolicyBuilder {
	b.statements = append(b.statements, map[string]interface{}{
		"Sid":       "IPRestricted",
		"Effect":    "Allow",
		"Principal": "*",
		"Action":    "s3:GetObject",
		"Resource":  fmt.Sprintf("arn:aws:s3:::%s/*", bucketName),
		"Condition": map[string]interface{}{
			"IpAddress": map[string]interface{}{
				"aws:SourceIp": ipRange,
			},
		},
	})
	return b
}

// DenyFromVPC adds a statement denying access from a specific VPC
func (b *BucketPolicyBuilder) DenyFromVPC(vpcID string, bucketName string) *BucketPolicyBuilder {
	b.statements = append(b.statements, map[string]interface{}{
		"Sid":       "DenyFromVPC",
		"Effect":    "Deny",
		"Principal": "*",
		"Action":    "s3:*",
		"Resource": []string{
			fmt.Sprintf("arn:aws:s3:::%s", bucketName),
			fmt.Sprintf("arn:aws:s3:::%s/*", bucketName),
		},
		"Condition": map[string]interface{}{
			"StringEquals": map[string]interface{}{
				"aws:SourceVpc": vpcID,
			},
		},
	})
	return b
}

// Build returns the policy as a JSON string
func (b *BucketPolicyBuilder) Build() string {
	policy := map[string]interface{}{
		"Version":   "2012-10-17",
		"Statement": b.statements,
	}
	jsonBytes, _ := json.Marshal(policy)
	return string(jsonBytes)
}

// BuildOutput returns the policy wrapped in GetBucketPolicyOutput
func (b *BucketPolicyBuilder) BuildOutput() *s3.GetBucketPolicyOutput {
	policy := b.Build()
	return &s3.GetBucketPolicyOutput{
		Policy: aws.String(policy),
	}
}

// =============================================================================
// ACL Builder
// =============================================================================

// ACLBuilder provides a fluent API for building test bucket ACLs.
type ACLBuilder struct {
	grants []s3types.Grant
	owner  *s3types.Owner
}

// NewACLBuilder creates a new ACL builder with default owner.
func NewACLBuilder() *ACLBuilder {
	return &ACLBuilder{
		grants: make([]s3types.Grant, 0),
		owner: &s3types.Owner{
			ID:          aws.String("owner-canonical-id"),
			DisplayName: aws.String("owner"),
		},
	}
}

// GrantAllUsersRead adds AllUsers READ permission (attack vector 2.1)
func (b *ACLBuilder) GrantAllUsersRead() *ACLBuilder {
	b.grants = append(b.grants, s3types.Grant{
		Grantee: &s3types.Grantee{
			Type: s3types.TypeGroup,
			URI:  aws.String("http://acs.amazonaws.com/groups/global/AllUsers"),
		},
		Permission: s3types.PermissionRead,
	})
	return b
}

// GrantAllUsersWrite adds AllUsers WRITE permission (attack vector 2.2)
func (b *ACLBuilder) GrantAllUsersWrite() *ACLBuilder {
	b.grants = append(b.grants, s3types.Grant{
		Grantee: &s3types.Grantee{
			Type: s3types.TypeGroup,
			URI:  aws.String("http://acs.amazonaws.com/groups/global/AllUsers"),
		},
		Permission: s3types.PermissionWrite,
	})
	return b
}

// GrantAllUsersFullControl adds AllUsers FULL_CONTROL permission (attack vector 2.3)
func (b *ACLBuilder) GrantAllUsersFullControl() *ACLBuilder {
	b.grants = append(b.grants, s3types.Grant{
		Grantee: &s3types.Grantee{
			Type: s3types.TypeGroup,
			URI:  aws.String("http://acs.amazonaws.com/groups/global/AllUsers"),
		},
		Permission: s3types.PermissionFullControl,
	})
	return b
}

// GrantAuthenticatedUsersRead adds AuthenticatedUsers READ permission (attack vector 2.4)
func (b *ACLBuilder) GrantAuthenticatedUsersRead() *ACLBuilder {
	b.grants = append(b.grants, s3types.Grant{
		Grantee: &s3types.Grantee{
			Type: s3types.TypeGroup,
			URI:  aws.String("http://acs.amazonaws.com/groups/global/AuthenticatedUsers"),
		},
		Permission: s3types.PermissionRead,
	})
	return b
}

// GrantAuthenticatedUsersWrite adds AuthenticatedUsers WRITE permission (attack vector 2.5)
func (b *ACLBuilder) GrantAuthenticatedUsersWrite() *ACLBuilder {
	b.grants = append(b.grants, s3types.Grant{
		Grantee: &s3types.Grantee{
			Type: s3types.TypeGroup,
			URI:  aws.String("http://acs.amazonaws.com/groups/global/AuthenticatedUsers"),
		},
		Permission: s3types.PermissionWrite,
	})
	return b
}

// GrantCanonicalUser adds a grant for a specific canonical user
func (b *ACLBuilder) GrantCanonicalUser(canonicalID string, permission s3types.Permission) *ACLBuilder {
	b.grants = append(b.grants, s3types.Grant{
		Grantee: &s3types.Grantee{
			Type: s3types.TypeCanonicalUser,
			ID:   aws.String(canonicalID),
		},
		Permission: permission,
	})
	return b
}

// Build returns the ACL as GetBucketAclOutput
func (b *ACLBuilder) Build() *s3.GetBucketAclOutput {
	return &s3.GetBucketAclOutput{
		Owner:  b.owner,
		Grants: b.grants,
	}
}

// =============================================================================
// Public Access Block (PAB) Builder
// =============================================================================

// PABBuilder provides a fluent API for building Public Access Block configurations.
type PABBuilder struct {
	blockPublicAcls       bool
	ignorePublicAcls      bool
	blockPublicPolicy     bool
	restrictPublicBuckets bool
}

// NewPABBuilder creates a new PAB builder with default (all false).
func NewPABBuilder() *PABBuilder {
	return &PABBuilder{}
}

// BlockAll enables all PAB settings (secure configuration)
func (b *PABBuilder) BlockAll() *PABBuilder {
	b.blockPublicAcls = true
	b.ignorePublicAcls = true
	b.blockPublicPolicy = true
	b.restrictPublicBuckets = true
	return b
}

// AllowAll disables all PAB settings (attack vector 3.1)
func (b *PABBuilder) AllowAll() *PABBuilder {
	b.blockPublicAcls = false
	b.ignorePublicAcls = false
	b.blockPublicPolicy = false
	b.restrictPublicBuckets = false
	return b
}

// BlockPublicAcls sets BlockPublicAcls
func (b *PABBuilder) BlockPublicAcls(value bool) *PABBuilder {
	b.blockPublicAcls = value
	return b
}

// IgnorePublicAcls sets IgnorePublicAcls
func (b *PABBuilder) IgnorePublicAcls(value bool) *PABBuilder {
	b.ignorePublicAcls = value
	return b
}

// BlockPublicPolicy sets BlockPublicPolicy
func (b *PABBuilder) BlockPublicPolicy(value bool) *PABBuilder {
	b.blockPublicPolicy = value
	return b
}

// RestrictPublicBuckets sets RestrictPublicBuckets
func (b *PABBuilder) RestrictPublicBuckets(value bool) *PABBuilder {
	b.restrictPublicBuckets = value
	return b
}

// Build returns the PAB as GetPublicAccessBlockOutput
func (b *PABBuilder) Build() *s3.GetPublicAccessBlockOutput {
	return &s3.GetPublicAccessBlockOutput{
		PublicAccessBlockConfiguration: &s3types.PublicAccessBlockConfiguration{
			BlockPublicAcls:       aws.Bool(b.blockPublicAcls),
			IgnorePublicAcls:      aws.Bool(b.ignorePublicAcls),
			BlockPublicPolicy:     aws.Bool(b.blockPublicPolicy),
			RestrictPublicBuckets: aws.Bool(b.restrictPublicBuckets),
		},
	}
}

// =============================================================================
// Pre-built Exposure Scenarios
// =============================================================================

// ExposureScenarios contains pre-built mock configurations for exposure testing
var ExposureScenarios = struct {
	// PublicBucketPolicy: Bucket with public policy (Principal: "*")
	PublicBucketPolicy func(bucketName string) *MockS3Client
	// PublicACL: Bucket with AllUsers READ ACL
	PublicACL func() *MockS3Client
	// PrivateFullPAB: Private bucket with full PAB blocking
	PrivateFullPAB func() *MockS3Client
	// OrgRestricted: Bucket with org restriction
	OrgRestricted func(bucketName, orgID string) *MockS3Client
	// VPCRestricted: Bucket with VPC restriction
	VPCRestricted func(bucketName, vpcID string) *MockS3Client
}{
	PublicBucketPolicy: func(bucketName string) *MockS3Client {
		policy := NewBucketPolicyBuilder().AllowPublicGetObject(bucketName).Build()
		return &MockS3Client{
			GetBucketPolicyFunc: func(ctx context.Context, params *s3.GetBucketPolicyInput, optFns ...func(*s3.Options)) (*s3.GetBucketPolicyOutput, error) {
				return &s3.GetBucketPolicyOutput{Policy: aws.String(policy)}, nil
			},
			GetPublicAccessBlockFunc: func(ctx context.Context, params *s3.GetPublicAccessBlockInput, optFns ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error) {
				return NewPABBuilder().AllowAll().Build(), nil
			},
			GetBucketAclFunc: func(ctx context.Context, params *s3.GetBucketAclInput, optFns ...func(*s3.Options)) (*s3.GetBucketAclOutput, error) {
				return NewACLBuilder().Build(), nil // Private ACL
			},
		}
	},
	PublicACL: func() *MockS3Client {
		return &MockS3Client{
			GetBucketPolicyFunc: func(ctx context.Context, params *s3.GetBucketPolicyInput, optFns ...func(*s3.Options)) (*s3.GetBucketPolicyOutput, error) {
				return &s3.GetBucketPolicyOutput{}, nil // No policy
			},
			GetPublicAccessBlockFunc: func(ctx context.Context, params *s3.GetPublicAccessBlockInput, optFns ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error) {
				return NewPABBuilder().AllowAll().Build(), nil
			},
			GetBucketAclFunc: func(ctx context.Context, params *s3.GetBucketAclInput, optFns ...func(*s3.Options)) (*s3.GetBucketAclOutput, error) {
				return NewACLBuilder().GrantAllUsersRead().Build(), nil
			},
		}
	},
	PrivateFullPAB: func() *MockS3Client {
		return &MockS3Client{
			GetBucketPolicyFunc: func(ctx context.Context, params *s3.GetBucketPolicyInput, optFns ...func(*s3.Options)) (*s3.GetBucketPolicyOutput, error) {
				return &s3.GetBucketPolicyOutput{}, nil
			},
			GetPublicAccessBlockFunc: func(ctx context.Context, params *s3.GetPublicAccessBlockInput, optFns ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error) {
				return NewPABBuilder().BlockAll().Build(), nil
			},
			GetBucketAclFunc: func(ctx context.Context, params *s3.GetBucketAclInput, optFns ...func(*s3.Options)) (*s3.GetBucketAclOutput, error) {
				return NewACLBuilder().Build(), nil
			},
		}
	},
	OrgRestricted: func(bucketName, orgID string) *MockS3Client {
		policy := NewBucketPolicyBuilder().WithOrgCondition(orgID, bucketName).Build()
		return &MockS3Client{
			GetBucketPolicyFunc: func(ctx context.Context, params *s3.GetBucketPolicyInput, optFns ...func(*s3.Options)) (*s3.GetBucketPolicyOutput, error) {
				return &s3.GetBucketPolicyOutput{Policy: aws.String(policy)}, nil
			},
			GetPublicAccessBlockFunc: func(ctx context.Context, params *s3.GetPublicAccessBlockInput, optFns ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error) {
				return NewPABBuilder().AllowAll().Build(), nil
			},
			GetBucketAclFunc: func(ctx context.Context, params *s3.GetBucketAclInput, optFns ...func(*s3.Options)) (*s3.GetBucketAclOutput, error) {
				return NewACLBuilder().Build(), nil
			},
		}
	},
	VPCRestricted: func(bucketName, vpcID string) *MockS3Client {
		policy := NewBucketPolicyBuilder().WithVPCCondition(vpcID, bucketName).Build()
		return &MockS3Client{
			GetBucketPolicyFunc: func(ctx context.Context, params *s3.GetBucketPolicyInput, optFns ...func(*s3.Options)) (*s3.GetBucketPolicyOutput, error) {
				return &s3.GetBucketPolicyOutput{Policy: aws.String(policy)}, nil
			},
			GetPublicAccessBlockFunc: func(ctx context.Context, params *s3.GetPublicAccessBlockInput, optFns ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error) {
				return NewPABBuilder().AllowAll().Build(), nil
			},
			GetBucketAclFunc: func(ctx context.Context, params *s3.GetBucketAclInput, optFns ...func(*s3.Options)) (*s3.GetBucketAclOutput, error) {
				return NewACLBuilder().Build(), nil
			},
		}
	},
}

