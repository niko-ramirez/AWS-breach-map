// Package mocks provides mock implementations of AWS service clients for testing.
package mocks

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// =============================================================================
// RDS Interfaces
// =============================================================================

// RDSDescribeDBInstances defines the interface for RDS DescribeDBInstances operation.
// This is the only RDS method currently used in rdsbuilder.go
type RDSDescribeDBInstances interface {
	DescribeDBInstances(
		ctx context.Context,
		params *rds.DescribeDBInstancesInput,
		optFns ...func(*rds.Options),
	) (*rds.DescribeDBInstancesOutput, error)
}

// =============================================================================
// IAM Interfaces
// =============================================================================

// IAMSimulatePrincipalPolicy defines the interface for IAM SimulatePrincipalPolicy operation.
// Used for authorization verification in VerifyRDSAuthorization and VerifyS3Authorization.
type IAMSimulatePrincipalPolicy interface {
	SimulatePrincipalPolicy(
		ctx context.Context,
		params *iam.SimulatePrincipalPolicyInput,
		optFns ...func(*iam.Options),
	) (*iam.SimulatePrincipalPolicyOutput, error)
}

// =============================================================================
// S3 Interfaces
// =============================================================================

// S3GetBucketPolicy defines the interface for S3 GetBucketPolicy operation.
// Used to retrieve bucket policies for exposure analysis.
type S3GetBucketPolicy interface {
	GetBucketPolicy(
		ctx context.Context,
		params *s3.GetBucketPolicyInput,
		optFns ...func(*s3.Options),
	) (*s3.GetBucketPolicyOutput, error)
}

// S3GetBucketAcl defines the interface for S3 GetBucketAcl operation.
// Used to check ACL-based exposure (AllUsers, AuthenticatedUsers grants).
type S3GetBucketAcl interface {
	GetBucketAcl(
		ctx context.Context,
		params *s3.GetBucketAclInput,
		optFns ...func(*s3.Options),
	) (*s3.GetBucketAclOutput, error)
}

// S3GetPublicAccessBlock defines the interface for S3 GetPublicAccessBlock operation.
// Used to check Public Access Block configuration.
type S3GetPublicAccessBlock interface {
	GetPublicAccessBlock(
		ctx context.Context,
		params *s3.GetPublicAccessBlockInput,
		optFns ...func(*s3.Options),
	) (*s3.GetPublicAccessBlockOutput, error)
}

// S3GetBucketPolicyStatus defines the interface for S3 GetBucketPolicyStatus operation.
// Used to check if bucket policy is public.
type S3GetBucketPolicyStatus interface {
	GetBucketPolicyStatus(
		ctx context.Context,
		params *s3.GetBucketPolicyStatusInput,
		optFns ...func(*s3.Options),
	) (*s3.GetBucketPolicyStatusOutput, error)
}

// S3GetBucketEncryption defines the interface for S3 GetBucketEncryption operation.
// Used to check encryption configuration and KMS key.
type S3GetBucketEncryption interface {
	GetBucketEncryption(
		ctx context.Context,
		params *s3.GetBucketEncryptionInput,
		optFns ...func(*s3.Options),
	) (*s3.GetBucketEncryptionOutput, error)
}

// S3GetBucketLocation defines the interface for S3 GetBucketLocation operation.
// Used to determine bucket region for KMS key ARN construction.
type S3GetBucketLocation interface {
	GetBucketLocation(
		ctx context.Context,
		params *s3.GetBucketLocationInput,
		optFns ...func(*s3.Options),
	) (*s3.GetBucketLocationOutput, error)
}

// S3GetBucketTagging defines the interface for S3 GetBucketTagging operation.
// Used for crown jewel detection based on tags.
type S3GetBucketTagging interface {
	GetBucketTagging(
		ctx context.Context,
		params *s3.GetBucketTaggingInput,
		optFns ...func(*s3.Options),
	) (*s3.GetBucketTaggingOutput, error)
}

// S3ListBuckets defines the interface for S3 ListBuckets operation.
// Used to enumerate all buckets in the account.
type S3ListBuckets interface {
	ListBuckets(
		ctx context.Context,
		params *s3.ListBucketsInput,
		optFns ...func(*s3.Options),
	) (*s3.ListBucketsOutput, error)
}

// S3BucketOperations combines all S3 interfaces needed for breach path detection.
// This is the main interface to use when mocking the S3 client.
type S3BucketOperations interface {
	S3GetBucketPolicy
	S3GetBucketAcl
	S3GetPublicAccessBlock
	S3GetBucketPolicyStatus
	S3GetBucketEncryption
	S3GetBucketLocation
	S3GetBucketTagging
	S3ListBuckets
}

// =============================================================================
// KMS Interfaces
// =============================================================================

// KMSGetKeyPolicy defines the interface for KMS GetKeyPolicy operation.
// Used to check key policy for decrypt permissions.
type KMSGetKeyPolicy interface {
	GetKeyPolicy(
		ctx context.Context,
		params *kms.GetKeyPolicyInput,
		optFns ...func(*kms.Options),
	) (*kms.GetKeyPolicyOutput, error)
}

// =============================================================================
// KMS Mock Implementation
// =============================================================================

// MockKMSClient is a mock implementation of KMSGetKeyPolicy for testing.
// Use the function fields to customize behavior for each test case.
type MockKMSClient struct {
	// GetKeyPolicyFunc is called when GetKeyPolicy is invoked.
	// If nil, returns a restrictive default policy.
	GetKeyPolicyFunc func(
		ctx context.Context,
		params *kms.GetKeyPolicyInput,
		optFns ...func(*kms.Options),
	) (*kms.GetKeyPolicyOutput, error)

	// Call count for verification
	GetKeyPolicyCallCount int

	// LastInput stores the last input for verification
	LastGetKeyPolicyInput *kms.GetKeyPolicyInput
}

// GetKeyPolicy implements KMSGetKeyPolicy interface.
func (m *MockKMSClient) GetKeyPolicy(
	ctx context.Context,
	params *kms.GetKeyPolicyInput,
	optFns ...func(*kms.Options),
) (*kms.GetKeyPolicyOutput, error) {
	m.GetKeyPolicyCallCount++
	m.LastGetKeyPolicyInput = params

	if m.GetKeyPolicyFunc != nil {
		return m.GetKeyPolicyFunc(ctx, params, optFns...)
	}

	// Default: restrictive policy (only key owner)
	defaultPolicy := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Sid": "Enable IAM policies",
			"Effect": "Allow",
			"Principal": {"AWS": "arn:aws:iam::123456789012:root"},
			"Action": "kms:*",
			"Resource": "*"
		}]
	}`
	return &kms.GetKeyPolicyOutput{
		Policy: aws.String(defaultPolicy),
	}, nil
}

// Reset clears all call counts and stored inputs
func (m *MockKMSClient) Reset() {
	m.GetKeyPolicyCallCount = 0
	m.LastGetKeyPolicyInput = nil
}

// NewMockKMSClientWithPermissivePolicy creates a mock that returns a permissive key policy
// This simulates a key with Principal: "*" allowing any principal to decrypt
func NewMockKMSClientWithPermissivePolicy() *MockKMSClient {
	return &MockKMSClient{
		GetKeyPolicyFunc: func(
			ctx context.Context,
			params *kms.GetKeyPolicyInput,
			optFns ...func(*kms.Options),
		) (*kms.GetKeyPolicyOutput, error) {
			permissivePolicy := `{
				"Version": "2012-10-17",
				"Statement": [{
					"Sid": "Allow all principals",
					"Effect": "Allow",
					"Principal": "*",
					"Action": ["kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"],
					"Resource": "*"
				}]
			}`
			return &kms.GetKeyPolicyOutput{
				Policy: aws.String(permissivePolicy),
			}, nil
		},
	}
}

// NewMockKMSClientWithSpecificPrincipals creates a mock that allows specific principals
func NewMockKMSClientWithSpecificPrincipals(principalARNs []string) *MockKMSClient {
	return &MockKMSClient{
		GetKeyPolicyFunc: func(
			ctx context.Context,
			params *kms.GetKeyPolicyInput,
			optFns ...func(*kms.Options),
		) (*kms.GetKeyPolicyOutput, error) {
			// Build principal list for policy
			principals := "["
			for i, arn := range principalARNs {
				if i > 0 {
					principals += ", "
				}
				principals += `"` + arn + `"`
			}
			principals += "]"

			policy := `{
				"Version": "2012-10-17",
				"Statement": [{
					"Sid": "Allow specific principals",
					"Effect": "Allow",
					"Principal": {"AWS": ` + principals + `},
					"Action": ["kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"],
					"Resource": "*"
				}]
			}`
			return &kms.GetKeyPolicyOutput{
				Policy: aws.String(policy),
			}, nil
		},
	}
}

// =============================================================================
// S3 Mock Implementation
// =============================================================================

// MockS3Client is a mock implementation of S3BucketOperations for testing.
// Use the function fields to customize behavior for each test case.
type MockS3Client struct {
	// GetBucketPolicyFunc is called when GetBucketPolicy is invoked.
	GetBucketPolicyFunc func(
		ctx context.Context,
		params *s3.GetBucketPolicyInput,
		optFns ...func(*s3.Options),
	) (*s3.GetBucketPolicyOutput, error)

	// GetBucketAclFunc is called when GetBucketAcl is invoked.
	GetBucketAclFunc func(
		ctx context.Context,
		params *s3.GetBucketAclInput,
		optFns ...func(*s3.Options),
	) (*s3.GetBucketAclOutput, error)

	// GetPublicAccessBlockFunc is called when GetPublicAccessBlock is invoked.
	GetPublicAccessBlockFunc func(
		ctx context.Context,
		params *s3.GetPublicAccessBlockInput,
		optFns ...func(*s3.Options),
	) (*s3.GetPublicAccessBlockOutput, error)

	// GetBucketPolicyStatusFunc is called when GetBucketPolicyStatus is invoked.
	GetBucketPolicyStatusFunc func(
		ctx context.Context,
		params *s3.GetBucketPolicyStatusInput,
		optFns ...func(*s3.Options),
	) (*s3.GetBucketPolicyStatusOutput, error)

	// GetBucketEncryptionFunc is called when GetBucketEncryption is invoked.
	GetBucketEncryptionFunc func(
		ctx context.Context,
		params *s3.GetBucketEncryptionInput,
		optFns ...func(*s3.Options),
	) (*s3.GetBucketEncryptionOutput, error)

	// GetBucketLocationFunc is called when GetBucketLocation is invoked.
	GetBucketLocationFunc func(
		ctx context.Context,
		params *s3.GetBucketLocationInput,
		optFns ...func(*s3.Options),
	) (*s3.GetBucketLocationOutput, error)

	// GetBucketTaggingFunc is called when GetBucketTagging is invoked.
	GetBucketTaggingFunc func(
		ctx context.Context,
		params *s3.GetBucketTaggingInput,
		optFns ...func(*s3.Options),
	) (*s3.GetBucketTaggingOutput, error)

	// ListBucketsFunc is called when ListBuckets is invoked.
	ListBucketsFunc func(
		ctx context.Context,
		params *s3.ListBucketsInput,
		optFns ...func(*s3.Options),
	) (*s3.ListBucketsOutput, error)

	// Call counts for verification
	GetBucketPolicyCallCount       int
	GetBucketAclCallCount          int
	GetPublicAccessBlockCallCount  int
	GetBucketPolicyStatusCallCount int
	GetBucketEncryptionCallCount   int
	GetBucketLocationCallCount     int
	GetBucketTaggingCallCount      int
	ListBucketsCallCount           int
}

// GetBucketPolicy implements S3GetBucketPolicy interface.
func (m *MockS3Client) GetBucketPolicy(
	ctx context.Context,
	params *s3.GetBucketPolicyInput,
	optFns ...func(*s3.Options),
) (*s3.GetBucketPolicyOutput, error) {
	m.GetBucketPolicyCallCount++
	if m.GetBucketPolicyFunc != nil {
		return m.GetBucketPolicyFunc(ctx, params, optFns...)
	}
	// Default: no bucket policy (simulates NoSuchBucketPolicy error behavior)
	return &s3.GetBucketPolicyOutput{}, nil
}

// GetBucketAcl implements S3GetBucketAcl interface.
func (m *MockS3Client) GetBucketAcl(
	ctx context.Context,
	params *s3.GetBucketAclInput,
	optFns ...func(*s3.Options),
) (*s3.GetBucketAclOutput, error) {
	m.GetBucketAclCallCount++
	if m.GetBucketAclFunc != nil {
		return m.GetBucketAclFunc(ctx, params, optFns...)
	}
	// Default: private ACL (owner only)
	return &s3.GetBucketAclOutput{
		Grants: []s3types.Grant{},
	}, nil
}

// GetPublicAccessBlock implements S3GetPublicAccessBlock interface.
func (m *MockS3Client) GetPublicAccessBlock(
	ctx context.Context,
	params *s3.GetPublicAccessBlockInput,
	optFns ...func(*s3.Options),
) (*s3.GetPublicAccessBlockOutput, error) {
	m.GetPublicAccessBlockCallCount++
	if m.GetPublicAccessBlockFunc != nil {
		return m.GetPublicAccessBlockFunc(ctx, params, optFns...)
	}
	// Default: all public access blocked (secure default)
	return &s3.GetPublicAccessBlockOutput{
		PublicAccessBlockConfiguration: &s3types.PublicAccessBlockConfiguration{
			BlockPublicAcls:       aws.Bool(true),
			IgnorePublicAcls:      aws.Bool(true),
			BlockPublicPolicy:     aws.Bool(true),
			RestrictPublicBuckets: aws.Bool(true),
		},
	}, nil
}

// GetBucketPolicyStatus implements S3GetBucketPolicyStatus interface.
func (m *MockS3Client) GetBucketPolicyStatus(
	ctx context.Context,
	params *s3.GetBucketPolicyStatusInput,
	optFns ...func(*s3.Options),
) (*s3.GetBucketPolicyStatusOutput, error) {
	m.GetBucketPolicyStatusCallCount++
	if m.GetBucketPolicyStatusFunc != nil {
		return m.GetBucketPolicyStatusFunc(ctx, params, optFns...)
	}
	// Default: not public
	return &s3.GetBucketPolicyStatusOutput{
		PolicyStatus: &s3types.PolicyStatus{
			IsPublic: aws.Bool(false),
		},
	}, nil
}

// GetBucketEncryption implements S3GetBucketEncryption interface.
func (m *MockS3Client) GetBucketEncryption(
	ctx context.Context,
	params *s3.GetBucketEncryptionInput,
	optFns ...func(*s3.Options),
) (*s3.GetBucketEncryptionOutput, error) {
	m.GetBucketEncryptionCallCount++
	if m.GetBucketEncryptionFunc != nil {
		return m.GetBucketEncryptionFunc(ctx, params, optFns...)
	}
	// Default: no encryption configured
	return &s3.GetBucketEncryptionOutput{}, nil
}

// GetBucketLocation implements S3GetBucketLocation interface.
func (m *MockS3Client) GetBucketLocation(
	ctx context.Context,
	params *s3.GetBucketLocationInput,
	optFns ...func(*s3.Options),
) (*s3.GetBucketLocationOutput, error) {
	m.GetBucketLocationCallCount++
	if m.GetBucketLocationFunc != nil {
		return m.GetBucketLocationFunc(ctx, params, optFns...)
	}
	// Default: us-east-1 (empty LocationConstraint means us-east-1)
	return &s3.GetBucketLocationOutput{
		LocationConstraint: "",
	}, nil
}

// GetBucketTagging implements S3GetBucketTagging interface.
func (m *MockS3Client) GetBucketTagging(
	ctx context.Context,
	params *s3.GetBucketTaggingInput,
	optFns ...func(*s3.Options),
) (*s3.GetBucketTaggingOutput, error) {
	m.GetBucketTaggingCallCount++
	if m.GetBucketTaggingFunc != nil {
		return m.GetBucketTaggingFunc(ctx, params, optFns...)
	}
	// Default: no tags
	return &s3.GetBucketTaggingOutput{
		TagSet: []s3types.Tag{},
	}, nil
}

// ListBuckets implements S3ListBuckets interface.
func (m *MockS3Client) ListBuckets(
	ctx context.Context,
	params *s3.ListBucketsInput,
	optFns ...func(*s3.Options),
) (*s3.ListBucketsOutput, error) {
	m.ListBucketsCallCount++
	if m.ListBucketsFunc != nil {
		return m.ListBucketsFunc(ctx, params, optFns...)
	}
	// Default: no buckets
	return &s3.ListBucketsOutput{
		Buckets: []s3types.Bucket{},
	}, nil
}

// Reset clears all call counts
func (m *MockS3Client) Reset() {
	m.GetBucketPolicyCallCount = 0
	m.GetBucketAclCallCount = 0
	m.GetPublicAccessBlockCallCount = 0
	m.GetBucketPolicyStatusCallCount = 0
	m.GetBucketEncryptionCallCount = 0
	m.GetBucketLocationCallCount = 0
	m.GetBucketTaggingCallCount = 0
	m.ListBucketsCallCount = 0
}

// =============================================================================
// RDS Mock Implementation
// =============================================================================

// MockRDSClient is a mock implementation of RDSDescribeDBInstances for testing.
// Use the function fields to customize behavior for each test case.
type MockRDSClient struct {
	// DescribeDBInstancesFunc is called when DescribeDBInstances is invoked.
	// If nil, returns empty result with no error.
	DescribeDBInstancesFunc func(
		ctx context.Context,
		params *rds.DescribeDBInstancesInput,
		optFns ...func(*rds.Options),
	) (*rds.DescribeDBInstancesOutput, error)

	// CallCount tracks how many times each method was called
	DescribeDBInstancesCallCount int

	// LastInput stores the last input for verification
	LastDescribeDBInstancesInput *rds.DescribeDBInstancesInput
}

// DescribeDBInstances implements RDSDescribeDBInstances interface.
func (m *MockRDSClient) DescribeDBInstances(
	ctx context.Context,
	params *rds.DescribeDBInstancesInput,
	optFns ...func(*rds.Options),
) (*rds.DescribeDBInstancesOutput, error) {
	m.DescribeDBInstancesCallCount++
	m.LastDescribeDBInstancesInput = params

	if m.DescribeDBInstancesFunc != nil {
		return m.DescribeDBInstancesFunc(ctx, params, optFns...)
	}

	// Default: return empty result
	return &rds.DescribeDBInstancesOutput{
		DBInstances: []rdstypes.DBInstance{},
	}, nil
}

// Reset clears all call counts and stored inputs
func (m *MockRDSClient) Reset() {
	m.DescribeDBInstancesCallCount = 0
	m.LastDescribeDBInstancesInput = nil
}

// =============================================================================
// IAM Mock Implementation
// =============================================================================

// MockIAMClient is a mock implementation of IAMSimulatePrincipalPolicy for testing.
// Use the function fields to customize behavior for each test case.
type MockIAMClient struct {
	// SimulatePrincipalPolicyFunc is called when SimulatePrincipalPolicy is invoked.
	// If nil, returns "allowed" result with no error.
	SimulatePrincipalPolicyFunc func(
		ctx context.Context,
		params *iam.SimulatePrincipalPolicyInput,
		optFns ...func(*iam.Options),
	) (*iam.SimulatePrincipalPolicyOutput, error)

	// CallCount tracks how many times each method was called
	SimulatePrincipalPolicyCallCount int

	// LastInput stores the last input for verification
	LastSimulatePrincipalPolicyInput *iam.SimulatePrincipalPolicyInput

	// Inputs stores all inputs for verification (useful for multiple calls)
	AllSimulatePrincipalPolicyInputs []*iam.SimulatePrincipalPolicyInput
}

// SimulatePrincipalPolicy implements IAMSimulatePrincipalPolicy interface.
func (m *MockIAMClient) SimulatePrincipalPolicy(
	ctx context.Context,
	params *iam.SimulatePrincipalPolicyInput,
	optFns ...func(*iam.Options),
) (*iam.SimulatePrincipalPolicyOutput, error) {
	m.SimulatePrincipalPolicyCallCount++
	m.LastSimulatePrincipalPolicyInput = params
	m.AllSimulatePrincipalPolicyInputs = append(m.AllSimulatePrincipalPolicyInputs, params)

	if m.SimulatePrincipalPolicyFunc != nil {
		return m.SimulatePrincipalPolicyFunc(ctx, params, optFns...)
	}

	// Default: return "allowed" result for all actions
	results := make([]iamtypes.EvaluationResult, 0, len(params.ActionNames))
	for _, action := range params.ActionNames {
		results = append(results, iamtypes.EvaluationResult{
			EvalActionName: &action,
			EvalDecision:   iamtypes.PolicyEvaluationDecisionTypeAllowed,
		})
	}

	return &iam.SimulatePrincipalPolicyOutput{
		EvaluationResults: results,
	}, nil
}

// Reset clears all call counts and stored inputs
func (m *MockIAMClient) Reset() {
	m.SimulatePrincipalPolicyCallCount = 0
	m.LastSimulatePrincipalPolicyInput = nil
	m.AllSimulatePrincipalPolicyInputs = nil
}

// =============================================================================
// Helper Functions for Creating Test Scenarios
// =============================================================================

// NewMockIAMClientDenyAll creates a mock that denies all actions
func NewMockIAMClientDenyAll() *MockIAMClient {
	return &MockIAMClient{
		SimulatePrincipalPolicyFunc: func(
			ctx context.Context,
			params *iam.SimulatePrincipalPolicyInput,
			optFns ...func(*iam.Options),
		) (*iam.SimulatePrincipalPolicyOutput, error) {
			results := make([]iamtypes.EvaluationResult, 0, len(params.ActionNames))
			for _, action := range params.ActionNames {
				results = append(results, iamtypes.EvaluationResult{
					EvalActionName: &action,
					EvalDecision:   iamtypes.PolicyEvaluationDecisionTypeImplicitDeny,
				})
			}
			return &iam.SimulatePrincipalPolicyOutput{
				EvaluationResults: results,
			}, nil
		},
	}
}

// NewMockIAMClientExplicitDeny creates a mock that explicitly denies all actions
func NewMockIAMClientExplicitDeny() *MockIAMClient {
	return &MockIAMClient{
		SimulatePrincipalPolicyFunc: func(
			ctx context.Context,
			params *iam.SimulatePrincipalPolicyInput,
			optFns ...func(*iam.Options),
		) (*iam.SimulatePrincipalPolicyOutput, error) {
			results := make([]iamtypes.EvaluationResult, 0, len(params.ActionNames))
			for _, action := range params.ActionNames {
				results = append(results, iamtypes.EvaluationResult{
					EvalActionName: &action,
					EvalDecision:   iamtypes.PolicyEvaluationDecisionTypeExplicitDeny,
				})
			}
			return &iam.SimulatePrincipalPolicyOutput{
				EvaluationResults: results,
			}, nil
		},
	}
}

// NewMockIAMClientAllowAll creates a mock that allows all actions (default behavior)
func NewMockIAMClientAllowAll() *MockIAMClient {
	return &MockIAMClient{} // Default behavior is to allow
}
