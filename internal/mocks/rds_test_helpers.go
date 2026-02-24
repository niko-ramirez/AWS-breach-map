// Package mocks provides test helpers for building RDS test scenarios.
package mocks

import (
	"context"
	"fmt"

	"breachmap/internal/domain"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
)

// =============================================================================
// RDSJewel Builder - Fluent API for creating test RDSJewel objects
// =============================================================================

// RDSJewelBuilder provides a fluent API for building test RDSJewel objects.
type RDSJewelBuilder struct {
	jewel domain.RDSJewel
}

// NewRDSJewelBuilder creates a new builder with default values.
// Default: unencrypted, IAM auth disabled, private, mysql engine
func NewRDSJewelBuilder(name string) *RDSJewelBuilder {
	encrypted := false
	iamAuth := false
	publiclyAccessible := false
	engine := "mysql"

	return &RDSJewelBuilder{
		jewel: domain.RDSJewel{
			ARN:                fmt.Sprintf("arn:aws:rds:us-east-1:123456789012:db:%s", name),
			ResourceType:       "RDS",
			Name:               name,
			Encrypted:          &encrypted,
			IAMAuthEnabled:     &iamAuth,
			PubliclyAccessible: &publiclyAccessible,
			Engine:             &engine,
		},
	}
}

// WithARN sets a custom ARN
func (b *RDSJewelBuilder) WithARN(arn string) *RDSJewelBuilder {
	b.jewel.ARN = arn
	return b
}

// WithAccountID sets the account ID in the ARN
func (b *RDSJewelBuilder) WithAccountID(accountID string) *RDSJewelBuilder {
	b.jewel.ARN = fmt.Sprintf("arn:aws:rds:us-east-1:%s:db:%s", accountID, b.jewel.Name)
	return b
}

// WithRegion sets the region in the ARN
func (b *RDSJewelBuilder) WithRegion(region string) *RDSJewelBuilder {
	b.jewel.ARN = fmt.Sprintf("arn:aws:rds:%s:123456789012:db:%s", region, b.jewel.Name)
	return b
}

// Encrypted marks the database as KMS encrypted
func (b *RDSJewelBuilder) Encrypted(kmsKeyID string) *RDSJewelBuilder {
	encrypted := true
	b.jewel.Encrypted = &encrypted
	b.jewel.KMSKeyID = &kmsKeyID
	return b
}

// Unencrypted marks the database as unencrypted (default)
func (b *RDSJewelBuilder) Unencrypted() *RDSJewelBuilder {
	encrypted := false
	b.jewel.Encrypted = &encrypted
	b.jewel.KMSKeyID = nil
	return b
}

// WithIAMAuth enables IAM database authentication
func (b *RDSJewelBuilder) WithIAMAuth() *RDSJewelBuilder {
	iamAuth := true
	b.jewel.IAMAuthEnabled = &iamAuth
	return b
}

// WithPasswordAuth disables IAM auth (password only - default)
func (b *RDSJewelBuilder) WithPasswordAuth() *RDSJewelBuilder {
	iamAuth := false
	b.jewel.IAMAuthEnabled = &iamAuth
	return b
}

// Public marks the database as publicly accessible
func (b *RDSJewelBuilder) Public() *RDSJewelBuilder {
	public := true
	b.jewel.PubliclyAccessible = &public
	return b
}

// Private marks the database as private (default)
func (b *RDSJewelBuilder) Private() *RDSJewelBuilder {
	public := false
	b.jewel.PubliclyAccessible = &public
	return b
}

// WithEngine sets the database engine
func (b *RDSJewelBuilder) WithEngine(engine string) *RDSJewelBuilder {
	b.jewel.Engine = &engine
	return b
}

// MySQL sets engine to mysql
func (b *RDSJewelBuilder) MySQL() *RDSJewelBuilder {
	return b.WithEngine("mysql")
}

// PostgreSQL sets engine to postgres
func (b *RDSJewelBuilder) PostgreSQL() *RDSJewelBuilder {
	return b.WithEngine("postgres")
}

// Aurora sets engine to aurora-mysql
func (b *RDSJewelBuilder) Aurora() *RDSJewelBuilder {
	return b.WithEngine("aurora-mysql")
}

// Build returns the constructed RDSJewel
func (b *RDSJewelBuilder) Build() domain.RDSJewel {
	return b.jewel
}

// =============================================================================
// Pre-built Test Scenarios
// =============================================================================

// TestRDSScenarios contains pre-built RDSJewel objects for common test cases
var TestRDSScenarios = struct {
	// PublicIAMAuthEncrypted: Worst case - public, IAM auth, KMS encrypted
	PublicIAMAuthEncrypted func() domain.RDSJewel
	// PublicIAMAuthUnencrypted: Public with IAM auth, no encryption
	PublicIAMAuthUnencrypted func() domain.RDSJewel
	// PublicPasswordOnly: Public but password-only auth
	PublicPasswordOnly func() domain.RDSJewel
	// PrivateIAMAuthEncrypted: Ideal scenario - private, IAM auth, encrypted
	PrivateIAMAuthEncrypted func() domain.RDSJewel
	// PrivatePasswordOnly: Private with password auth
	PrivatePasswordOnly func() domain.RDSJewel
}{
	PublicIAMAuthEncrypted: func() domain.RDSJewel {
		return NewRDSJewelBuilder("public-iam-encrypted").
			Public().
			WithIAMAuth().
			Encrypted("arn:aws:kms:us-east-1:123456789012:key/test-key-1").
			Build()
	},
	PublicIAMAuthUnencrypted: func() domain.RDSJewel {
		return NewRDSJewelBuilder("public-iam-unencrypted").
			Public().
			WithIAMAuth().
			Unencrypted().
			Build()
	},
	PublicPasswordOnly: func() domain.RDSJewel {
		return NewRDSJewelBuilder("public-password-only").
			Public().
			WithPasswordAuth().
			Build()
	},
	PrivateIAMAuthEncrypted: func() domain.RDSJewel {
		return NewRDSJewelBuilder("private-iam-encrypted").
			Private().
			WithIAMAuth().
			Encrypted("arn:aws:kms:us-east-1:123456789012:key/test-key-2").
			Build()
	},
	PrivatePasswordOnly: func() domain.RDSJewel {
		return NewRDSJewelBuilder("private-password-only").
			Private().
			WithPasswordAuth().
			Build()
	},
}

// =============================================================================
// Mock RDS Client Helpers
// =============================================================================

// NewMockRDSClientWithInstances creates a mock that returns the specified DB instances
func NewMockRDSClientWithInstances(instances ...rdstypes.DBInstance) *MockRDSClient {
	return &MockRDSClient{
		DescribeDBInstancesFunc: func(
			ctx context.Context,
			params *rds.DescribeDBInstancesInput,
			optFns ...func(*rds.Options),
		) (*rds.DescribeDBInstancesOutput, error) {
			// If a specific instance is requested, filter
			if params.DBInstanceIdentifier != nil {
				for _, inst := range instances {
					if aws.ToString(inst.DBInstanceIdentifier) == *params.DBInstanceIdentifier {
						return &rds.DescribeDBInstancesOutput{
							DBInstances: []rdstypes.DBInstance{inst},
						}, nil
					}
				}
				return &rds.DescribeDBInstancesOutput{
					DBInstances: []rdstypes.DBInstance{},
				}, nil
			}
			return &rds.DescribeDBInstancesOutput{
				DBInstances: instances,
			}, nil
		},
	}
}

// RDSInstanceFromJewel converts an RDSJewel back to an rdstypes.DBInstance for mocking
func RDSInstanceFromJewel(jewel domain.RDSJewel) rdstypes.DBInstance {
	instance := rdstypes.DBInstance{
		DBInstanceArn:        aws.String(jewel.ARN),
		DBInstanceIdentifier: aws.String(jewel.Name),
	}

	if jewel.Encrypted != nil {
		instance.StorageEncrypted = jewel.Encrypted
	}
	if jewel.KMSKeyID != nil {
		instance.KmsKeyId = jewel.KMSKeyID
	}
	if jewel.IAMAuthEnabled != nil {
		instance.IAMDatabaseAuthenticationEnabled = jewel.IAMAuthEnabled
	}
	if jewel.PubliclyAccessible != nil {
		instance.PubliclyAccessible = jewel.PubliclyAccessible
	}
	if jewel.Engine != nil {
		instance.Engine = jewel.Engine
	}

	return instance
}

// =============================================================================
// Test Data Helpers
// =============================================================================

// TestRoleARN generates a test role ARN
func TestRoleARN(roleName string) string {
	return fmt.Sprintf("arn:aws:iam::123456789012:role/%s", roleName)
}

// TestKMSKeyARN generates a test KMS key ARN
func TestKMSKeyARN(keyID string) string {
	return fmt.Sprintf("arn:aws:kms:us-east-1:123456789012:key/%s", keyID)
}

// TestCMKMap creates a resource-to-CMK mapping for testing
func TestCMKMap(mappings map[string]string) map[string]map[string]string {
	return map[string]map[string]string{
		"RDS": mappings,
	}
}

// TestRolesToResourceMap creates a resource-to-roles mapping for testing
func TestRolesToResourceMap(resourceARN string, roleARNs ...string) map[string][]string {
	return map[string][]string{
		resourceARN: roleARNs,
	}
}

// TestCriticalRolesSet creates a critical roles set for testing
func TestCriticalRolesSet(roleARNs ...string) map[string]bool {
	set := make(map[string]bool)
	for _, arn := range roleARNs {
		set[arn] = true
	}
	return set
}

