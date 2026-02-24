package domain

// CrownJewels represents a Crown Jewel database resource
type CrownJewels struct {
	S3CrownJewels *[]S3CrownJewel `json:"s3_jewels,omitempty"`
	RDSJewels     *[]RDSJewel     `json:"rds_jewels,omitempty"`
}

type RDSJewel struct {
	ARN                string   `json:"arn"`
	ResourceType       string   `json:"resource_type"`
	Name               string   `json:"name"`
	Encrypted          *bool    `json:"encrypted,omitempty"`
	KMSKeyID           *string  `json:"kms_key_id,omitempty"`
	IAMAuthEnabled     *bool    `json:"iam_auth_enabled,omitempty"`    // True if IAM database authentication is enabled
	PubliclyAccessible *bool    `json:"publicly_accessible,omitempty"` // True if database is publicly accessible
	Engine             *string  `json:"engine,omitempty"`              // Database engine (e.g., mysql, postgres, aurora)

	// Network information for boundary checking
	VPCID            *string  `json:"vpc_id,omitempty"`             // VPC where RDS is deployed
	SubnetIDs        []string `json:"subnet_ids,omitempty"`         // Subnets in the DB subnet group
	SecurityGroupIDs []string `json:"security_group_ids,omitempty"` // Security groups attached to RDS
	Port             *int32   `json:"port,omitempty"`               // Database port (3306, 5432, etc.)
	Endpoint         *string  `json:"endpoint,omitempty"`           // Database endpoint address
}

type S3CrownJewel struct {
	ARN          string  `json:"arn"`
	ResourceType string  `json:"resource_type"`
	Name         string  `json:"name"`
	Encrypted    *bool   `json:"encrypted,omitempty"`
	KMSKeyID     *string `json:"kms_key_id,omitempty"`
}

// PrivilegedRole represents a role with access to Crown Jewels
type PrivilegedRole struct {
	RoleName string `json:"role_name"`
	RoleARN  string `json:"role_arn"`
	AccessTo string `json:"access_to"`
}

// FilteredRoleInfo represents a role that was filtered with the reason
type FilteredRoleInfo struct {
	RoleARN     string `json:"role_arn"`
	ResourceARN string `json:"resource_arn"` // ARN of the resource (S3 bucket, RDS database, etc.)
	Reason      string `json:"reason"`
}
