package domain

import "strings"

// ExtractBucketNameFromARN extracts the bucket name from an S3 ARN.
// Returns the bucket name if the input is a valid S3 ARN (arn:aws:s3:::bucket-name),
// or empty string if the input is not a valid S3 ARN.
func ExtractBucketNameFromARN(bucketARN string) string {
	if !strings.HasPrefix(bucketARN, "arn:aws:s3:::") {
		return ""
	}
	return strings.TrimPrefix(bucketARN, "arn:aws:s3:::")
}

type S3ResourceData struct {
	KMSBuckets            []S3CrownJewel
	NonKMSBuckets         []S3CrownJewel
	BucketToCMKMap        map[string]string
	CMKSet                map[string]bool
	ExposureMap           map[string]*ExposureResult
	CrownJewelMap         map[string]S3CrownJewel
	EncryptedResources    []EncryptedResource
	NonEncryptedResources []NonEncryptedResource
	AllBuckets            []S3CrownJewel
}

// EncryptedResource represents an encrypted resource with its CMK ARN
type EncryptedResource struct {
	ResourceARN  string
	CMKARN       string
	ResourceType string
}

// NonEncryptedResource represents a non-encrypted resource
type NonEncryptedResource struct {
	ResourceARN  string
	ResourceType string
}

// RDSResourceData holds RDS-specific resource data
type RDSResourceData struct {
	KMSDatabases            []RDSJewel
	NonKMSDatabases        []RDSJewel
	DatabaseToCMKMap       map[string]string
	CMKSet                  map[string]bool
	ExposureMap             map[string]*ExposureResult
	CrownJewelMap           map[string]RDSJewel
	EncryptedResources      []EncryptedResource
	NonEncryptedResources   []NonEncryptedResource
	AllDatabases            []RDSJewel
}

// SharedIAMData holds the results of shared IAM analysis steps (4-9)
type SharedIAMData struct {
	CMKToRolesMap              map[string][]string
	RoleToCMKsMap              map[string][]string
	RoleToActionTypeMap        map[string]string
	ResourceToRolesMap         map[string][]string // resourceARN -> []roleARN
	PrincipalAccessResults     map[string][]PrincipalAccess
	RDSPrincipalAccessResults  map[string][]PrincipalAccess // RDS-specific authorization results
	CriticalRolesSet           map[string]bool
	SeedRiskyRoles             []string
	LateralMovementRoles       []LateralMovementRole
	PrivilegeEscalationRoles   []PrivilegeEscalationRole
	BreachSurfaceRoles         []string
	FilteredRoles              []FilteredRoleInfo
}
