package domain

// BreachPath represents a potential breach path
type BreachPath struct {
	PathID              string                   `json:"path_id"`
	Vector              string                   `json:"vector"`
	ResourceID          string                   `json:"resource_id"`
	ResourceARN         *string                  `json:"resource_arn,omitempty"`
	ResourceName        *string                  `json:"resource_name,omitempty"` // Name tag from resource (EC2 Name tag or Lambda Name tag)
	Role                string                   `json:"role"`
	RoleARN             string                   `json:"role_arn"`
	AssumedRoleARN      string                   `json:"assumed_role_arn,omitempty"`
	TargetDB            string                   `json:"target_db"`
	TargetType          string                   `json:"target_type"`
	Status              string                   `json:"status"`
	PublicIP            *string                  `json:"public_ip,omitempty"`
	Exposure            *string                  `json:"exposure,omitempty"`
	VPCID               *string                  `json:"vpc_id,omitempty"`
	SubnetIDs           []string                 `json:"subnet_ids,omitempty"`
	SecurityGroupIDs    []string                 `json:"security_group_ids,omitempty"`
	VpcEndpointID       *string                  `json:"vpc_endpoint_id,omitempty"`
	TargetEncrypted     *bool                    `json:"target_encrypted,omitempty"`
	KMSKeyID            *string                  `json:"kms_key_id,omitempty"`
	VerificationResults *PathVerificationResults `json:"verification_results,omitempty"`
	VerifiedStatus      string                   `json:"verified_status,omitempty"`
	LateralMovement     bool                     `json:"lateral_movement,omitempty"`
	PrivilegeEscalation bool                     `json:"privilege_escalation,omitempty"`
}

// BreachPathOutput represents a comprehensive breach path output
type BreachPathOutput struct {
	PathID              string               `json:"path_id"`
	PathString          string               `json:"path_string"`
	PathType            string               `json:"path_type"`
	InternetExposed     bool                 `json:"internet_exposed"`
	Container           *EC2WorkloadInfo     `json:"container,omitempty"`
	IAMRole             *IAMRoleInfo         `json:"iam_role,omitempty"`
	Store               StoreInfo            `json:"store"`
	BucketExposed       bool                 `json:"bucket_exposed"`
	ExposureDetails     *ExposureResult      `json:"exposure_details,omitempty"`
	Authorization       *AuthorizationResult `json:"authorization,omitempty"`
	LateralMovement     bool                 `json:"lateral_movement,omitempty"`
	PrivilegeEscalation bool                 `json:"privilege_escalation,omitempty"`
	ExposureAnalysis    interface{}          `json:"exposure_analysis,omitempty"`
}

// EC2WorkloadInfo contains EC2 instance details
type EC2WorkloadInfo struct {
	InstanceID       string              `json:"instance_id"`
	InstanceARN      string              `json:"instance_arn"`
	Region           string              `json:"region"`
	VPCID            *string             `json:"vpc_id,omitempty"`
	SubnetID         *string             `json:"subnet_id,omitempty"`
	SecurityGroupIDs []string            `json:"security_group_ids,omitempty"`
	PublicIP         *string             `json:"public_ip,omitempty"`
	PrivateIP        *string             `json:"private_ip,omitempty"`
	InternetExposed  bool                `json:"internet_exposed"`
	PublicExposure   *PublicExposureInfo `json:"public_exposure,omitempty"`
}

// IAMRoleInfo contains IAM role access details
type IAMRoleInfo struct {
	RoleARN       string               `json:"role_arn"`
	RoleName      string               `json:"role_name"`
	RiskProfile   string               `json:"risk_profile"`
	AccessActions []S3AccessAction     `json:"access_actions"`
	PolicyDetails []PolicyAccessDetail `json:"policy_details"`
}

// StoreInfo contains data store details (S3 bucket, RDS database, etc.)
type StoreInfo struct {
	ResourceARN      string  `json:"resource_arn"`  // ARN of the data store
	ResourceName     string  `json:"resource_name"` // Name of the data store
	ResourceType     string  `json:"resource_type,omitempty"` // "S3", "RDS", etc.
	Encrypted        *bool   `json:"encrypted,omitempty"`
	KMSKeyID         *string `json:"kms_key_id,omitempty"`
	IsCrownJewel     bool    `json:"is_crown_jewel"`
	CrownJewelReason string  `json:"crown_jewel_reason,omitempty"`
}

// AuthorizationResult contains authorization verification result
type AuthorizationResult struct {
	ResourceAccessAllowed bool                   `json:"resource_access_allowed"` // Whether principal can access the resource (S3, RDS, etc.)
	KMSDecryptAllowed     *bool                  `json:"kms_decrypt_allowed,omitempty"`
	Exploitable           bool                   `json:"exploitable"`
	SimulationDetails     map[string]interface{} `json:"simulation_details,omitempty"`

	// Network boundary results
	NetworkBoundaries *NetworkBoundaryResult `json:"network_boundaries,omitempty"`
	BlockedByNetwork  bool                   `json:"blocked_by_network,omitempty"`
}
