package domain

// ExposureResult represents the final exposure assessment for a resource (S3, RDS, etc.)
type ExposureResult struct {
	ResourceName       string                   `json:"resource_name"` // Name of the resource (bucket name, database identifier, etc.)
	FinalExposure      string                   `json:"final_exposure"`
	ACLExposure        string                   `json:"acl_exposure,omitempty"`
	PolicyExposure     string                   `json:"policy_exposure,omitempty"`
	PABBlocking        bool                     `json:"pab_blocking"`
	PABDetails         *PublicAccessBlockConfig `json:"pab_details,omitempty"`
	Details            string                   `json:"details,omitempty"`
	PolicyStatements   []PolicyStatement        `json:"policy_statements,omitempty"`
	ACLGrants          []ACLGrant               `json:"acl_grants,omitempty"`
	HasBucketPolicy    bool                     `json:"has_bucket_policy,omitempty"`
	HasPublicACL       bool                     `json:"has_public_acl,omitempty"`
	PublicAccessBlock  bool                     `json:"public_access_block,omitempty"`
	PolicyAllowsPublic bool                     `json:"policy_allows_public,omitempty"`
}

// BucketExposureInputs represents normalized inputs for bucket exposure analysis
type BucketExposureInputs struct {
	Policy       *BucketPolicyJSON        `json:"policy,omitempty"`
	ACL          *BucketACLJSON           `json:"acl,omitempty"`
	PAB          *PublicAccessBlockConfig `json:"pab,omitempty"`
	PolicyStatus *BucketPolicyStatus      `json:"policy_status,omitempty"`
}

// BucketPolicyJSON represents a parsed bucket policy
type BucketPolicyJSON struct {
	Version   string            `json:"Version,omitempty"`
	Statement []PolicyStatement `json:"Statement"`
}

// PolicyStatement represents a single policy statement
type PolicyStatement struct {
	Sid       string                 `json:"Sid,omitempty"`
	Effect    string                 `json:"Effect"`
	Principal interface{}            `json:"Principal,omitempty"`
	Action    interface{}            `json:"Action,omitempty"`
	Resource  interface{}            `json:"Resource,omitempty"`
	Condition map[string]interface{} `json:"Condition,omitempty"`
}

// BucketACLJSON represents bucket ACL grants
type BucketACLJSON struct {
	Grants []ACLGrant `json:"Grants,omitempty"`
	Owner  *ACLOwner  `json:"Owner,omitempty"`
}

// ACLGrant represents a single ACL grant
type ACLGrant struct {
	Grantee    ACLGrantee `json:"Grantee"`
	Permission string     `json:"Permission"`
}

// ACLGrantee represents the grantee in an ACL grant
type ACLGrantee struct {
	Type        string `json:"Type,omitempty"`
	ID          string `json:"ID,omitempty"`
	URI         string `json:"URI,omitempty"`
	DisplayName string `json:"DisplayName,omitempty"`
}

// ACLOwner represents the bucket owner
type ACLOwner struct {
	ID          string `json:"ID,omitempty"`
	DisplayName string `json:"DisplayName,omitempty"`
}

// PublicAccessBlockConfig represents Public Access Block settings
type PublicAccessBlockConfig struct {
	BlockPublicAcls       bool `json:"BlockPublicAcls"`
	IgnorePublicAcls      bool `json:"IgnorePublicAcls"`
	BlockPublicPolicy     bool `json:"BlockPublicPolicy"`
	RestrictPublicBuckets bool `json:"RestrictPublicBuckets"`
}

// BucketPolicyStatus represents AWS-provided policy status
type BucketPolicyStatus struct {
	IsPublic bool `json:"IsPublic"`
}

// EC2ExposureResult represents the result of EC2 exposure analysis
type EC2ExposureResult struct {
	InstanceID           string                `json:"instance_id,omitempty"`
	IsExposed            bool                  `json:"is_exposed"`
	Reason               string                `json:"reason,omitempty"`
	HasPublicIP          bool                  `json:"has_public_ip"`
	HasPublicSG          bool                  `json:"has_public_sg"`
	InternetExposed      bool                  `json:"internet_exposed"`
	SecurityGroupDetails []SecurityGroupDetail `json:"security_group_details,omitempty"`
}

// SecurityGroupDetail contains details about a security group's public access
type SecurityGroupDetail struct {
	GroupID         string        `json:"group_id"`
	GroupName       string        `json:"group_name,omitempty"`
	HasPublicAccess bool          `json:"has_public_access"`
	AllowsPublic    bool          `json:"allows_public"`
	ExposedPorts    []ExposedPort `json:"exposed_ports,omitempty"`
	PublicPorts     []int32       `json:"public_ports,omitempty"`
}

// LambdaExposureResult represents the result of Lambda exposure analysis
type LambdaExposureResult struct {
	FunctionName    string `json:"function_name,omitempty"`
	IsExposed       bool   `json:"is_exposed"`
	Reason          string `json:"reason,omitempty"`
	ExposureType    string `json:"exposure_type,omitempty"`
	HasFunctionURL  bool   `json:"has_function_url"`
	FunctionURLAuth string `json:"function_url_auth,omitempty"`
	HasAPIGateway   bool   `json:"has_api_gateway"`
	APIGatewayAuth  string `json:"api_gateway_auth,omitempty"`
	InternetExposed bool   `json:"internet_exposed"`
}
