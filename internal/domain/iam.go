package domain

// PrincipalAccess represents IAM principal access to a resource (S3 bucket, RDS database, etc.)
type PrincipalAccess struct {
	PrincipalARN    string                 `json:"principal_arn"`
	PrincipalType   string                 `json:"principal_type"`
	PrincipalName   string                 `json:"principal_name"`
	ResourceARN     string                 `json:"resource_arn"`  // ARN of the target resource (S3 bucket, RDS database, etc.)
	ResourceName    string                 `json:"resource_name"` // Name of the target resource
	AccessActions   []S3AccessAction       `json:"access_actions"`
	RiskProfile     string                 `json:"risk_profile"`
	PolicyDetails   []PolicyAccessDetail   `json:"policy_details"`
	SimulatedAccess *SimulatedAccessResult `json:"simulated_access,omitempty"`
	Authorization   *AuthorizationResult   `json:"authorization,omitempty"`
}

// PolicyAccessDetail captures which policy grants access
type PolicyAccessDetail struct {
	PolicyARN         string   `json:"policy_arn"`
	PolicyName        string   `json:"policy_name"`
	StatementID       string   `json:"statement_id,omitempty"`
	Actions           []string `json:"actions"`
	Resources         []string `json:"resources"`
	IsCustomerManaged bool     `json:"is_customer_managed"`
}

// SimulatedAccessResult contains IAM policy simulation results
type SimulatedAccessResult struct {
	ListBucket   string `json:"list_bucket"`
	GetObject    string `json:"get_object"`
	PutObject    string `json:"put_object"`
	DeleteObject string `json:"delete_object"`
}

// LateralMovementRole represents a role that can assume other roles
type LateralMovementRole struct {
	RoleARN        string   `json:"role_arn"`
	RoleName       string   `json:"role_name"`
	CanAssumeRoles []string `json:"can_assume_roles"`
	CanPassRoles   []string `json:"can_pass_roles"`
}

// PrivilegeEscalationRole represents a role with dangerous IAM permissions
type PrivilegeEscalationRole struct {
	RoleARN          string   `json:"role_arn"`
	RoleName         string   `json:"role_name"`
	DangerousActions []string `json:"dangerous_actions"`
}
