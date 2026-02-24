package domain

// EC2InstanceInfo represents metadata about an EC2 instance
type EC2InstanceInfo struct {
	InstanceID       string              `json:"instance_id"`
	Name             *string             `json:"name,omitempty"` // Name tag from EC2 instance
	Region           string              `json:"region"`
	VPCID            *string             `json:"vpc_id,omitempty"`
	SubnetID         *string             `json:"subnet_id,omitempty"`
	SecurityGroupIDs []string            `json:"security_group_ids"`
	PublicIP         *string             `json:"public_ip,omitempty"`
	PrivateIP        *string             `json:"private_ip,omitempty"`
	PublicIPFlag     bool                `json:"public_ip_flag"`
	PublicSGFlag     bool                `json:"public_sg_flag"`
	InternetExposed  bool                `json:"internet_exposed"`
	PublicExposure   *PublicExposureInfo `json:"public_exposure,omitempty"`
}

// PublicExposureInfo contains detailed public exposure information
type PublicExposureInfo struct {
	HasPublicIP          bool          `json:"has_public_ip"`
	PublicSecurityGroups []string      `json:"public_security_groups"`
	ExposedPorts         []ExposedPort `json:"exposed_ports"`
}

// ExposedPort represents a port exposed to the internet
type ExposedPort struct {
	Protocol string `json:"protocol"`
	FromPort *int32 `json:"from_port,omitempty"`
	ToPort   *int32 `json:"to_port,omitempty"`
}

// ComputeResource represents a compute resource that assumes an IAM role
type ComputeResource struct {
	RuntimeType      string              `json:"runtime_type"`
	ResourceID       string              `json:"resource_id"`
	ResourceARN      string              `json:"resource_arn"`
	ResourceName     *string             `json:"resource_name,omitempty"` // Name tag from resource (EC2 Name tag or Lambda Name tag)
	Region           string              `json:"region"`
	RoleARN          string              `json:"role_arn"`
	InternetExposed  bool                `json:"internet_exposed"`
	VPCID            *string             `json:"vpc_id,omitempty"`
	SubnetIDs        []string            `json:"subnet_ids,omitempty"`
	SecurityGroupIDs []string            `json:"security_group_ids,omitempty"`
	PublicIP         *string             `json:"public_ip,omitempty"`
	PrivateIP        *string             `json:"private_ip,omitempty"`
	PublicExposure   *PublicExposureInfo `json:"public_exposure,omitempty"`
	ExposureDetails  *LambdaExposureInfo `json:"exposure_details,omitempty"`
}

// LambdaInfo represents metadata about a Lambda function
type LambdaInfo struct {
	Name             *string  `json:"name,omitempty"` // Name tag from Lambda function
	FunctionName     string   `json:"function_name"`
	FunctionARN      string   `json:"function_arn"`
	Region           string   `json:"region"`
	RoleARN          string   `json:"role_arn"`
	Runtime          string   `json:"runtime,omitempty"`
	VPCID            *string  `json:"vpc_id,omitempty"`
	SubnetIDs        []string `json:"subnet_ids,omitempty"`
	SecurityGroupIDs []string `json:"security_group_ids,omitempty"`
	// Exposure flags
	PublicLambdaURL   bool                   `json:"public_lambda_url"`
	PublicAPIGateway  bool                   `json:"public_api_gateway"`
	InternetReachable bool                   `json:"internet_reachable"`
	InternetExposed   bool                   `json:"internet_exposed"`
	FunctionURL       *FunctionURLConfig     `json:"function_url,omitempty"`
	APIGateway        *APIGatewayIntegration `json:"api_gateway,omitempty"`
	ExposureDetails   *LambdaExposureInfo    `json:"exposure_details,omitempty"`
}

// LambdaExposureInfo contains detailed information about Lambda exposure
type LambdaExposureInfo struct {
	HasFunctionURL         bool                    `json:"has_function_url"`
	AuthType               string                  `json:"auth_type,omitempty"`
	FunctionURLConfig      *FunctionURLConfig      `json:"function_url_config,omitempty"`
	APIGatewayIntegrations []APIGatewayIntegration `json:"api_gateway_integrations,omitempty"`
}

// FunctionURLConfig represents Lambda Function URL configuration
type FunctionURLConfig struct {
	FunctionURL string `json:"function_url"`
	URL         string `json:"url,omitempty"` // Alias for FunctionURL
	AuthType    string `json:"auth_type"`
}

// APIGatewayIntegration represents an API Gateway integration for a Lambda
type APIGatewayIntegration struct {
	APIID          string `json:"api_id"`
	APIName        string `json:"api_name"`
	APIType        string `json:"api_type,omitempty"`
	StageName      string `json:"stage_name"`
	Endpoint       string `json:"endpoint,omitempty"`
	AuthType       string `json:"auth_type,omitempty"`
	AuthorizerType string `json:"authorizer_type,omitempty"`
	APIKeyRequired bool   `json:"api_key_required,omitempty"`
	Public         bool   `json:"public,omitempty"`
}

// RoleToComputeResourcesMapping maps IAM role ARNs to compute resources
type RoleToComputeResourcesMapping map[string][]ComputeResource

// RoleToInstancesMapping maps IAM role ARNs to EC2 instances
type RoleToInstancesMapping map[string][]EC2InstanceInfo

// RoleToLambdasMapping maps IAM role ARNs to Lambda functions
type RoleToLambdasMapping map[string][]LambdaInfo

// RoleRiskInfo contains role risk information
type RoleRiskInfo struct {
	RoleARN       string           `json:"role_arn"`
	RoleName      string           `json:"role_name"`
	RiskProfile   string           `json:"risk_profile"`
	AccessActions []S3AccessAction `json:"access_actions"`
	Resources     []ResourceAccess `json:"resources"` // Resources this role can access
}

// ResourceAccess represents resource access details (S3 bucket, RDS database, etc.)
type ResourceAccess struct {
	ResourceARN  string `json:"resource_arn"`
	ResourceName string `json:"resource_name"`
	AccessLevel  string `json:"access_level"`
}

// RoleInstanceMapping contains role risk info and EC2 instances
type RoleInstanceMapping struct {
	RoleRisk  RoleRiskInfo      `json:"role_risk"`
	Instances []EC2InstanceInfo `json:"instances"`
}

// EnhancedRoleToInstancesMapping includes role risk information
type EnhancedRoleToInstancesMapping map[string]RoleInstanceMapping

// DroppedWorkloadInfo contains information about dropped workloads
type DroppedWorkloadInfo struct {
	ResourceID   string `json:"resource_id"`
	ResourceType string `json:"resource_type"`
	RuntimeType  string `json:"runtime_type,omitempty"`
	RoleARN      string `json:"role_arn"`
	Reason       string `json:"reason"`
}
