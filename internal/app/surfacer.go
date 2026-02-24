package app

import (
	"breachmap/internal/authorization"
	"breachmap/internal/aws"
	"breachmap/internal/compute"
	"breachmap/internal/domain"
	"breachmap/internal/iam"
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	iamsvc "github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// BreachSurfacer holds all AWS clients for the application
type BreachSurfacer struct {
	awsClients   awsClients
}

type awsClients struct {
	s3Client       *s3.Client
	iamClient      *iamsvc.Client
	ec2Client      *ec2.Client
	lambdaClient   *lambda.Client
	kmsClient      *kms.Client
	rdsClient      *rds.Client
	dynamodbClient *dynamodb.Client
	stsClient      *sts.Client
	ssmClient      *ssm.Client
}

// NewBreachSurfacer initializes all AWS clients.
// AWS credentials are resolved via the standard credential chain (env vars, IAM role, SSO profile, etc.).
func NewBreachSurfacer(ctx context.Context) (*BreachSurfacer, error) {
	bs := &BreachSurfacer{}

	// Preflight: verify AWS credentials work before doing anything else
	accountID, err := aws.GetAccountID(ctx)
	if err != nil {
		return nil, fmt.Errorf("AWS credential check failed (ensure valid credentials via env vars, IAM role, or SSO): %w", err)
	}
	fmt.Printf("🔑 AWS Account: %s\n", accountID)

	// Initialize all required AWS service clients
	services := []struct {
		name   string
		assign func(interface{})
	}{
		{"s3", func(c interface{}) { bs.awsClients.s3Client = c.(*s3.Client) }},
		{"iam", func(c interface{}) { bs.awsClients.iamClient = c.(*iamsvc.Client) }},
		{"ec2", func(c interface{}) { bs.awsClients.ec2Client = c.(*ec2.Client) }},
		{"lambda", func(c interface{}) { bs.awsClients.lambdaClient = c.(*lambda.Client) }},
		{"kms", func(c interface{}) { bs.awsClients.kmsClient = c.(*kms.Client) }},
		{"rds", func(c interface{}) { bs.awsClients.rdsClient = c.(*rds.Client) }},
		{"dynamodb", func(c interface{}) { bs.awsClients.dynamodbClient = c.(*dynamodb.Client) }},
		{"sts", func(c interface{}) { bs.awsClients.stsClient = c.(*sts.Client) }},
		{"ssm", func(c interface{}) { bs.awsClients.ssmClient = c.(*ssm.Client) }},
	}
	for _, svc := range services {
		client, err := aws.GetAWSClient(ctx, svc.name)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize %s client: %w", svc.name, err)
		}
		svc.assign(client)
	}

	// Wire up cross-package dependencies
	compute.SetEC2Dependencies(compute.EC2Dependencies{
		GetAWSClient:     aws.GetAWSClient,
		GetAuditorConfig: nil, // TODO: planned for cross-account support
	})
	authorization.SetDependencies(authorization.Dependencies{
		GetAWSClient:      aws.GetAWSClient,
		NormalizeToList:   iam.NormalizeIAMToList,
		ExtractBucketName: domain.ExtractBucketNameFromARN,
	})

	return bs, nil
}

// S3Client returns the S3 client
func (bs *BreachSurfacer) S3Client() *s3.Client {
	return bs.awsClients.s3Client
}

// RDSClient returns the RDS client
func (bs *BreachSurfacer) RDSClient() *rds.Client {
	return bs.awsClients.rdsClient
}

// IAMClient returns the IAM client
func (bs *BreachSurfacer) IAMClient() *iamsvc.Client {
	return bs.awsClients.iamClient
}

// KMSClient returns the KMS client
func (bs *BreachSurfacer) KMSClient() *kms.Client {
	return bs.awsClients.kmsClient
}

// EC2Client returns the EC2 client
func (bs *BreachSurfacer) EC2Client() *ec2.Client {
	return bs.awsClients.ec2Client
}
