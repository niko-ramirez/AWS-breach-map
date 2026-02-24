package aws

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	lambdasvc "github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"breachmap/internal/logging"
)

var (
	clientCache      = make(map[string]interface{})
	cacheMutex       sync.RWMutex
	auditorConfig    *aws.Config
	auditorConfigMux sync.RWMutex
)

// AWSClient is an interface for AWS service clients
type AWSClient interface{}

// GetAWSClient returns a cached AWS client for a service
func GetAWSClient(ctx context.Context, service string) (interface{}, error) {
	cacheMutex.RLock()
	if client, ok := clientCache[service]; ok {
		cacheMutex.RUnlock()
		return client, nil
	}
	cacheMutex.RUnlock()

	cacheMutex.Lock()
	defer cacheMutex.Unlock()

	if client, ok := clientCache[service]; ok {
		return client, nil
	}

	var cfg aws.Config
	var err error

	auditorConfigMux.RLock()
	if auditorConfig != nil {
		cfg = *auditorConfig
		auditorConfigMux.RUnlock()
		logging.LogDebug(fmt.Sprintf("Using auditor role credentials for %s client", service))
	} else {
		auditorConfigMux.RUnlock()
		cfg, err = config.LoadDefaultConfig(ctx,
			config.WithRetryMaxAttempts(5),
			config.WithRetryer(func() aws.Retryer {
				return retry.NewAdaptiveMode(func(o *retry.AdaptiveModeOptions) {
					o.StandardOptions = append(o.StandardOptions, func(so *retry.StandardOptions) {
						so.MaxBackoff = 30 * time.Second
					})
				})
			}),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to load AWS config: %w", err)
		}
		logging.LogDebug(fmt.Sprintf("Using default credentials for %s client", service))
	}

	var client interface{}
	switch service {
	case "rds":
		client = rds.NewFromConfig(cfg)
	case "dynamodb":
		client = dynamodb.NewFromConfig(cfg)
	case "s3":
		client = s3.NewFromConfig(cfg)
	case "iam":
		client = iam.NewFromConfig(cfg)
	case "ec2":
		client = ec2.NewFromConfig(cfg)
	case "lambda":
		client = lambdasvc.NewFromConfig(cfg)
	case "sts":
		client = sts.NewFromConfig(cfg)
	case "ssm":
		client = ssm.NewFromConfig(cfg)
	case "kms":
		client = kms.NewFromConfig(cfg)
	default:
		return nil, fmt.Errorf("unknown service: %s", service)
	}

	clientCache[service] = client
	return client, nil
}

// GetAccountID returns the current AWS account ID
func GetAccountID(ctx context.Context) (string, error) {
	if accountID := os.Getenv("AWS_ACCOUNT_ID"); accountID != "" {
		return accountID, nil
	}

	stsClient, err := GetAWSClient(ctx, "sts")
	if err != nil {
		return "", fmt.Errorf("failed to get STS client: %w", err)
	}

	stsSvc := stsClient.(*sts.Client)
	result, err := stsSvc.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", fmt.Errorf("failed to get caller identity: %w", err)
	}

	if result == nil || result.Account == nil {
		return "", fmt.Errorf("empty account ID in response")
	}

	return aws.ToString(result.Account), nil
}

// GetSSMParameter retrieves a parameter from SSM
func GetSSMParameter(ctx context.Context, parameterName string) (string, error) {
	ssmClient, err := GetAWSClient(ctx, "ssm")
	if err != nil {
		return "", fmt.Errorf("failed to get SSM client: %w", err)
	}

	ssmSvc := ssmClient.(*ssm.Client)
	result, err := ssmSvc.GetParameter(ctx, &ssm.GetParameterInput{
		Name:           aws.String(parameterName),
		WithDecryption: aws.Bool(true),
	})
	if err != nil {
		return "", fmt.Errorf("failed to get parameter %s: %w", parameterName, err)
	}

	return aws.ToString(result.Parameter.Value), nil
}
