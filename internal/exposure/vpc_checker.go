package exposure

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"breachmap/internal/domain"
	"breachmap/internal/logging"
)

// CheckBucketPolicyVPCDeny extracts VPC IDs from bucket policy deny conditions
func CheckBucketPolicyVPCDeny(
	ctx context.Context,
	s3Client *s3.Client,
	bucketARNs []string,
) (map[string][]string, error) {
	logging.LogDebug("--- Checking Bucket Policies for VPC Deny Conditions ---")

	bucketToDeniedVPCsMap := make(map[string][]string)

	for _, bucketARN := range bucketARNs {
		bucketName := domain.ExtractBucketNameFromARN(bucketARN)
		if bucketName == "" {
			logging.LogWarn("Invalid bucket ARN format", map[string]interface{}{"bucket_arn": bucketARN})
			continue
		}

		deniedVPCs, err := ExtractDeniedVPCsFromBucketPolicy(ctx, s3Client, bucketName)
		if err != nil {
			logging.LogWarn("Failed to check bucket policy", map[string]interface{}{
				"bucket": bucketName,
				"error":  err.Error(),
			})
			continue
		}

		if len(deniedVPCs) > 0 {
			bucketToDeniedVPCsMap[bucketARN] = deniedVPCs
			logging.LogDebug(fmt.Sprintf("Bucket %s denies access from %d VPC(s): %v", bucketName, len(deniedVPCs), deniedVPCs))
		}
	}

	logging.LogDebug(fmt.Sprintf("Found VPC deny conditions in %d bucket(s)", len(bucketToDeniedVPCsMap)))
	return bucketToDeniedVPCsMap, nil
}

// ExtractDeniedVPCsFromBucketPolicy extracts VPC IDs from Deny statements in bucket policy
func ExtractDeniedVPCsFromBucketPolicy(
	ctx context.Context,
	s3Client *s3.Client,
	bucketName string,
) ([]string, error) {
	policyOutput, err := s3Client.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		if strings.Contains(err.Error(), "NoSuchBucketPolicy") {
			return []string{}, nil
		}
		return nil, err
	}

	if policyOutput.Policy == nil {
		return []string{}, nil
	}

	var policyDoc map[string]interface{}
	if err := json.Unmarshal([]byte(*policyOutput.Policy), &policyDoc); err != nil {
		return nil, fmt.Errorf("failed to parse bucket policy: %w", err)
	}

	statements, ok := policyDoc["Statement"].([]interface{})
	if !ok {
		return []string{}, nil
	}

	deniedVPCs := make(map[string]bool)

	for _, stmtInterface := range statements {
		stmt, ok := stmtInterface.(map[string]interface{})
		if !ok {
			continue
		}

		if effect, ok := stmt["Effect"].(string); !ok || effect != "Deny" {
			continue
		}

		condition, ok := stmt["Condition"].(map[string]interface{})
		if !ok {
			continue
		}

		if stringEquals, ok := condition["StringEquals"].(map[string]interface{}); ok {
			if vpcID, ok := stringEquals["aws:SourceVpc"].(string); ok {
				deniedVPCs[vpcID] = true
			}
			if vpcList, ok := stringEquals["aws:SourceVpc"].([]interface{}); ok {
				for _, vpcInterface := range vpcList {
					if vpcID, ok := vpcInterface.(string); ok {
						deniedVPCs[vpcID] = true
					}
				}
			}
		}
	}

	result := make([]string, 0, len(deniedVPCs))
	for vpcID := range deniedVPCs {
		result = append(result, vpcID)
	}

	return result, nil
}


