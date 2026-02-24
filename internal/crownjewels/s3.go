package crownjewels

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"breachmap/internal/domain"
	"breachmap/internal/logging"
	"breachmap/internal/outputter"
)

// EnumerateS3Stores enumerates S3 buckets and identifies Crown Jewels
func EnumerateS3Stores(ctx context.Context, s3Client *s3.Client) ([]domain.S3CrownJewel, error) {
	startTime := time.Now()
	metrics := logging.GetMetrics()
	s3CrownJewels := []domain.S3CrownJewel{}

	// List all buckets
	result, err := s3Client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list S3 buckets: %w", err)
	}

	if result == nil || result.Buckets == nil {
		return []domain.S3CrownJewel{}, nil
	}

	crownBucketNames := []string{}
	ignoredBucketNames := []string{}
	for _, bucket := range result.Buckets {
		bucketName := aws.ToString(bucket.Name)

		encrypted, kmsKeyID, kmsEncrypted, err := checkEncryptionForBucket(ctx, s3Client, bucket.Name)
		if err != nil {
			return nil, fmt.Errorf("failed to check encryption for bucket %s: %w", bucketName, err)
		}

		// Get bucket tags
		tags, err := getBucketTags(ctx, s3Client, bucket.Name)
		if err != nil {
			return nil, fmt.Errorf("failed to get bucket tags for bucket %s: %w", bucketName, err)
		}

		// Check if it's a crown jewel
		bucketARN := "arn:aws:s3:::" + bucketName
		if !IsCrownJewel(bucketARN, bucketName, tags, kmsEncrypted) {
			ignoredBucketNames = append(ignoredBucketNames, bucketName)
			continue
		}

		logging.LogDebug("Found crown jewel bucket", map[string]interface{}{
			"bucket":        bucketName,
			"encrypted":     encrypted,
			"kms_encrypted": kmsEncrypted,
		})

		crownJewel := domain.S3CrownJewel{
			ARN:          bucketARN,
			ResourceType: "S3",
			Name:         bucketName,
			Encrypted:    &encrypted,
		}
		if kmsKeyID != nil {
			crownJewel.KMSKeyID = kmsKeyID
		}
		s3CrownJewels = append(s3CrownJewels, crownJewel)
		crownBucketNames = append(crownBucketNames, bucketName)

	}

	if len(ignoredBucketNames) > 0 {
		fmt.Printf("\n🚫 Buckets Ignored (not crown jewels): %d bucket(s)\n", len(ignoredBucketNames))
		displayResourceNames(ignoredBucketNames, 10)
	}

	fmt.Printf("\n💎 Crown Jewels Detected: %d bucket(s)\n", len(crownBucketNames))
	if len(crownBucketNames) > 0 {
		displayResourceNames(crownBucketNames, len(crownBucketNames))
	}

	enumDuration := time.Since(startTime)

	// Output Step 1: Crown Jewels
	fmt.Print(outputter.FormatStepOutputWithTiming(1, "Detect Crown Jewels",
		"Identifying sensitive S3 buckets based on encryption and naming patterns",
		struct {
			CrownJewels    domain.CrownJewels
			IgnoredBuckets []string
		}{domain.CrownJewels{S3CrownJewels: &s3CrownJewels}, ignoredBucketNames}, enumDuration))

	metrics.RecordOperation("enumerate_s3_buckets", enumDuration, true, 0, len(s3CrownJewels), nil)
	logging.LogInfo("Found critical buckets", map[string]interface{}{
		"bucket_count":  len(crownBucketNames),
		"ignored_count": len(ignoredBucketNames),
	})

	log.Printf("Found %d crown jewel S3 buckets", len(s3CrownJewels))
	return s3CrownJewels, nil
}

func checkEncryptionForBucket(
	ctx context.Context,
	s3Client *s3.Client,
	bucketName *string,
) (bool, *string, bool, error) {

	encResult, err := s3Client.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{
		Bucket: bucketName,
	})
	if err != nil {
		// ServerSideEncryptionConfigurationNotFoundError means bucket has no encryption - this is valid
		if strings.Contains(err.Error(), "ServerSideEncryptionConfigurationNotFoundError") {
			return false, nil, false, nil
		}
		return false, nil, false, err
	}

	// If no encryption configuration, return false
	if encResult == nil || encResult.ServerSideEncryptionConfiguration == nil {
		return false, nil, false, nil
	}

	// Check encryption
	var encrypted bool
	var kmsKeyID *string
	var kmsEncrypted bool

	for _, rule := range encResult.ServerSideEncryptionConfiguration.Rules {
		if rule.ApplyServerSideEncryptionByDefault != nil {
			encrypted = true
			if rule.ApplyServerSideEncryptionByDefault.SSEAlgorithm == "aws:kms" {
				kmsKeyID = rule.ApplyServerSideEncryptionByDefault.KMSMasterKeyID
				kmsEncrypted = true
			}
		}
	}

	return encrypted, kmsKeyID, kmsEncrypted, nil
}

func getBucketTags(ctx context.Context, s3Client *s3.Client, bucketName *string) ([]map[string]string, error) {
	tags := make([]map[string]string, 0)
	tagResult, err := s3Client.GetBucketTagging(ctx, &s3.GetBucketTaggingInput{
		Bucket: bucketName,
	})
	if err != nil {
		// NoSuchTagSet is a valid state - bucket simply doesn't have tags configured
		errStr := err.Error()
		if strings.Contains(errStr, "NoSuchTagSet") {
			return tags, nil
		}
		// For other errors, return them
		return nil, fmt.Errorf("failed to get bucket tags for bucket %s: %w", aws.ToString(bucketName), err)
	}

	// If tagResult or TagSet is nil, return empty tags
	if tagResult == nil || tagResult.TagSet == nil {
		return tags, nil
	}

	for _, tag := range tagResult.TagSet {
		tags = append(tags, map[string]string{
			"Key":   aws.ToString(tag.Key),
			"Value": aws.ToString(tag.Value),
		})
	}

	return tags, nil
}

func displayResourceNames(names []string, maxShow int) {
	for i, name := range names {
		if i < maxShow {
			fmt.Printf("   • %s\n", name)
		} else {
			remaining := len(names) - maxShow
			fmt.Printf("   ... and %d more resource(s)\n", remaining)
			break
		}
	}
}
