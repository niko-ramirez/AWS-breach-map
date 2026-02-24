package crownjewels

import (
	"breachmap/internal/domain"
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func GetCrownJewels(ctx context.Context, s3Client *s3.Client, rdsClient *rds.Client) (domain.CrownJewels, error) {

	crownJewels := domain.CrownJewels{}
	s3CrownJewels, err := EnumerateS3Stores(ctx, s3Client)
	if err != nil {
		return domain.CrownJewels{}, fmt.Errorf("failed to enumerate crown jewels: %w", err)
	}
	crownJewels.S3CrownJewels = &s3CrownJewels
	// Add other crown jewel resources here

	rdsCrownJewels, err := EnumerateRDSDatabases(ctx, rdsClient)
	if err != nil {
		return domain.CrownJewels{}, fmt.Errorf("failed to enumerate crown jewels: %w", err)
	}
	crownJewels.RDSJewels = &rdsCrownJewels
	return crownJewels, nil
}

// IsCrownJewel determines if a resource is a Crown Jewel.
// Checks in order: 1) user-specified ARNs, 2) KMS encryption, 3) pattern heuristics.
func IsCrownJewel(arn, resourceName string, tags []map[string]string, kmsEncrypted bool) bool {
	if IsKnownARN(arn) {
		return true
	}
	if kmsEncrypted {
		return true
	}

	positiveRegex := GetPositiveRegex()
	negativeRegex := GetNegativeRegex()

	// We care more about exclusion from crown jewels since we are more confident in this.
	if negativeRegex.MatchString(resourceName) {
		return false
	}

	for _, tag := range tags {
		key := tag["Key"]
		value := tag["Value"]
		if negativeRegex.MatchString(key) || negativeRegex.MatchString(value) {
			return false
		}
	}

	positiveMatch := false

	if positiveRegex.MatchString(resourceName) {
		positiveMatch = true
	}

	if !positiveMatch {
		for _, tag := range tags {
			key := tag["Key"]
			value := tag["Value"]
			if positiveRegex.MatchString(key) || positiveRegex.MatchString(value) {
				positiveMatch = true
				break
			}
		}
	}

	return positiveMatch
}
