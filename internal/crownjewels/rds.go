package crownjewels

import (
	"breachmap/internal/domain"
	"breachmap/internal/logging"
	"breachmap/internal/outputter"
	"context"
	"fmt"
	"log"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/rds/types"
)

// EnumerateRDSDatabases enumerates RDS databases and identifies Crown Jewels
func EnumerateRDSDatabases(ctx context.Context, rdsClient *rds.Client) ([]domain.RDSJewel, error) {
	startTime := time.Now()
	metrics := logging.GetMetrics()

	crownJewels := []domain.RDSJewel{}
	ignoredRDSInstances := []string{}
	crownJewelNames := []string{}

	paginator := rds.NewDescribeDBInstancesPaginator(rdsClient, &rds.DescribeDBInstancesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			log.Printf("Warning: Failed to get RDS page: %v, continuing with partial results", err)
			// Return partial results rather than failing completely
			if len(crownJewels) > 0 {
				return crownJewels, nil
			}
			return nil, fmt.Errorf("failed to describe DB instances: %w", err)
		}

		for _, db := range page.DBInstances {

			instanceArn := aws.ToString(db.DBInstanceArn)
			instanceIdentifer := aws.ToString(db.DBInstanceIdentifier)
			tags := getRDSTags(db)
			isKMSEncypted, kmsKeyID := isRDSEncrypted(db)

			if !IsCrownJewel(instanceArn, instanceIdentifer, tags, isKMSEncypted) {
				ignoredRDSInstances = append(ignoredRDSInstances, instanceIdentifer)
				continue
			}

			crownJewelNames = append(crownJewelNames, instanceIdentifer)

			// Capture IAM authentication status
			iamAuthEnabled := false
			if db.IAMDatabaseAuthenticationEnabled != nil {
				iamAuthEnabled = *db.IAMDatabaseAuthenticationEnabled
			}

			// Capture public accessibility status
			publiclyAccessible := false
			if db.PubliclyAccessible != nil {
				publiclyAccessible = *db.PubliclyAccessible
			}

			// Capture engine type
			engine := aws.ToString(db.Engine)

			// Capture network information for boundary checking
			var vpcID *string
			var subnetIDs []string
			var securityGroupIDs []string
			var port *int32
			var endpoint *string

			// Get VPC and subnet info from DB subnet group
			if db.DBSubnetGroup != nil {
				vpcID = db.DBSubnetGroup.VpcId
				for _, subnet := range db.DBSubnetGroup.Subnets {
					if subnet.SubnetIdentifier != nil {
						subnetIDs = append(subnetIDs, *subnet.SubnetIdentifier)
					}
				}
			}

			// Get security groups
			for _, sg := range db.VpcSecurityGroups {
				if sg.VpcSecurityGroupId != nil {
					securityGroupIDs = append(securityGroupIDs, *sg.VpcSecurityGroupId)
				}
			}

			// Get port and endpoint
			if db.Endpoint != nil {
				port = db.Endpoint.Port
				endpoint = db.Endpoint.Address
			}

			crownJewels = append(crownJewels, domain.RDSJewel{
				ARN:                instanceArn,
				ResourceType:       "RDS",
				Name:               instanceIdentifer,
				Encrypted:          &isKMSEncypted,
				KMSKeyID:           kmsKeyID,
				IAMAuthEnabled:     &iamAuthEnabled,
				PubliclyAccessible: &publiclyAccessible,
				Engine:             &engine,
				// Network info
				VPCID:            vpcID,
				SubnetIDs:        subnetIDs,
				SecurityGroupIDs: securityGroupIDs,
				Port:             port,
				Endpoint:         endpoint,
			})
			
		}
	}

	if len(ignoredRDSInstances) > 0 {
		fmt.Printf("\n🚫 RDS Ignored (not crown jewels): %d database(s)\n", len(ignoredRDSInstances))
		displayResourceNames(ignoredRDSInstances, 10)
	}

	fmt.Printf("\n💎 RDS Crown Jewels Detected: %d database(s)\n", len(crownJewelNames))
	if len(crownJewelNames) > 0 {
		displayResourceNames(crownJewelNames, len(crownJewelNames))
	}

	enumDuration := time.Since(startTime)

	// Output Step 1: Crown Jewels
	fmt.Print(outputter.FormatStepOutputWithTiming(1, "Detect Crown Jewels",
		"Identifying sensitive RDS databases based on encryption and naming patterns",
		struct {
			CrownJewels    domain.CrownJewels
			IgnoredRDSInstances []string
		}{domain.CrownJewels{RDSJewels: &crownJewels}, ignoredRDSInstances}, enumDuration))

	metrics.RecordOperation("enumerate_rds_databases", enumDuration, true, 0, len(crownJewels), nil)
	logging.LogInfo("Found critical databases", map[string]interface{}{
		"database_count":  len(crownJewelNames),
		"ignored_count": len(ignoredRDSInstances),
	})

	log.Printf("Found %d crown jewel RDS databases", len(crownJewels))
	return crownJewels, nil
}


func getRDSTags(db types.DBInstance) []map[string]string{
	// Convert tags
	tags := make([]map[string]string, 0)
	for _, tag := range db.TagList {
		tags = append(tags, map[string]string{
			"Key":   aws.ToString(tag.Key),
			"Value": aws.ToString(tag.Value),
		})
	}
	return tags
}

func isRDSEncrypted(db types.DBInstance) (bool, *string) {
	encrypted := db.StorageEncrypted != nil && *db.StorageEncrypted
	var kmsKeyID *string
	if encrypted && db.KmsKeyId != nil {
		kmsKeyID = db.KmsKeyId
	} 

	return encrypted, kmsKeyID
}