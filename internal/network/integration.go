package network

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"breachmap/internal/domain"
	"breachmap/internal/logging"
)

/*
Integration - How to use network boundary checking with authorization

PURPOSE:
  This file provides functions to integrate network boundary checking
  into the existing breach path authorization flow.

INTEGRATION POINT:
  Call CheckAndUpdateAuthorization AFTER the standard authorization
  check (VerifyAuthorization) completes. This will:
    1. Run network boundary checks
    2. Update AuthorizationResult.NetworkBoundaries
    3. Update AuthorizationResult.BlockedByNetwork
    4. Set AuthorizationResult.Exploitable = false if blocked

EXAMPLE USAGE IN S3BUILDER:
  // After standard authorization check
  authResult := authorization.VerifyAuthorization(ctx, iamClient, kmsClient, s3Client, roleARN, bucketARN)

  // Add network boundary check
  network.CheckAndUpdateAuthorization(ctx, s3Client, ec2Client, &computeResource, bucketARN, bucketName, authResult)

  // Now authResult.Exploitable accounts for network boundaries
*/

// CheckAndUpdateAuthorization runs network boundary checks and updates AuthorizationResult
// This should be called AFTER standard IAM/KMS authorization checks
func CheckAndUpdateAuthorization(
	ctx context.Context,
	s3Client *s3.Client,
	ec2Client *ec2.Client,
	computeResource *domain.ComputeResource,
	bucketARN string,
	bucketName string,
	authResult *domain.AuthorizationResult,
) {
	if authResult == nil || computeResource == nil {
		return
	}

	// Only check network boundaries if IAM allows access
	// No point checking network if IAM already denies
	if !authResult.ResourceAccessAllowed {
		return
	}

	// If KMS is required and denied, skip network check
	if authResult.KMSDecryptAllowed != nil && !*authResult.KMSDecryptAllowed {
		return
	}

	// Run network boundary checks
	orchestrator := NewOrchestrator(s3Client, ec2Client)
	boundaryResult := orchestrator.CheckBoundariesForS3(ctx, computeResource, bucketARN, bucketName)

	// Update authorization result
	authResult.NetworkBoundaries = boundaryResult
	authResult.BlockedByNetwork = boundaryResult.AnyBlocks

	// If network boundaries block, path is not exploitable
	if boundaryResult.AnyBlocks {
		authResult.Exploitable = false
		logging.LogDebug("Network boundaries block breach path", map[string]interface{}{
			"source_vpc":   computeResource.VPCID,
			"target":       bucketARN,
			"blockers":     boundaryResult.BlockingChecks,
		})
	}
}

// FilterBreachPathsByNetwork filters out breach paths blocked by network boundaries
// Returns: (exploitable paths, blocked paths)
func FilterBreachPathsByNetwork(
	ctx context.Context,
	s3Client *s3.Client,
	ec2Client *ec2.Client,
	paths []domain.BreachPathOutput,
	computeResources map[string]*domain.ComputeResource, // roleARN -> ComputeResource
) ([]domain.BreachPathOutput, []domain.BreachPathOutput) {
	exploitable := make([]domain.BreachPathOutput, 0)
	blocked := make([]domain.BreachPathOutput, 0)

	orchestrator := NewOrchestrator(s3Client, ec2Client)

	for _, path := range paths {
		// Get compute resource for this path's role
		var computeResource *domain.ComputeResource
		if path.IAMRole != nil {
			computeResource = computeResources[path.IAMRole.RoleARN]
		}

		if computeResource == nil {
			// No network context, can't filter
			exploitable = append(exploitable, path)
			continue
		}

		// Check network boundaries
		resourceName := path.Store.ResourceName
		resourceARN := path.Store.ResourceARN
		boundaryResult := orchestrator.CheckBoundariesForS3(ctx, computeResource, resourceARN, resourceName)

		if boundaryResult.AnyBlocks {
			// Update authorization with network info
			if path.Authorization != nil {
				path.Authorization.NetworkBoundaries = boundaryResult
				path.Authorization.BlockedByNetwork = true
				path.Authorization.Exploitable = false
			}
			blocked = append(blocked, path)
		} else {
			exploitable = append(exploitable, path)
		}
	}

	logging.LogDebug("Network boundary filtering complete", map[string]interface{}{
		"total_paths":      len(paths),
		"exploitable":      len(exploitable),
		"blocked_by_network": len(blocked),
	})

	return exploitable, blocked
}

// PreFilterByVPCDeny does a quick VPC deny check before full authorization
// Use this to avoid expensive IAM simulations for paths that will be blocked anyway
// Returns true if the path would be blocked by VPC conditions
func PreFilterByVPCDeny(
	ctx context.Context,
	s3Client *s3.Client,
	bucketName string,
	sourceVPCID string,
) (bool, string) {
	if sourceVPCID == "" {
		return false, "No VPC context"
	}

	if s3Client == nil {
		return false, "No S3 client"
	}

	// Fetch bucket policy
	policyOutput, err := s3Client.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{
		Bucket: &bucketName,
	})
	if err != nil || policyOutput.Policy == nil {
		return false, "No bucket policy"
	}

	// Quick check for VPC conditions
	return QuickCheckVPCBlocked(*policyOutput.Policy, sourceVPCID)
}
