package main

import (
	"breachmap/internal/app"
	"breachmap/internal/breachpath"
	"breachmap/internal/crownjewels"
	"breachmap/internal/logging"
	"breachmap/internal/outputter"
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/joho/godotenv"
	"github.com/spf13/cobra"
)

func main() {
	var debug bool

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	rootCmd := &cobra.Command{
		Use:   "breachsurfacer",
		Short: "Breach Surfacer - AWS Security Scanner",
		Long:  "Detects and analyzes breach paths in AWS environment",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runBreachSurfacer(ctx, debug)
		},
		SilenceUsage: true,
	}

	rootCmd.Flags().BoolVar(&debug, "debug", false, "Enable debug logging (verbose output)")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// runBreachSurfacer is the main function that runs the breach surfacer - a novel
// 12 step algorithm for detecting breach paths in an AWS environment.
func runBreachSurfacer(ctx context.Context, debug bool) error {
	// Initialize all clients early - fail fast if any client cannot be initialized
	breachSurfacer, err := initializeBreachSurfacer(ctx, debug)
	if err != nil {
		return fmt.Errorf("error initializing breach surfacer: %w", err)
	}

	//  STEP 1: Detect Crown Jewels - Identify sensitive S3 buckets via heuristics
	crownJewels, err := crownjewels.GetCrownJewels(ctx, breachSurfacer.S3Client(), breachSurfacer.RDSClient())
	if err != nil {
		return fmt.Errorf("error getting crown jewels: %w", err)
	}

	// STEP 2 & 3: Resource-specific exposure & KMS separation
	s3Data, err := breachpath.ProcessS3ExposureAndKMSSeparation(ctx, breachSurfacer, crownJewels.S3CrownJewels)
	if err != nil {
		return fmt.Errorf("failed to process S3 steps 1.5-3: %w", err)
	}
	allEncryptedResources := s3Data.EncryptedResources
	allNonEncryptedResources := s3Data.NonEncryptedResources

	rdsData, err := breachpath.ProcessRDSExposureAndKMSSeparation(ctx, breachSurfacer, crownJewels.RDSJewels)
	if err != nil {
		return fmt.Errorf("failed to process RDS steps 1.5-3: %w", err)
	}
	// Merge RDS encrypted and non-encrypted resources with S3 resources
	allEncryptedResources = append(allEncryptedResources, rdsData.EncryptedResources...)
	allNonEncryptedResources = append(allNonEncryptedResources, rdsData.NonEncryptedResources...)

	// STEP 4: Shared KMS Principals (works for all resource types)
	resourceToCMKMap := make(map[string]map[string]string)
	resourceToCMKMap["S3"] = s3Data.BucketToCMKMap
	resourceToCMKMap["RDS"] = rdsData.DatabaseToCMKMap

	kmsIAMData, err := breachpath.FindKMSPrincipalsShared(ctx, breachSurfacer, allEncryptedResources, resourceToCMKMap)
	if err != nil {
		return fmt.Errorf("failed to find KMS principals: %w", err)
	}

	// STEP 5: Shared Non-KMS Principals (works for all resource types)
	nonKMSIAMData, err := breachpath.FindNonKMSPrincipalsShared(ctx, breachSurfacer, allNonEncryptedResources)
	if err != nil {
		return fmt.Errorf("failed to find non-KMS principals: %w", err)
	}

	// Merge KMS and Non-KMS IAM data
	sharedIAMData := breachpath.MergeKMSAndNonKMSIAMData(kmsIAMData, nonKMSIAMData)

	// Authorization Verification for S3 resources
	principalAccessResults, err := breachpath.VerifyS3Authorization(
		ctx,
		breachSurfacer,
		s3Data.AllBuckets,
		sharedIAMData.ResourceToRolesMap,
		sharedIAMData.CriticalRolesSet,
		sharedIAMData.CMKToRolesMap,
		resourceToCMKMap,
	)
	if err != nil {
		return fmt.Errorf("failed to verify S3 authorization: %w", err)
	}
	sharedIAMData.PrincipalAccessResults = principalAccessResults

	// Authorization Verification for RDS resources
	rdsPrincipalAccessResults, err := breachpath.VerifyRDSAuthorization(
		ctx,
		breachSurfacer,
		rdsData.AllDatabases,
		sharedIAMData.ResourceToRolesMap,
		sharedIAMData.CriticalRolesSet,
		sharedIAMData.CMKToRolesMap,
		resourceToCMKMap,
	)
	if err != nil {
		return fmt.Errorf("failed to verify RDS authorization: %w", err)
	}
	sharedIAMData.RDSPrincipalAccessResults = rdsPrincipalAccessResults

	// criticalRolesSet is updated by verifyAuthorization to only include exploitable roles
	// Convert to slice for next steps
	criticalRoles := make([]string, 0, len(sharedIAMData.CriticalRolesSet))
	for roleARN := range sharedIAMData.CriticalRolesSet {
		criticalRoles = append(criticalRoles, roleARN)
	}

	// STEP 6: Shared Seed of Risky Principals
	seedRiskyRoles := breachpath.BuildSeedRiskyPrincipalsShared(criticalRoles)
	sharedIAMData.SeedRiskyRoles = seedRiskyRoles

	// STEP 7: Shared Lateral Risk
	lateralMovementRoles, err := breachpath.FindLateralRiskShared(ctx, breachSurfacer, seedRiskyRoles)
	if err != nil {
		return fmt.Errorf("failed to find lateral risk: %w", err)
	}
	sharedIAMData.LateralMovementRoles = lateralMovementRoles

	// Add lateral movement roles to critical roles set
	for _, role := range lateralMovementRoles {
		sharedIAMData.CriticalRolesSet[role.RoleARN] = true
	}

	// STEP 8: Shared Privilege Escalation Risk
	privilegeEscalationRoles, err := breachpath.FindPrivilegeEscalationRiskShared(ctx, breachSurfacer)
	if err != nil {
		return fmt.Errorf("failed to find privilege escalation risk: %w", err)
	}
	sharedIAMData.PrivilegeEscalationRoles = privilegeEscalationRoles

	// Add privilege escalation roles to critical roles set
	for _, role := range privilegeEscalationRoles {
		sharedIAMData.CriticalRolesSet[role.RoleARN] = true
	}

	// STEP 9: Shared Breach Surface of Principals
	breachSurfaceRoles := breachpath.BuildBreachSurfaceShared(seedRiskyRoles, lateralMovementRoles, privilegeEscalationRoles)
	sharedIAMData.BreachSurfaceRoles = breachSurfaceRoles

	// STEP 10: Shared Compute Resources Mapping
	computeResourcesMapping, err := breachpath.MapToComputeResourcesShared(ctx, breachSurfacer, breachSurfaceRoles)
	if err != nil {
		return fmt.Errorf("failed to map to compute resources: %w", err)
	}

	// STEP 11: Resource-specific Breach Path Building
	// S3 breach paths
	s3BreachPaths, s3BreachOutputs, err := breachpath.BuildBreachPathsAndSave(ctx, breachSurfacer, s3Data, sharedIAMData, computeResourcesMapping)
	if err != nil {
		return fmt.Errorf("failed to build S3 breach paths: %w", err)
	}

	// RDS breach paths
	rdsBreachPaths, rdsBreachOutputs, err := breachpath.BuildRDSBreachPathsAndSave(ctx, breachSurfacer, rdsData, sharedIAMData, computeResourcesMapping)
	if err != nil {
		return fmt.Errorf("failed to build RDS breach paths: %w", err)
	}

	// Merge all breach paths
	breachPaths := append(s3BreachPaths, rdsBreachPaths...)
	breachOutputs := append(s3BreachOutputs, rdsBreachOutputs...)

	outputter.DisplayBreachPaths(breachPaths, breachOutputs)

	processedPaths, allResults, err := breachpath.ProofByContradiction(ctx, breachPaths, breachOutputs)
	if err != nil {
		return fmt.Errorf("failed to process LLM proof by contradiction: %w", err)
	}

	return outputter.GenerateReport(processedPaths, allResults)

}

func initializeBreachSurfacer(ctx context.Context, debug bool) (*app.BreachSurfacer, error) {
	// Load .env file if present (optional — production should use env vars or IAM roles directly)
	_ = godotenv.Load()

	// Set log level based on debug flag
	logging.SetLogLevel(logging.LogLevelWarn)
	if debug {
		logging.SetLogLevel(logging.LogLevelDebug)
		fmt.Println("\n🔍 Debug logging: ENABLED")
	}

	// Initialize all AWS clients (uses standard AWS credential chain: env vars, IAM role, SSO, etc.)
	return app.NewBreachSurfacer(ctx)
}
