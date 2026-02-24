package breachpath

import (
	"breachmap/internal/app"
	"breachmap/internal/domain"
	"breachmap/internal/logging"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// MergeKMSAndNonKMSIAMData merges KMS and Non-KMS IAM data into a unified SharedIAMData structure
func MergeKMSAndNonKMSIAMData(kmsIAMData, nonKMSIAMData *domain.SharedIAMData) *domain.SharedIAMData {
	// Merge resource to roles maps (nonKMS overwrites KMS if same resourceARN)
	resourceToRolesMap := make(map[string][]string)
	for k, v := range kmsIAMData.ResourceToRolesMap {
		resourceToRolesMap[k] = v
	}
	for k, v := range nonKMSIAMData.ResourceToRolesMap {
		resourceToRolesMap[k] = v
	}

	// Merge critical roles sets
	criticalRolesSet := make(map[string]bool)
	for k := range kmsIAMData.CriticalRolesSet {
		criticalRolesSet[k] = true
	}
	for k := range nonKMSIAMData.CriticalRolesSet {
		criticalRolesSet[k] = true
	}

	return &domain.SharedIAMData{
		CMKToRolesMap:       kmsIAMData.CMKToRolesMap,
		RoleToCMKsMap:       kmsIAMData.RoleToCMKsMap,
		RoleToActionTypeMap: kmsIAMData.RoleToActionTypeMap,
		ResourceToRolesMap:  resourceToRolesMap,
		CriticalRolesSet:    criticalRolesSet,
		FilteredRoles:       append(kmsIAMData.FilteredRoles, nonKMSIAMData.FilteredRoles...),
	}
}

// BuildS3BreachPathsAndSave builds breach paths (Step 11) and saves them to a file
func BuildBreachPathsAndSave(
	ctx context.Context,
	breachSurfacer *app.BreachSurfacer,
	s3Data *domain.S3ResourceData,
	sharedIAMData *domain.SharedIAMData,
	computeResourcesMapping domain.RoleToComputeResourcesMapping,
) ([]domain.BreachPath, []domain.BreachPathOutput, error) {
	// ============================================================================
	// Step 11: Resource-specific S3 Breach Path Building
	// ============================================================================
	breachPaths, breachOutputs, err := buildS3BreachPaths(
		ctx,
		breachSurfacer,
		s3Data,
		sharedIAMData,
		computeResourcesMapping,
	)
	if err != nil {
		return breachPaths, breachOutputs, fmt.Errorf("failed to build S3 breach paths: %w", err)
	}
	// ============================================================================

	// Automatically save results to file
	defaultFilename := fmt.Sprintf("s3_breach_paths_%s.json", time.Now().Format("20060102_150405"))
	if err := SaveBreachPathsToFile(breachOutputs, defaultFilename); err != nil {
		// Suppress this log during scan - only show if log level allows
		logging.LogWarn("Failed to save breach paths to file", map[string]interface{}{"error": err.Error()})
	} else {
		// Suppress this log during scan - only show if log level allows
		logging.LogDebug("Breach paths saved", map[string]interface{}{"file": filepath.Join("results", "s3_breach_paths", defaultFilename)})
	}

	return breachPaths, breachOutputs, nil
}

// SaveBreachPathsToFile saves breach path outputs to a JSON file
// Files are saved to results/s3_breach_paths/ directory
// If filename is an absolute path, it will be used as-is
func SaveBreachPathsToFile(outputs []domain.BreachPathOutput, filename string) error {
	var filePath string

	// Check if filename is an absolute path
	if filepath.IsAbs(filename) {
		filePath = filename
	} else {
		// Create results directory structure
		outputDir := filepath.Join("results", "s3_breach_paths")
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			return fmt.Errorf("failed to create output directory: %w", err)
		}

		// Construct full file path
		filePath = filepath.Join(outputDir, filename)
	}

	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(outputs); err != nil {
		return fmt.Errorf("failed to encode results: %w", err)
	}

	return nil
}
