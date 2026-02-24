package outputter

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"breachmap/internal/domain"
	"breachmap/internal/logging"
)

// FormatPathFlow creates a compact path representation
func FormatPathFlow(bp domain.BreachPath) string {
	var path strings.Builder

	path.WriteString("Internet → ")

	if bp.Exposure != nil {
		path.WriteString(fmt.Sprintf("🌐 %s → ", *bp.Exposure))
	} else if bp.PublicIP != nil {
		path.WriteString(fmt.Sprintf("🌐 Public IP (%s) → ", *bp.PublicIP))
	} else {
		path.WriteString("🌐 Public Access → ")
	}

	path.WriteString(fmt.Sprintf("%s %s", GetVectorIcon(bp.Vector), bp.ResourceID))

	if bp.AssumedRoleARN != "" {
		computeRoleName := ExtractRoleNameFromARN(bp.RoleARN)
		assumedRoleName := ExtractRoleNameFromARN(bp.AssumedRoleARN)
		path.WriteString(fmt.Sprintf(" → 🔐 Role (%s) → 🔐 Role (%s)", computeRoleName, assumedRoleName))
	} else {
		path.WriteString(fmt.Sprintf(" → 🔐 Role (%s)", bp.Role))
	}

	path.WriteString(fmt.Sprintf(" → 💎 %s", GetTargetDisplay(bp)))

	return path.String()
}

// FormatCheckResult formats a single verification check result
func FormatCheckResult(result domain.VerificationResult) string {
	contextIcon := GetContextIcon(result.Context)

	var resultIcon, resultText string
	switch result.Result {
	case "Yes":
		resultIcon = "✅"
		resultText = "YES (BLOCKED! 🛡️)"
	case "No":
		resultIcon = "❌"
		resultText = "NO  (Not blocked)"
	case "Error":
		resultIcon = "⚠️"
		resultText = fmt.Sprintf("ERROR (%s)", result.Error)
	case "Timeout":
		resultIcon = "⏱️"
		resultText = "TIMEOUT"
	default:
		resultIcon = "❓"
		resultText = result.Result
	}

	question := result.Question
	if len(question) > 50 {
		question = question[:47] + "..."
	}

	output := fmt.Sprintf("[%s %s]  %-50s  %s %s",
		contextIcon, result.Context, question, resultIcon, resultText)

	if result.Result == "Yes" && result.Reasoning != "" {
		output += fmt.Sprintf("\n      └─ %s", result.Reasoning)
	}

	return output + "\n"
}

// FormatConclusion formats the final conclusion section
func FormatConclusion(bp domain.BreachPath) string {
	var conclusion strings.Builder

	var statusIcon, statusText, riskLevel, riskIcon string
	var blockedCount, totalChecks int
	var summary string

	if bp.VerificationResults != nil {
		totalChecks = bp.VerificationResults.TotalChecks
		successfulChecks := bp.VerificationResults.SuccessfulChecks
		_ = bp.VerificationResults.FailedChecks

		for _, result := range bp.VerificationResults.Results {
			if result.Result == "Yes" {
				blockedCount++
			}
		}

		if bp.VerificationResults.Disproved {
			statusIcon = "✅"
			statusText = "DISPROVED (Path is BLOCKED)"
			riskLevel = "MITIGATED"
			riskIcon = "🛡️"

			var blockingControls []string
			for _, result := range bp.VerificationResults.Results {
				if result.Result == "Yes" {
					controlName := ExtractControlName(result.Question)
					blockingControls = append(blockingControls, controlName)
				}
			}

			if len(blockingControls) > 0 {
				summary = fmt.Sprintf("This path is BLOCKED by %d control(s):\n   • %s",
					blockedCount, strings.Join(blockingControls, "\n   • "))
			} else {
				summary = fmt.Sprintf("This path is BLOCKED by %d control(s).", blockedCount)
			}
		} else {
			statusIcon = "⚠️"
			statusText = "POTENTIALLY EXPLOITABLE"
			riskLevel = "HIGH"
			riskIcon = "🔴"
			summary = "This path is NOT blocked by any controls."
		}

		conclusion.WriteString(fmt.Sprintf("🎯 CONCLUSION: %s %s\n\n", statusIcon, statusText))
		conclusion.WriteString(fmt.Sprintf("✅ %d/%d checks completed  |  ", successfulChecks, totalChecks))
		if blockedCount > 0 {
			conclusion.WriteString(fmt.Sprintf("✅ %d control(s) block path  |  ", blockedCount))
		} else {
			conclusion.WriteString("❌ 0 controls block path  |  ")
		}
		conclusion.WriteString(fmt.Sprintf("%s Risk: %s\n\n", riskIcon, riskLevel))
		conclusion.WriteString(summary)
		conclusion.WriteString("\n\n")
	} else {
		statusIcon = "⏳"
		statusText = "PENDING VERIFICATION"
		conclusion.WriteString(fmt.Sprintf("🎯 CONCLUSION: %s %s\n\n", statusIcon, statusText))
		conclusion.WriteString("Verification checks have not been executed yet.\n\n")
	}

	if bp.VerificationResults != nil && !bp.VerificationResults.Disproved {
		conclusion.WriteString(FormatRecommendations(bp))
	} else if bp.VerificationResults != nil && bp.VerificationResults.Disproved {
		conclusion.WriteString("💡 Status: Path is secure. No action needed.\n")
	}

	return conclusion.String()
}

// FormatRecommendations generates recommendations based on the breach path
func FormatRecommendations(bp domain.BreachPath) string {
	var recs strings.Builder
	recs.WriteString("💡 Recommended Actions:\n")

	if bp.Vector == "Lambda" {
		if bp.Exposure != nil && strings.Contains(*bp.Exposure, "Function URL") {
			recs.WriteString("   1. Enable authentication on Function URL (AuthType: AWS_IAM)\n")
		}
		recs.WriteString("   2. Restrict Lambda role to least-privilege access\n")
		if bp.VPCID == nil {
			recs.WriteString("   3. Move Lambda to VPC with restricted network access\n")
		}
	} else if bp.Vector == "EC2" {
		recs.WriteString("   1. Remove public IP or restrict security group rules\n")
		recs.WriteString("   2. Restrict EC2 instance role to least-privilege access\n")
		recs.WriteString("   3. Ensure instance is in private subnet\n")
	}

	if bp.TargetType == "S3" {
		recs.WriteString("   4. Add S3 bucket policy with IP/VPC endpoint restrictions\n")
		if bp.TargetEncrypted != nil && *bp.TargetEncrypted && bp.KMSKeyID != nil {
			recs.WriteString("   5. Add KMS key policy conditions to restrict decrypt access\n")
		}
	} else if bp.TargetType == "RDS" {
		recs.WriteString("   4. Ensure RDS is in private subnet with restricted security groups\n")
		if bp.TargetEncrypted != nil && *bp.TargetEncrypted && bp.KMSKeyID != nil {
			recs.WriteString("   5. Add KMS key policy conditions to restrict decrypt access\n")
		}
	}

	return recs.String()
}

// Helper functions

func GetVectorIcon(vector string) string {
	switch vector {
	case "Lambda":
		return "⚡"
	case "EC2":
		return "🖥️"
	case "ECS":
		return "📦"
	case "EKS":
		return "☸️"
	case "ALB":
		return "🌐"
	default:
		return "🔧"
	}
}

func GetContextIcon(context string) string {
	switch strings.ToLower(context) {
	case "encryption":
		return "🔒"
	case "data":
		return "💾"
	case "network":
		return "🌐"
	case "identity":
		return "🔐"
	case "compute":
		return "⚙️"
	case "trust":
		return "🤝"
	case "org":
		return "🏢"
	default:
		return "📋"
	}
}

func GetTargetDisplay(bp domain.BreachPath) string {
	target := bp.TargetDB
	if strings.Contains(target, "::") {
		parts := strings.Split(target, "::")
		if len(parts) > 1 {
			resourcePart := parts[len(parts)-1]
			resourcePart = strings.TrimSuffix(resourcePart, "/*")
			if strings.Contains(resourcePart, ":") {
				parts2 := strings.Split(resourcePart, ":")
				resourcePart = parts2[len(parts2)-1]
			}
			return fmt.Sprintf("%s (%s)", bp.TargetType, resourcePart)
		}
	}
	return fmt.Sprintf("%s (%s)", bp.TargetType, target)
}

// ExtractControlName extracts a human-readable control name from a question
func ExtractControlName(question string) string {
	questionLower := strings.ToLower(question)

	if strings.Contains(questionLower, "kms key policy") {
		return "KMS key policy"
	}
	if strings.Contains(questionLower, "s3 bucket policy") {
		return "S3 bucket policy"
	}
	if strings.Contains(questionLower, "public access block") || strings.Contains(questionLower, "pab") {
		return "S3 Public Access Block"
	}
	if strings.Contains(questionLower, "iam role policy") || strings.Contains(questionLower, "iam policy") {
		return "IAM role policy"
	}
	if strings.Contains(questionLower, "security group") {
		return "Security group rules"
	}
	if strings.Contains(questionLower, "vpc endpoint") {
		return "VPC endpoint policy"
	}
	if strings.Contains(questionLower, "lambda function url") {
		return "Lambda Function URL authentication"
	}
	if strings.Contains(questionLower, "encryption") {
		return "Encryption configuration"
	}

	words := strings.Fields(question)
	if len(words) > 3 {
		startIdx := 0
		for i, word := range words {
			if strings.ToLower(word) == "does" || strings.ToLower(word) == "is" {
				startIdx = i + 1
				break
			}
		}
		if startIdx < len(words) && startIdx+3 < len(words) {
			return strings.Join(words[startIdx:startIdx+3], " ")
		}
	}

	return "Security control"
}

// FormatBreachPathReport generates a simplified report
func FormatBreachPathReport(bp domain.BreachPath, breachOutput *domain.BreachPathOutput) string {
	var report strings.Builder

	report.WriteString("═══════════════════════════════════════════════════════════════════════════════\n")
	report.WriteString(fmt.Sprintf("🔍 BREACH PATH ANALYSIS: %s → %s\n", GetVectorIcon(bp.Vector), bp.TargetType))
	report.WriteString("═══════════════════════════════════════════════════════════════════════════════\n\n")

	report.WriteString("📍 Path: ")
	report.WriteString(FormatPathFlow(bp))
	report.WriteString("\n\n")

	if breachOutput != nil && breachOutput.Authorization != nil {
		report.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
		report.WriteString("🔍 DETERMINISTIC AUTHORIZATION VERIFICATION\n")
		report.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")

		auth := breachOutput.Authorization
		isRDS := bp.TargetType == "RDS"

		if isRDS {
			// RDS-specific authorization display
			if auth.ResourceAccessAllowed { // Reused for RDS access
				report.WriteString("✅ RDS Access: ALLOWED\n")
				report.WriteString("   • IAM policy simulation: rds-db:connect = allowed\n")
			} else {
				report.WriteString("❌ RDS Access: DENIED\n")
				report.WriteString("   • IAM policy simulation: rds-db:connect = denied\n")
			}
		} else {
			// S3-specific authorization display
			if auth.ResourceAccessAllowed {
				report.WriteString("✅ S3 Access: ALLOWED\n")
				report.WriteString("   • IAM policy simulation: s3:GetObject = allowed\n")
			} else {
				report.WriteString("❌ S3 Access: DENIED\n")
				report.WriteString("   • IAM policy simulation: s3:GetObject = denied\n")
			}
		}

		if auth.KMSDecryptAllowed != nil {
			if *auth.KMSDecryptAllowed {
				report.WriteString("✅ KMS Decrypt: ALLOWED\n")
				report.WriteString("   • KMS key policy allows decrypt for this role\n")
			} else {
				report.WriteString("❌ KMS Decrypt: DENIED\n")
				report.WriteString("   • KMS key policy blocks decrypt for this role\n")
			}
		} else {
			if isRDS {
				report.WriteString("ℹ️  KMS Decrypt: N/A\n")
				report.WriteString("   • Database does not use KMS encryption or is unencrypted\n")
			} else {
				report.WriteString("ℹ️  KMS Decrypt: N/A\n")
				report.WriteString("   • Bucket does not use KMS encryption (SSE-S3 or no encryption)\n")
			}
		}

		report.WriteString("\n")
	}

	report.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")

	var statusIcon, statusText string
	isRDS := bp.TargetType == "RDS"
	accessType := "S3"
	if isRDS {
		accessType = "RDS"
	}

	if breachOutput != nil && breachOutput.Authorization != nil {
		if breachOutput.Authorization.Exploitable {
			statusIcon = "⚠️"
			statusText = "POTENTIALLY_EXPLOITABLE"
			report.WriteString(fmt.Sprintf("🎯 CONCLUSION: %s %s\n\n", statusIcon, statusText))
			report.WriteString(fmt.Sprintf("   • %s access is allowed", accessType))
			if breachOutput.Authorization.KMSDecryptAllowed != nil {
				if *breachOutput.Authorization.KMSDecryptAllowed {
					report.WriteString(" and KMS decrypt is allowed")
				} else {
					report.WriteString(" but KMS decrypt is denied")
				}
			}
			report.WriteString("\n   • 🔴 Risk: HIGH - Path appears exploitable\n\n")
		} else {
			statusIcon = "✅"
			statusText = "DISPROVED"
			report.WriteString(fmt.Sprintf("🎯 CONCLUSION: %s %s\n\n", statusIcon, statusText))
			report.WriteString("   • Authorization verification shows path is blocked\n")
			report.WriteString("   • 🛡️ Risk: MITIGATED - Path is not exploitable\n\n")
		}
	} else {
		statusIcon = "⚠️"
		statusText = "NOT_VERIFIED"
		report.WriteString(fmt.Sprintf("🎯 CONCLUSION: %s %s\n\n", statusIcon, statusText))
		report.WriteString("   • Authorization verification not available\n")
		report.WriteString("   • ⚠️  Risk: UNKNOWN - Cannot determine exploitability\n\n")
	}

	if bp.LateralMovement || bp.PrivilegeEscalation {
		report.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
		report.WriteString("🔄 ADDITIONAL RISK FACTORS\n")
		report.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")

		if bp.LateralMovement {
			report.WriteString("🔄 Lateral Movement: YES\n")
			report.WriteString("   • This role can assume or pass other risky roles\n")
			report.WriteString("   • Attackers could use this to move to more privileged roles\n\n")
		}

		if bp.PrivilegeEscalation {
			report.WriteString("⬆️  Privilege Escalation: YES\n")
			report.WriteString("   • This role can modify IAM permissions\n")
			report.WriteString("   • Attackers could grant themselves additional access\n\n")
		}
	}

	report.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")

	return report.String()
}

// ExtractRoleNameFromARN extracts role name from ARN
func ExtractRoleNameFromARN(roleARN string) string {
	if strings.Contains(roleARN, "/") {
		parts := strings.Split(roleARN, "/")
		return parts[len(parts)-1]
	}
	return roleARN
}

func DisplayHeader(title string) {
	if title != "" {
		fmt.Println("\n" + strings.Repeat("═", 79))
		fmt.Println(title)
	}
	fmt.Println(strings.Repeat("═", 79))
}

func DisplayBreachPaths(breachPaths []domain.BreachPath, breachOutputs []domain.BreachPathOutput) {
	logging.SetLogLevel(logging.LogLevelInfo)

	// Display scan summary
	DisplayHeader("📊 SCAN SUMMARY")

	// Extract summary stats from outputs
	ec2ToS3Count := 0
	lambdaToS3Count := 0
	ec2ToRDSCount := 0
	lambdaToRDSCount := 0
	publicS3Paths := 0
	publicRDSPaths := 0

	for _, breachOutput := range breachOutputs {
		switch breachOutput.PathType {
		case "EC2_TO_BUCKET":
			ec2ToS3Count++
		case "LAMBDA_TO_BUCKET":
			lambdaToS3Count++
		case "EC2_TO_RDS":
			ec2ToRDSCount++
		case "LAMBDA_TO_RDS":
			lambdaToRDSCount++
		case "PUBLIC_BUCKET":
			publicS3Paths++
		case "PUBLIC_DATABASE":
			publicRDSPaths++
		}
	}

	totalEC2 := ec2ToS3Count + ec2ToRDSCount
	totalLambda := lambdaToS3Count + lambdaToRDSCount

	fmt.Printf("\n🌐 Internet-Exposed Workloads:\n")
	fmt.Printf("   • EC2 Instances: %d\n", totalEC2)
	fmt.Printf("   • Lambda Functions: %d\n", totalLambda)
	fmt.Printf("   • Total: %d\n", totalEC2+totalLambda)

	fmt.Printf("\n🔗 Breach Paths Found: %d\n", len(breachPaths))
	if len(breachPaths) > 0 {
		// S3 paths
		if ec2ToS3Count > 0 {
			fmt.Printf("   • EC2 → S3: %d path(s)\n", ec2ToS3Count)
		}
		if lambdaToS3Count > 0 {
			fmt.Printf("   • Lambda → S3: %d path(s)\n", lambdaToS3Count)
		}
		if publicS3Paths > 0 {
			fmt.Printf("   • Public Bucket Access: %d path(s)\n", publicS3Paths)
		}
		// RDS paths
		if ec2ToRDSCount > 0 {
			fmt.Printf("   • EC2 → RDS: %d path(s)\n", ec2ToRDSCount)
		}
		if lambdaToRDSCount > 0 {
			fmt.Printf("   • Lambda → RDS: %d path(s)\n", lambdaToRDSCount)
		}
		if publicRDSPaths > 0 {
			fmt.Printf("   • Public Database Access: %d path(s)\n", publicRDSPaths)
		}
	}

	DisplayHeader("")

	if len(breachPaths) == 0 {
		fmt.Println("\n✅ No breach paths found!")
		fmt.Println("Possible reasons:")
		fmt.Println("  1. No EC2 instances with public IPs")
		fmt.Println("  2. No IAM roles with S3/RDS access")
		fmt.Println("  3. No S3 buckets or RDS databases matching crown jewel criteria")
	}
}

func GenerateReport(processedPaths []domain.BreachPath, allResults []domain.BreachPathOutput) error {
	DisplayHeader("📊 SUMMARY STATISTICS")

	disprovedCount := 0
	exploitableCount := 0
	failedCount := 0
	totalChecks := 0
	successfulChecks := 0

	for _, bp := range processedPaths {
		if bp.VerifiedStatus == "DISPROVED" {
			disprovedCount++
		} else if bp.VerifiedStatus == "POTENTIALLY_EXPLOITABLE" {
			exploitableCount++
		} else {
			failedCount++
		}
		if bp.VerificationResults != nil {
			totalChecks += bp.VerificationResults.TotalChecks
			successfulChecks += bp.VerificationResults.SuccessfulChecks
		}
	}

	fmt.Printf("   🔍 Total Breach Paths:         %d\n", len(processedPaths))
		// Count by authorization status
		authExploitable := 0
		authDisproved := 0
		authNotVerified := 0
		lateralMovementCount := 0
		privilegeEscalationCount := 0
		for _, bp := range processedPaths {
			if bp.VerifiedStatus == "POTENTIALLY_EXPLOITABLE" {
				authExploitable++
			} else if bp.VerifiedStatus == "DISPROVED" {
				authDisproved++
			} else {
				authNotVerified++
			}
			if bp.LateralMovement {
				lateralMovementCount++
			}
			if bp.PrivilegeEscalation {
				privilegeEscalationCount++
			}
		}
		fmt.Printf("   ✅ Disproved (Authorization):  %d\n", authDisproved)
		fmt.Printf("   ⚠️  Potentially Exploitable:   %d\n", authExploitable)
		fmt.Printf("   ⚠️  Not Verified:              %d\n", authNotVerified)
		if lateralMovementCount > 0 {
			fmt.Printf("   🔄 Lateral Movement Paths:     %d\n", lateralMovementCount)
		}
		if privilegeEscalationCount > 0 {
			fmt.Printf("   ⬆️  Privilege Escalation Paths:  %d\n", privilegeEscalationCount)
		}
		fmt.Printf("\n   🔍 Authorization Verification:\n")
		fmt.Printf("      • Deterministic checks only (no AI analysis)\n")
		fmt.Printf("      • IAM policy simulation + KMS key policy evaluation\n")
	

	// ============================================================================
	// RESULTS PERSISTENCE
	// ============================================================================
	// Save all breach paths and detailed results to JSON files for further analysis
	// ============================================================================
	DisplayHeader("💾 SAVING RESULTS")

	// Ensure results directory exists
	resultsDir := "results"
	if err := os.MkdirAll(resultsDir, 0755); err != nil {
		return fmt.Errorf("failed to create results directory: %w", err)
	}

	// Save all processed paths
	allPathsJSON, _ := json.MarshalIndent(processedPaths, "", "  ")
	allPathsFile := resultsDir + "/all_breach_paths.json"
	if err := os.WriteFile(allPathsFile, allPathsJSON, 0644); err != nil {
		return fmt.Errorf("failed to save all breach paths: %w", err)
	}
	fmt.Printf("✓ Saved all breach paths to: %s\n", allPathsFile)

	// Save all outputs
	if len(allResults) > 0 {
		allOutputsJSON, _ := json.MarshalIndent(allResults, "", "  ")
		allOutputsFile := resultsDir + "/all_breach_paths_results.json"
		if err := os.WriteFile(allOutputsFile, allOutputsJSON, 0644); err != nil {
			return fmt.Errorf("failed to save all detailed results: %w", err)
		}
		fmt.Printf("✓ Saved all detailed results to: %s\n", allOutputsFile)
	}

	DisplayHeader("                          END OF REPORT")
	return nil
}
