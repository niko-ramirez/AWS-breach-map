package breachpath

import (
	"breachmap/internal/domain"
	"breachmap/internal/outputter"
	"context"
	"fmt"
)

// ProofByContradiction processes each breach path found in Steps 1-11:
//   - Execute verification checks via AWS API calls
//   - Evaluate if controls block exploitability
//   - Determine final status: DISPROVED or POTENTIALLY_EXPLOITABLE
func ProofByContradiction(ctx context.Context, breachPaths []domain.BreachPath, breachOutputs []domain.BreachPathOutput) ([]domain.BreachPath, []domain.BreachPathOutput, error) {
	fmt.Printf("\nStep 3: Processing %d breach path(s)...\n", len(breachPaths))
	outputter.DisplayHeader("")

	var processedPaths []domain.BreachPath
	var allResults []domain.BreachPathOutput

	for pathIdx := range breachPaths {
		bp := &breachPaths[pathIdx]
		var bpOutput *domain.BreachPathOutput
		if pathIdx < len(breachOutputs) {
			bpOutput = &breachOutputs[pathIdx]
		}

		bucketName := outputter.ExtractBucketNameFromARN(bp.TargetDB)
		fmt.Printf("\n[%d/%d] Processing: %s → %s (%s)\n",
			pathIdx+1, len(breachPaths), bp.Vector, bucketName, bp.PathID)

	
			// Show authorization verification results instead
			if bpOutput != nil && bpOutput.Authorization != nil {
				auth := bpOutput.Authorization
				fmt.Printf("  🔍 Authorization Verification:\n")
				if auth.ResourceAccessAllowed {
					fmt.Printf("     ✅ S3 Access: ALLOWED\n")
				} else {
					fmt.Printf("     ❌ S3 Access: DENIED\n")
				}
				if auth.KMSDecryptAllowed != nil {
					if *auth.KMSDecryptAllowed {
						fmt.Printf("     ✅ KMS Decrypt: ALLOWED\n")
					} else {
						fmt.Printf("     ❌ KMS Decrypt: DENIED\n")
					}
				} else {
					fmt.Printf("     ℹ️  KMS Decrypt: N/A (no KMS encryption)\n")
				}
				if auth.Exploitable {
					bp.VerifiedStatus = "POTENTIALLY_EXPLOITABLE"
					fmt.Printf("  ⚠️  Status: POTENTIALLY_EXPLOITABLE\n")
				} else {
					bp.VerifiedStatus = "DISPROVED"
					fmt.Printf("  ✅ Status: DISPROVED (authorization check failed)\n")
				}
			} else {
				bp.VerifiedStatus = "NOT_VERIFIED"
				fmt.Printf("  ⚠️  Status: NOT_VERIFIED (no authorization data)\n")
			}
		

		processedPaths = append(processedPaths, *bp)
		if bpOutput != nil {
			allResults = append(allResults, *bpOutput)
		}

		// Display report immediately after processing (real-time)
		fmt.Printf("\n─── Report %d of %d ───\n", pathIdx+1, len(breachPaths))
		
			fmt.Println(outputter.FormatBreachPathReport(*bp, bpOutput))
		

		// Add resource details if available
		if bpOutput != nil {
			outputter.DisplayHeader("📊 RESOURCE DETAILS")

			if bpOutput.Container != nil {
				fmt.Printf("\n🖥️  EC2 Instance: %s\n", bpOutput.Container.InstanceID)
				if bpOutput.Container.PublicIP != nil {
					fmt.Printf("   Public IP: %s\n", *bpOutput.Container.PublicIP)
				}
				fmt.Printf("   Region: %s\n", bpOutput.Container.Region)
			}

			if bpOutput.IAMRole != nil {
				fmt.Printf("\n🔐 IAM Role: %s\n", bpOutput.IAMRole.RoleName)
				fmt.Printf("   Risk Profile: %s\n", bpOutput.IAMRole.RiskProfile)
			}

			fmt.Printf("\n💾 Data Store: %s\n", bpOutput.Store.ResourceName)
			if bpOutput.Store.KMSKeyID != nil {
				fmt.Printf("   🔒 KMS Encryption: %s\n", *bpOutput.Store.KMSKeyID)
			}
			fmt.Printf("   Crown Jewel: %v (%s)\n", bpOutput.Store.IsCrownJewel, bpOutput.Store.CrownJewelReason)

			// Show authorization results if available
			if bpOutput.Authorization != nil {
				fmt.Printf("\n🔍 Authorization Verification:\n")
				auth := bpOutput.Authorization
				if auth.ResourceAccessAllowed {
					fmt.Printf("   ✅ S3 Access: ALLOWED\n")
				} else {
					fmt.Printf("   ❌ S3 Access: DENIED\n")
				}
				if auth.KMSDecryptAllowed != nil {
					if *auth.KMSDecryptAllowed {
						fmt.Printf("   ✅ KMS Decrypt: ALLOWED\n")
					} else {
						fmt.Printf("   ❌ KMS Decrypt: DENIED\n")
					}
				} else {
					fmt.Printf("   ℹ️  KMS Decrypt: N/A (no KMS encryption)\n")
				}
				if auth.Exploitable {
					fmt.Printf("   ⚠️  Exploitable: YES\n")
				} else {
					fmt.Printf("   ✅ Exploitable: NO (blocked)\n")
				}
			}

			// Show lateral movement and privilege escalation flags if set
			if bp.LateralMovement {
				fmt.Printf("\n🔄 Lateral Movement: YES (role can assume/pass other risky roles)\n")
			}
			if bp.PrivilegeEscalation {
				fmt.Printf("⬆️  Privilege Escalation: YES (role can modify IAM permissions)\n")
			}
		}

		fmt.Println() // Add spacing between reports
	}
	return processedPaths, allResults, nil
}

