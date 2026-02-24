package domain

// Step represents a step in the breach surfacing algorithm
type Step struct {
	Number      int
	Name        string
	Description string
}

// Algorithm steps for breach path detection
var (
	// Step1DetectCrownJewels identifies sensitive resources via heuristics
	Step1DetectCrownJewels = Step{
		Number:      1,
		Name:        "Detect Crown Jewels",
		Description: "Identifying sensitive resources via heuristics",
	}

	// Step2DirectExposure analyzes public access vectors
	Step2DirectExposure = Step{
		Number:      2,
		Name:        "Directly Exposed Resources",
		Description: "Analyzing public access vectors",
	}

	// Step3KMSSeparation separates KMS-encrypted from non-KMS resources
	Step3KMSSeparation = Step{
		Number:      3,
		Name:        "KMS vs Non-KMS",
		Description: "Mapping encryption keys and separating KMS-encrypted from non-KMS resources",
	}

	// Step4KMSPrincipals finds roles with KMS decrypt access
	Step4KMSPrincipals = Step{
		Number:      4,
		Name:        "KMS Principals",
		Description: "Finding roles with decryption access (direct and indirect) mapped to KMS resources",
	}

	// Step5NonKMSPrincipals finds roles with access to non-KMS resources
	Step5NonKMSPrincipals = Step{
		Number:      5,
		Name:        "Non-KMS Principals",
		Description: "Finding roles with access to non-KMS encrypted crown jewels",
	}

	// Step6SeedRiskyPrincipals builds the initial set of risky principals
	Step6SeedRiskyPrincipals = Step{
		Number:      6,
		Name:        "Seed of Risky Principals",
		Description: "Initial high-risk role set with direct access to crown jewels (after authorization verification)",
	}

	// Step7LateralRisk finds roles with lateral movement capabilities
	Step7LateralRisk = Step{
		Number:      7,
		Name:        "Include Lateral Risk",
		Description: "Roles that can assume/pass other risky roles",
	}

	// Step8PrivilegeEscalation finds roles with privilege escalation capabilities
	Step8PrivilegeEscalation = Step{
		Number:      8,
		Name:        "Include Privilege Escalation Risk",
		Description: "Roles that can write/grant permissions",
	}

	// Step9BreachSurface builds the complete breach surface of principals
	Step9BreachSurface = Step{
		Number:      9,
		Name:        "Breach Surface of Principals",
		Description: "Complete risky role set (seed + lateral + privilege escalation)",
	}

	// Step10ComputeMapping maps roles to internet-exposed compute resources
	Step10ComputeMapping = Step{
		Number:      10,
		Name:        "Internet-Exposed Workloads",
		Description: "Mapping risky roles to internet-exposed compute resources",
	}

	// Step11BreachPaths builds the final breach paths
	Step11BreachPaths = Step{
		Number:      11,
		Name:        "Breach Paths",
		Description: "Final attack path enumeration from internet-exposed workloads to crown jewels",
	}
)
