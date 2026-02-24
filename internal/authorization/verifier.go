package authorization

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"breachmap/internal/domain"
	"breachmap/internal/logging"
)

// parsedKeyPolicy represents a parsed KMS key policy for efficient checking
type parsedKeyPolicy struct {
	allowsWildcard    bool
	allowedPrincipals map[string]bool
	hasDecryptAction  bool
}

// kmsDecryptCacheKey is used as a key for the result cache
type kmsDecryptCacheKey struct {
	principalARN string
	keyARN       string
}

// iamSimulateSemaphore is a shared semaphore that coordinates rate limiting across
// all concurrent validators (S3, RDS, KMS) calling SimulatePrincipalPolicy.
// Without this, each validator's independent semaphore could overwhelm the IAM API
// when running concurrently (e.g., 5 S3 + 5 RDS + 12 KMS = 22 concurrent calls).
var iamSimulateSemaphore = make(chan struct{}, 10)

// Verifier holds instance-level caches and dependencies for authorization verification.
// This allows for better testability and concurrent usage with different configurations.
type Verifier struct {
	keyPolicyCache        sync.Map
	parsedKeyPolicyCache  sync.Map
	kmsDecryptResultCache sync.Map

	// Dependencies
	GetAWSClient           func(ctx context.Context, service string) (interface{}, error)
	NormalizeToList        func(value interface{}) []string
	ExtractResourceNameFn  func(resourceARN string) string
}

// NewVerifier creates a new Verifier with the given dependencies.
func NewVerifier(
	getAWSClient func(ctx context.Context, service string) (interface{}, error),
	normalizeToList func(value interface{}) []string,
	extractResourceName func(resourceARN string) string,
) *Verifier {
	return &Verifier{
		GetAWSClient:          getAWSClient,
		NormalizeToList:       normalizeToList,
		ExtractResourceNameFn: extractResourceName,
	}
}

// ClearCaches clears all cached data. Useful for testing.
func (v *Verifier) ClearCaches() {
	v.keyPolicyCache = sync.Map{}
	v.parsedKeyPolicyCache = sync.Map{}
	v.kmsDecryptResultCache = sync.Map{}
}

// defaultVerifier is the package-level verifier for backward compatibility.
// Use NewVerifier() for better testability and isolation.
var defaultVerifier = &Verifier{}

// Dependencies holds injected functions (kept for backward compatibility)
type Dependencies struct {
	GetAWSClient      func(ctx context.Context, service string) (interface{}, error)
	NormalizeToList   func(value interface{}) []string
	ExtractBucketName func(bucketARN string) string
}

// SetDependencies sets the injected dependencies on the default verifier.
// Prefer using NewVerifier() for new code.
func SetDependencies(d Dependencies) {
	defaultVerifier.GetAWSClient = d.GetAWSClient
	defaultVerifier.NormalizeToList = d.NormalizeToList
	defaultVerifier.ExtractResourceNameFn = d.ExtractBucketName
}

// ClearCaches clears all cached data in the default verifier. Useful for testing.
func ClearCaches() {
	defaultVerifier.ClearCaches()
}

// isThrottlingError checks if an error is a throttling/rate limit error
func isThrottlingError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "Throttling") ||
		strings.Contains(errStr, "Rate exceeded") ||
		strings.Contains(errStr, "rate limit") ||
		strings.Contains(errStr, "429") ||
		strings.Contains(errStr, "TooManyRequests")
}

// simulateWithRateLimit wraps a SimulatePrincipalPolicy call with the shared semaphore
// to coordinate rate limiting across all concurrent validators (S3, RDS, KMS).
func simulateWithRateLimit(ctx context.Context, fn func() (bool, error)) (bool, error) {
	select {
	case iamSimulateSemaphore <- struct{}{}:
		defer func() { <-iamSimulateSemaphore }()
		return fn()
	case <-ctx.Done():
		return false, ctx.Err()
	}
}

// retryWithBackoff retries a function with exponential backoff on throttling errors
func retryWithBackoff(ctx context.Context, maxRetries int, fn func() (bool, error)) (bool, error) {
	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(1<<uint(attempt-1)) * time.Second
			select {
			case <-ctx.Done():
				return false, ctx.Err()
			case <-time.After(backoff):
			}
		}

		result, err := fn()
		if err == nil {
			return result, nil
		}

		lastErr = err
		if !isThrottlingError(err) {
			return false, err
		}
	}

	return false, fmt.Errorf("failed after %d retries: %w", maxRetries, lastErr)
}

// VerifyAuthorization verifies if a principal has exploitable access to an S3 bucket
func VerifyAuthorization(
	ctx context.Context,
	iamClient *iam.Client,
	kmsClient *kms.Client,
	s3Client *s3.Client,
	principalARN string,
	bucketARN string,
) (*domain.AuthorizationResult, error) {
	result := &domain.AuthorizationResult{
		SimulationDetails: make(map[string]interface{}),
	}

	bucketName := ""
	if defaultVerifier.ExtractResourceNameFn != nil {
		bucketName = defaultVerifier.ExtractResourceNameFn(bucketARN)
	} else if strings.HasPrefix(bucketARN, "arn:aws:s3:::") {
		bucketName = strings.TrimPrefix(bucketARN, "arn:aws:s3:::")
	}
	if bucketName == "" {
		return nil, fmt.Errorf("invalid bucket ARN format: %s", bucketARN)
	}

	objectARN := bucketARN + "/*"
	simInput := &iam.SimulatePrincipalPolicyInput{
		PolicySourceArn: aws.String(principalARN),
		ActionNames:     []string{"s3:GetObject"},
		ResourceArns:    []string{objectARN},
	}

	var simOutput *iam.SimulatePrincipalPolicyOutput
	var err error
	_, err = retryWithBackoff(ctx, 3, func() (bool, error) {
		return simulateWithRateLimit(ctx, func() (bool, error) {
			var retryErr error
			simOutput, retryErr = iamClient.SimulatePrincipalPolicy(ctx, simInput)
			if retryErr != nil {
				return false, retryErr
			}
			return true, nil
		})
	})

	if err != nil {
		if !isThrottlingError(err) {
			logging.LogDebug(fmt.Sprintf("S3 simulation failed for %s on %s: %v", principalARN, bucketARN, err))
		}
		result.SimulationDetails["s3_simulation_error"] = err.Error()
		result.ResourceAccessAllowed = false
	} else {
		s3Allowed := false
		explicitDeny := false
		for _, evalResult := range simOutput.EvaluationResults {
			if evalResult.EvalDecision == iamtypes.PolicyEvaluationDecisionTypeAllowed {
				s3Allowed = true
			}
			if evalResult.EvalDecision == iamtypes.PolicyEvaluationDecisionTypeExplicitDeny {
				explicitDeny = true
			}
		}
		result.ResourceAccessAllowed = s3Allowed && !explicitDeny
		result.SimulationDetails["s3_simulation"] = map[string]interface{}{
			"allowed":       s3Allowed && !explicitDeny,
			"explicit_deny": explicitDeny,
			"results":       len(simOutput.EvaluationResults),
		}
		logging.LogDebug(fmt.Sprintf("S3 IAM policy simulation for %s on %s: allowed=%v, explicitDeny=%v, results=%d (bucket policy check pending)",
			principalARN, bucketARN, result.ResourceAccessAllowed, explicitDeny, len(simOutput.EvaluationResults)))
	}

	// Step 2: Fetch bucket policy once and check for deny/allow
	policyStatements, policyErr := fetchBucketPolicyStatements(ctx, s3Client, bucketName)
	if policyErr != nil {
		logging.LogWarn("Failed to fetch bucket policy", map[string]interface{}{
			"bucket": bucketName,
			"error":  policyErr.Error(),
		})
	}

	// Step 2a: Check bucket policy for explicit denies targeting this principal
	// This is important because bucket policies can override identity-based policies
	if policyStatements != nil {
		bucketPolicyDenies := checkPolicyStatementsForDeny(policyStatements, bucketName, principalARN)
		if bucketPolicyDenies {
			logging.LogDebug(fmt.Sprintf("Bucket policy DENY overrides IAM policy for %s on %s: ResourceAccessAllowed=false (bucket policy explicitly denies this principal)",
				principalARN, bucketARN))
			result.ResourceAccessAllowed = false
			result.SimulationDetails["bucket_policy_deny"] = true
			result.Exploitable = false
			return result, nil
		}
	}

	// Step 2b: Check bucket policy for explicit allows targeting this principal
	// Bucket policies can grant access even if IAM policies don't
	if !result.ResourceAccessAllowed && policyStatements != nil {
		bucketPolicyAllows := checkPolicyStatementsForAllow(policyStatements, bucketName, principalARN)
		if bucketPolicyAllows {
			logging.LogDebug(fmt.Sprintf("Bucket policy ALLOW grants access for %s on %s: ResourceAccessAllowed=true (bucket policy allows this principal)",
				principalARN, bucketARN))
			result.ResourceAccessAllowed = true
			result.SimulationDetails["bucket_policy_allow"] = true
		}
	}

	if !result.ResourceAccessAllowed {
		result.Exploitable = false
		return result, nil
	}

	kmsKeyARN, err := GetKMSKeyFromBucket(ctx, s3Client, bucketName)
	if err != nil {
		logging.LogWarn("Failed to get KMS key for bucket", map[string]interface{}{
			"bucket": bucketName,
			"error":  err.Error(),
		})
		result.Exploitable = result.ResourceAccessAllowed
		return result, nil
	}

	if kmsKeyARN == "" {
		result.Exploitable = result.ResourceAccessAllowed
		return result, nil
	}

	var kmsAllowed bool
	_, err = retryWithBackoff(ctx, 3, func() (bool, error) {
		var retryErr error
		kmsAllowed, retryErr = SimulateKMSDecrypt(ctx, iamClient, kmsClient, principalARN, kmsKeyARN)
		if retryErr != nil {
			return false, retryErr
		}
		return true, nil
	})

	if err != nil {
		if !isThrottlingError(err) {
			logging.LogDebug(fmt.Sprintf("KMS simulation failed for %s on key %s: %v", principalARN, kmsKeyARN, err))
		}
		result.SimulationDetails["kms_simulation_error"] = err.Error()
		result.KMSDecryptAllowed = aws.Bool(false)
		result.Exploitable = false
		return result, nil
	}

	result.KMSDecryptAllowed = aws.Bool(kmsAllowed)
	result.SimulationDetails["kms_simulation"] = map[string]interface{}{
		"allowed": kmsAllowed,
		"key_arn": kmsKeyARN,
	}

	result.Exploitable = result.ResourceAccessAllowed && kmsAllowed

	return result, nil
}

// GetKMSKeyFromBucket extracts the KMS key ARN from bucket encryption configuration
func GetKMSKeyFromBucket(ctx context.Context, s3Client *s3.Client, bucketName string) (string, error) {
	encryption, err := s3Client.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		if strings.Contains(err.Error(), "ServerSideEncryptionConfigurationNotFoundError") ||
			strings.Contains(err.Error(), "NoSuchBucket") {
			return "", nil
		}
		return "", fmt.Errorf("failed to get bucket encryption: %w", err)
	}

	if encryption.ServerSideEncryptionConfiguration == nil {
		return "", nil
	}

	bucketLocation, err := s3Client.GetBucketLocation(ctx, &s3.GetBucketLocationInput{
		Bucket: aws.String(bucketName),
	})
	region := "us-east-1"
	if err == nil && bucketLocation.LocationConstraint != "" {
		region = string(bucketLocation.LocationConstraint)
		if region == "" {
			region = "us-east-1"
		}
	}

	var stsClient *sts.Client
	if defaultVerifier.GetAWSClient != nil {
		client, err := defaultVerifier.GetAWSClient(ctx, "sts")
		if err != nil {
			return "", fmt.Errorf("failed to get STS client: %w", err)
		}
		var ok bool
		stsClient, ok = client.(*sts.Client)
		if !ok {
			return "", fmt.Errorf("unexpected client type for STS: %T", client)
		}
	} else {
		return "", fmt.Errorf("GetAWSClient dependency not set")
	}

	callerIdentity, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", fmt.Errorf("failed to get caller identity: %w", err)
	}
	accountID := aws.ToString(callerIdentity.Account)

	for _, rule := range encryption.ServerSideEncryptionConfiguration.Rules {
		if rule.ApplyServerSideEncryptionByDefault != nil {
			if rule.ApplyServerSideEncryptionByDefault.SSEAlgorithm == "aws:kms" {
				if rule.ApplyServerSideEncryptionByDefault.KMSMasterKeyID != nil {
					keyID := aws.ToString(rule.ApplyServerSideEncryptionByDefault.KMSMasterKeyID)
					if strings.HasPrefix(keyID, "arn:aws:kms:") {
						return keyID, nil
					}
					keyARN := fmt.Sprintf("arn:aws:kms:%s:%s:key/%s", region, accountID, keyID)
					return keyARN, nil
				}
			}
		}
	}

	return "", nil
}

func getOrFetchKeyPolicy(ctx context.Context, kmsClient *kms.Client, keyARN string) (*string, error) {
	return defaultVerifier.getOrFetchKeyPolicy(ctx, kmsClient, keyARN)
}

func (v *Verifier) getOrFetchKeyPolicy(ctx context.Context, kmsClient *kms.Client, keyARN string) (*string, error) {
	if cached, ok := v.keyPolicyCache.Load(keyARN); ok {
		if policy, ok := cached.(*string); ok && policy != nil {
			return policy, nil
		}
	}

	keyPolicy, err := kmsClient.GetKeyPolicy(ctx, &kms.GetKeyPolicyInput{
		KeyId:      aws.String(keyARN),
		PolicyName: aws.String("default"),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get KMS key policy: %w", err)
	}

	v.keyPolicyCache.Store(keyARN, keyPolicy.Policy)
	return keyPolicy.Policy, nil
}

func parseKeyPolicy(keyARN string, policyJSON *string) (*parsedKeyPolicy, error) {
	return defaultVerifier.parseKeyPolicy(keyARN, policyJSON)
}

func (v *Verifier) parseKeyPolicy(keyARN string, policyJSON *string) (*parsedKeyPolicy, error) {
	if cached, ok := v.parsedKeyPolicyCache.Load(keyARN); ok {
		if parsed, ok := cached.(*parsedKeyPolicy); ok {
			return parsed, nil
		}
	}

	if policyJSON == nil || *policyJSON == "" {
		parsed := &parsedKeyPolicy{
			allowedPrincipals: make(map[string]bool),
		}
		v.parsedKeyPolicyCache.Store(keyARN, parsed)
		return parsed, nil
	}

	var policyDoc map[string]interface{}
	if err := json.Unmarshal([]byte(*policyJSON), &policyDoc); err != nil {
		return nil, err
	}

	parsed := &parsedKeyPolicy{
		allowedPrincipals: make(map[string]bool),
	}

	statements, ok := policyDoc["Statement"].([]interface{})
	if !ok {
		v.parsedKeyPolicyCache.Store(keyARN, parsed)
		return parsed, nil
	}

	for _, stmtInterface := range statements {
		stmt, ok := stmtInterface.(map[string]interface{})
		if !ok {
			continue
		}

		if stmt["Effect"] != "Allow" {
			continue
		}

		hasKMSAction := false
		var actions []string
		if v.NormalizeToList != nil {
			actions = v.NormalizeToList(stmt["Action"])
		} else {
			actions = normalizeToListInternal(stmt["Action"])
		}
		kmsActionsWithCapabilities := map[string]bool{
			"kms:Decrypt":                         true,
			"kms:GenerateDataKey":                 true,
			"kms:Encrypt":                         true,
			"kms:ReEncrypt":                       true,
			"kms:GenerateDataKeyWithoutPlaintext": true,
			"kms:CreateGrant":                     true,
			"kms:DescribeKey":                     true,
			"kms:*":                               true,
			"*":                                   true,
		}
		for _, action := range actions {
			if kmsActionsWithCapabilities[action] {
				hasKMSAction = true
				break
			}
		}

		if !hasKMSAction {
			continue
		}

		if principal, ok := stmt["Principal"].(map[string]interface{}); ok {
			if awsPrincipal, ok := principal["AWS"].(string); ok {
				if awsPrincipal == "*" {
					parsed.allowsWildcard = true
				} else {
					parsed.allowedPrincipals[awsPrincipal] = true
				}
			} else if awsPrincipalList, ok := principal["AWS"].([]interface{}); ok {
				for _, p := range awsPrincipalList {
					if pStr, ok := p.(string); ok {
						if pStr == "*" {
							parsed.allowsWildcard = true
						} else {
							parsed.allowedPrincipals[pStr] = true
						}
					}
				}
			}
		}
	}

	parsed.hasDecryptAction = true
	v.parsedKeyPolicyCache.Store(keyARN, parsed)
	return parsed, nil
}

func normalizeToListInternal(value interface{}) []string {
	switch v := value.(type) {
	case string:
		return []string{v}
	case []string:
		return v
	case []interface{}:
		result := make([]string, 0, len(v))
		for _, item := range v {
			if str, ok := item.(string); ok {
				result = append(result, str)
			}
		}
		return result
	default:
		return []string{}
	}
}

func checkKeyPolicyForPrincipalOptimized(keyARN string, principalARN string) (bool, error) {
	return defaultVerifier.checkKeyPolicyForPrincipalOptimized(keyARN, principalARN)
}

func (v *Verifier) checkKeyPolicyForPrincipalOptimized(keyARN string, principalARN string) (bool, error) {
	parsed, ok := v.parsedKeyPolicyCache.Load(keyARN)
	if !ok {
		return false, fmt.Errorf("parsed policy not found for key %s", keyARN)
	}

	policy, ok := parsed.(*parsedKeyPolicy)
	if !ok {
		return false, fmt.Errorf("invalid parsed policy type for key %s", keyARN)
	}

	if !policy.hasDecryptAction {
		return false, nil
	}

	if policy.allowsWildcard {
		return true, nil
	}

	return policy.allowedPrincipals[principalARN], nil
}

// SimulateKMSDecrypt simulates if a principal has kms:Decrypt permission on a KMS key
func SimulateKMSDecrypt(
	ctx context.Context,
	iamClient *iam.Client,
	kmsClient *kms.Client,
	principalARN string,
	keyARN string,
) (bool, error) {
	return defaultVerifier.SimulateKMSDecrypt(ctx, iamClient, kmsClient, principalARN, keyARN)
}

// SimulateKMSDecrypt simulates if a principal has kms:Decrypt permission on a KMS key
func (v *Verifier) SimulateKMSDecrypt(
	ctx context.Context,
	iamClient *iam.Client,
	kmsClient *kms.Client,
	principalARN string,
	keyARN string,
) (bool, error) {
	cacheKey := kmsDecryptCacheKey{principalARN: principalARN, keyARN: keyARN}
	if cached, ok := v.kmsDecryptResultCache.Load(cacheKey); ok {
		if result, ok := cached.(struct {
			allowed bool
			err     error
		}); ok {
			return result.allowed, result.err
		}
	}

	keyPolicy, err := v.getOrFetchKeyPolicy(ctx, kmsClient, keyARN)
	if err != nil {
		v.kmsDecryptResultCache.Store(cacheKey, struct {
			allowed bool
			err     error
		}{false, err})
		return false, err
	}

	parsedPolicy, err := v.parseKeyPolicy(keyARN, keyPolicy)
	if err != nil {
		keyPolicyAllows, checkErr := checkKeyPolicyForPrincipal(keyPolicy, principalARN)
		if checkErr != nil {
			v.kmsDecryptResultCache.Store(cacheKey, struct {
				allowed bool
				err     error
			}{false, checkErr})
			return false, checkErr
		}
		if !keyPolicyAllows {
			v.kmsDecryptResultCache.Store(cacheKey, struct {
				allowed bool
				err     error
			}{false, nil})
			return false, nil
		}
	} else {
		keyPolicyAllows, err := v.checkKeyPolicyForPrincipalOptimized(keyARN, principalARN)
		if err != nil {
			keyPolicyAllows, checkErr := checkKeyPolicyForPrincipal(keyPolicy, principalARN)
			if checkErr != nil {
				v.kmsDecryptResultCache.Store(cacheKey, struct {
					allowed bool
					err     error
				}{false, checkErr})
				return false, checkErr
			}
			if !keyPolicyAllows {
				v.kmsDecryptResultCache.Store(cacheKey, struct {
					allowed bool
					err     error
				}{false, nil})
				return false, nil
			}
		} else if !keyPolicyAllows {
			v.kmsDecryptResultCache.Store(cacheKey, struct {
				allowed bool
				err     error
			}{false, nil})
			return false, nil
		}
	}

	simInput := &iam.SimulatePrincipalPolicyInput{
		PolicySourceArn: aws.String(principalARN),
		ActionNames:     []string{"kms:Decrypt"},
		ResourceArns:    []string{keyARN},
	}

	simOutput, err := iamClient.SimulatePrincipalPolicy(ctx, simInput)
	if err != nil {
		if !isThrottlingError(err) {
			logging.LogDebug(fmt.Sprintf("KMS simulation API call failed for %s on key %s: %v", principalARN, keyARN, err))
		}
		err = fmt.Errorf("KMS simulation failed: %w", err)
		v.kmsDecryptResultCache.Store(cacheKey, struct {
			allowed bool
			err     error
		}{false, err})
		return false, err
	}

	identityAllowed := false
	explicitDeny := false
	for _, evalResult := range simOutput.EvaluationResults {
		if evalResult.EvalDecision == iamtypes.PolicyEvaluationDecisionTypeAllowed {
			identityAllowed = true
		}
		if evalResult.EvalDecision == iamtypes.PolicyEvaluationDecisionTypeExplicitDeny {
			explicitDeny = true
		}
	}
	identityAllowed = identityAllowed && !explicitDeny

	var keyPolicyAllows bool
	if parsedPolicy != nil {
		keyPolicyAllows, _ = v.checkKeyPolicyForPrincipalOptimized(keyARN, principalARN)
	} else {
		keyPolicyAllows, _ = checkKeyPolicyForPrincipal(keyPolicy, principalARN)
	}

	finalResult := identityAllowed && keyPolicyAllows

	v.kmsDecryptResultCache.Store(cacheKey, struct {
		allowed bool
		err     error
	}{finalResult, nil})
	return finalResult, nil
}

func checkKeyPolicyForPrincipal(policyJSON *string, principalARN string) (bool, error) {
	if policyJSON == nil || *policyJSON == "" {
		return false, nil
	}

	var policyDoc map[string]interface{}
	if err := json.Unmarshal([]byte(*policyJSON), &policyDoc); err != nil {
		return false, err
	}

	statements, ok := policyDoc["Statement"].([]interface{})
	if !ok {
		return false, nil
	}

	for _, stmtInterface := range statements {
		stmt, ok := stmtInterface.(map[string]interface{})
		if !ok {
			continue
		}

		if stmt["Effect"] != "Allow" {
			continue
		}

		principalMatches := false
		if principal, ok := stmt["Principal"].(map[string]interface{}); ok {
			if awsPrincipal, ok := principal["AWS"].(string); ok {
				if awsPrincipal == "*" || awsPrincipal == principalARN {
					principalMatches = true
				}
			} else if awsPrincipalList, ok := principal["AWS"].([]interface{}); ok {
				for _, p := range awsPrincipalList {
					if pStr, ok := p.(string); ok {
						if pStr == "*" || pStr == principalARN {
							principalMatches = true
							break
						}
					}
				}
			}
		}

		if !principalMatches {
			continue
		}

		var actions []string
		if defaultVerifier.NormalizeToList != nil {
			actions = defaultVerifier.NormalizeToList(stmt["Action"])
		} else {
			actions = normalizeToListInternal(stmt["Action"])
		}
		kmsActionsWithCapabilities := map[string]bool{
			"kms:Decrypt":                         true,
			"kms:GenerateDataKey":                 true,
			"kms:Encrypt":                         true,
			"kms:ReEncrypt":                       true,
			"kms:GenerateDataKeyWithoutPlaintext": true,
			"kms:CreateGrant":                     true,
			"kms:DescribeKey":                     true,
			"kms:*":                               true,
			"*":                                   true,
		}
		for _, action := range actions {
			if kmsActionsWithCapabilities[action] {
				return true, nil
			}
		}
	}

	return false, nil
}

// fetchBucketPolicyStatements fetches and parses the bucket policy, returning the parsed statements.
// Returns nil statements (with no error) if the bucket has no policy.
func fetchBucketPolicyStatements(
	ctx context.Context,
	s3Client *s3.Client,
	bucketName string,
) ([]interface{}, error) {
	policyOutput, err := s3Client.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		if strings.Contains(err.Error(), "NoSuchBucketPolicy") {
			return nil, nil
		}
		return nil, err
	}

	if policyOutput.Policy == nil {
		return nil, nil
	}

	var policyDoc map[string]interface{}
	if err := json.Unmarshal([]byte(*policyOutput.Policy), &policyDoc); err != nil {
		return nil, fmt.Errorf("failed to parse bucket policy: %w", err)
	}

	statements, ok := policyDoc["Statement"].([]interface{})
	if !ok {
		return nil, nil
	}

	return statements, nil
}

// checkPolicyStatementsForDeny checks parsed bucket policy statements for explicit Deny targeting the principal
func checkPolicyStatementsForDeny(
	statements []interface{},
	bucketName string,
	principalARN string,
) bool {
	for _, stmtInterface := range statements {
		stmt, ok := stmtInterface.(map[string]interface{})
		if !ok {
			continue
		}

		if stmt["Effect"] != "Deny" {
			continue
		}

		if !principalMatchesStatement(stmt, principalARN) {
			continue
		}

		var actions []string
		if defaultVerifier.NormalizeToList != nil {
			actions = defaultVerifier.NormalizeToList(stmt["Action"])
		} else {
			actions = normalizeToListInternal(stmt["Action"])
		}
		for _, action := range actions {
			if action == "s3:GetObject" || action == "s3:*" || action == "*" {
				return true
			}
		}
	}

	return false
}

// principalMatchesStatement checks if a principal ARN matches the Principal field of a policy statement.
// Extracted to avoid duplicating principal matching logic across deny/allow checks.
func principalMatchesStatement(stmt map[string]interface{}, principalARN string) bool {
	if principal, ok := stmt["Principal"].(string); ok {
		if principal == "*" {
			return true
		}
	} else if principal, ok := stmt["Principal"].(map[string]interface{}); ok {
		if awsPrincipal, ok := principal["AWS"].(string); ok {
			if awsPrincipal == "*" || awsPrincipal == principalARN {
				return true
			}
		} else if awsPrincipalList, ok := principal["AWS"].([]interface{}); ok {
			for _, p := range awsPrincipalList {
				if pStr, ok := p.(string); ok {
					if pStr == "*" || pStr == principalARN {
						return true
					}
				}
			}
		}
	}
	return false
}

// checkPolicyStatementsForAllow checks parsed bucket policy statements for explicit Allow targeting the principal
func checkPolicyStatementsForAllow(
	statements []interface{},
	bucketName string,
	principalARN string,
) bool {
	for _, stmtInterface := range statements {
		stmt, ok := stmtInterface.(map[string]interface{})
		if !ok {
			continue
		}

		if stmt["Effect"] != "Allow" {
			continue
		}

		if !principalMatchesStatement(stmt, principalARN) {
			continue
		}

		// Check if action includes s3:GetObject, s3:ListBucket, or wildcard
		var actions []string
		if defaultVerifier.NormalizeToList != nil {
			actions = defaultVerifier.NormalizeToList(stmt["Action"])
		} else {
			actions = normalizeToListInternal(stmt["Action"])
		}
		for _, action := range actions {
			if action == "s3:GetObject" || action == "s3:GetObjectVersion" || action == "s3:ListBucket" || action == "s3:*" || action == "*" {
				// Check if resource matches the bucket
				var resources []string
				if defaultVerifier.NormalizeToList != nil {
					resources = defaultVerifier.NormalizeToList(stmt["Resource"])
				} else {
					resources = normalizeToListInternal(stmt["Resource"])
				}
				for _, resourceStr := range resources {
					bucketARN := fmt.Sprintf("arn:aws:s3:::%s", bucketName)
					if resourceStr == bucketARN || resourceStr == bucketARN+"/*" || resourceStr == "*" {
						return true
					}
				}
			}
		}
	}

	return false
}

// ValidateKMSDecryptForRoles validates which roles can decrypt which CMKs using SimulatePrincipalPolicy
// Optimized with: key policy caching, batched API calls, result caching, and increased concurrency
// Returns three mappings:
// - cmkToRolesMap: CMK ARN -> list of role ARNs that can decrypt it
// - roleToCMKsMap: role ARN -> list of CMK ARNs it can decrypt
// - roleToActionTypeMap: role ARN -> "direct" (has kms:Decrypt) or "indirect" (only GenerateDataKey, etc.)
func ValidateKMSDecryptForRoles(
	ctx context.Context,
	iamClient *iam.Client,
	kmsClient *kms.Client,
	roleARNs []string,
	cmkSet map[string]bool,
) (map[string][]string, map[string][]string, map[string]string, error) {
	logging.LogDebug("--- Validating KMS Decrypt Permissions for Filtered Roles (Optimized) ---")

	cmkARNs := make([]string, 0, len(cmkSet))
	for cmkARN := range cmkSet {
		cmkARNs = append(cmkARNs, cmkARN)
	}

	logging.LogDebug(fmt.Sprintf("Validating %d roles against %d CMKs", len(roleARNs), len(cmkARNs)))

	// Fetch and cache key policies
	var keyPolicyWg sync.WaitGroup
	const maxConcurrentKeyPolicyFetches = 10
	keyPolicySemaphore := make(chan struct{}, maxConcurrentKeyPolicyFetches)

	for _, cmkARN := range cmkARNs {
		if _, ok := defaultVerifier.keyPolicyCache.Load(cmkARN); ok {
			if _, ok := defaultVerifier.parsedKeyPolicyCache.Load(cmkARN); !ok {
				if policy, ok := defaultVerifier.keyPolicyCache.Load(cmkARN); ok {
					if policyStr, ok := policy.(*string); ok {
						_, _ = defaultVerifier.parseKeyPolicy(cmkARN, policyStr)
					}
				}
			}
			continue
		}

		keyPolicyWg.Add(1)
		go func(keyARN string) {
			defer keyPolicyWg.Done()
			keyPolicySemaphore <- struct{}{}
			defer func() { <-keyPolicySemaphore }()

			policy, err := defaultVerifier.getOrFetchKeyPolicy(ctx, kmsClient, keyARN)
			if err != nil {
				logging.LogDebug(fmt.Sprintf("Failed to fetch key policy for %s: %v", keyARN, err))
			} else if policy != nil {
				_, _ = defaultVerifier.parseKeyPolicy(keyARN, policy)
			}
		}(cmkARN)
	}
	keyPolicyWg.Wait()

	cmkToRolesMap := make(map[string][]string)
	roleToCMKsMap := make(map[string][]string)
	var resultMu sync.Mutex

	const maxConcurrentBatchedValidations = 12
	batchedSemaphore := make(chan struct{}, maxConcurrentBatchedValidations)
	var batchedWg sync.WaitGroup

	type batchedResult struct {
		roleARN    string
		results    map[string]bool // cmkARN -> canDecrypt
		actionType string          // "direct" or "indirect"
		err        error
	}

	resultChan := make(chan batchedResult, len(roleARNs))

	for _, roleARN := range roleARNs {
		batchedWg.Add(1)
		go func(rARN string) {
			defer batchedWg.Done()
			batchedSemaphore <- struct{}{}
			defer func() { <-batchedSemaphore }()

			simInput1 := &iam.SimulatePrincipalPolicyInput{
				PolicySourceArn: aws.String(rARN),
				ActionNames: []string{
					"kms:Decrypt",
					"kms:GenerateDataKey",
					"kms:Encrypt",
					"kms:GenerateDataKeyWithoutPlaintext",
					"kms:CreateGrant",
					"kms:DescribeKey",
				},
				ResourceArns: cmkARNs,
			}

			var simOutput1 *iam.SimulatePrincipalPolicyOutput
			var err1 error

			_, err1 = retryWithBackoff(ctx, 3, func() (bool, error) {
				return simulateWithRateLimit(ctx, func() (bool, error) {
					var retryErr error
					simOutput1, retryErr = iamClient.SimulatePrincipalPolicy(ctx, simInput1)
					if retryErr != nil {
						return false, retryErr
					}
					return true, nil
				})
			})

			var simOutput2 *iam.SimulatePrincipalPolicyOutput
			var err2 error
			if err1 == nil {
				simInput2 := &iam.SimulatePrincipalPolicyInput{
					PolicySourceArn: aws.String(rARN),
					ActionNames:     []string{"kms:ReEncrypt"},
					ResourceArns:    cmkARNs,
				}

				_, err2 = retryWithBackoff(ctx, 3, func() (bool, error) {
					return simulateWithRateLimit(ctx, func() (bool, error) {
						var retryErr error
						simOutput2, retryErr = iamClient.SimulatePrincipalPolicy(ctx, simInput2)
						if retryErr != nil {
							return false, retryErr
						}
						return true, nil
					})
				})
			}

			if err1 != nil && err2 != nil {
				resultChan <- batchedResult{roleARN: rARN, results: nil, err: err1}
				return
			}

			// We have 6 actions (excluding ReEncrypt) and N CMKs, so we get 6*N results from first call
			// Plus 1*N results from ReEncrypt call
			// Use EvalActionName and EvalResourceName to match results to actions/resources
			// (AWS API does not guarantee result ordering)
			identityAllowedMap := make(map[string]bool)
			decryptAllowedMap := make(map[string]bool)   // Track if kms:Decrypt specifically is allowed
			explicitDenyCountMap := make(map[string]int) // Count how many actions are explicitly denied per CMK
			actionCount := 6                             // Number of KMS actions in first call (excluding ReEncrypt)
			reEncryptActionCount := 1                    // ReEncrypt actions in second call

			generateDataKeyAllowedMap := make(map[string]bool) // Track if kms:GenerateDataKey is allowed

			// Build a set of valid CMK ARNs for fast lookup
			cmkARNSet := make(map[string]bool, len(cmkARNs))
			for _, arn := range cmkARNs {
				cmkARNSet[arn] = true
			}

			// Process first call results using EvalActionName/EvalResourceName (not index ordering)
			if simOutput1 != nil {
				for _, evalResult := range simOutput1.EvaluationResults {
					cmkARN := aws.ToString(evalResult.EvalResourceName)
					actionName := aws.ToString(evalResult.EvalActionName)
					if !cmkARNSet[cmkARN] {
						continue
					}
					if evalResult.EvalDecision == iamtypes.PolicyEvaluationDecisionTypeAllowed {
						identityAllowedMap[cmkARN] = true
						if actionName == "kms:Decrypt" {
							decryptAllowedMap[cmkARN] = true
						}
						if actionName == "kms:GenerateDataKey" {
							generateDataKeyAllowedMap[cmkARN] = true
						}
					}
					if evalResult.EvalDecision == iamtypes.PolicyEvaluationDecisionTypeExplicitDeny {
						explicitDenyCountMap[cmkARN]++
					}
				}
			}

			// Process second call results (ReEncrypt) using EvalResourceName
			if simOutput2 != nil {
				for _, evalResult := range simOutput2.EvaluationResults {
					cmkARN := aws.ToString(evalResult.EvalResourceName)
					if !cmkARNSet[cmkARN] {
						continue
					}
					if evalResult.EvalDecision == iamtypes.PolicyEvaluationDecisionTypeAllowed {
						identityAllowedMap[cmkARN] = true
					}
					if evalResult.EvalDecision == iamtypes.PolicyEvaluationDecisionTypeExplicitDeny {
						explicitDenyCountMap[cmkARN]++
					}
				}
			}

			totalActionCount := actionCount + reEncryptActionCount

			// Now check key policies for each CMK (using cached parsed policies)
			finalResults := make(map[string]bool)
			hasDirectDecrypt := false // Track if this role has direct decrypt (kms:Decrypt) for any CMK
			for _, cmkARN := range cmkARNs {
				// If ALL actions are explicitly denied, block access
				// Otherwise, if ANY action is allowed, consider it allowed (unless key policy blocks)
				allActionsDenied := explicitDenyCountMap[cmkARN] == totalActionCount
				identityAllowed := identityAllowedMap[cmkARN] && !allActionsDenied

				var keyPolicyAllows bool
				if parsed, ok := defaultVerifier.parsedKeyPolicyCache.Load(cmkARN); ok {
					if parsedPolicy, ok := parsed.(*parsedKeyPolicy); ok {
						keyPolicyAllows = parsedPolicy.allowsWildcard || parsedPolicy.allowedPrincipals[rARN]
					}
				}

				// KMS requires both identity-based policy AND key policy to allow
				finalResult := identityAllowed && keyPolicyAllows
				finalResults[cmkARN] = finalResult

				// If this CMK allows access, check what permissions the role has
				if finalResult {
					// If role has kms:Decrypt permission, mark as direct
					if decryptAllowedMap[cmkARN] {
						hasDirectDecrypt = true
					}
				}
			}

			// Determine action type:
			// - "direct" if has kms:Decrypt (can directly decrypt, even if it also has GenerateDataKey)
			// - "indirect" if only has kms:GenerateDataKey (but not Decrypt)
			actionType := "indirect" // Default to indirect

			// Check if role has GenerateDataKey for any CMK that it can access
			hasAnyGenerateDataKey := false
			for _, cmkARN := range cmkARNs {
				if finalResults[cmkARN] && generateDataKeyAllowedMap[cmkARN] {
					hasAnyGenerateDataKey = true
					break
				}
			}

			// If role has kms:Decrypt, classify as direct (prioritize direct decrypt capability)
			// Only classify as indirect if it doesn't have Decrypt but has GenerateDataKey
			if hasDirectDecrypt {
				actionType = "direct"
			} else if hasAnyGenerateDataKey {
				// Only has GenerateDataKey (indirect capability)
				actionType = "indirect"
			}

			resultChan <- batchedResult{roleARN: rARN, results: finalResults, actionType: actionType, err: nil}
		}(roleARN)
	}

	go func() {
		batchedWg.Wait()
		close(resultChan)
	}()

	// Collect results
	roleToActionTypeMap := make(map[string]string)
	for result := range resultChan {
		if result.err != nil {
			continue
		}

		resultMu.Lock()
		for cmkARN, canDecrypt := range result.results {
			if canDecrypt {
				cmkToRolesMap[cmkARN] = append(cmkToRolesMap[cmkARN], result.roleARN)
				roleToCMKsMap[result.roleARN] = append(roleToCMKsMap[result.roleARN], cmkARN)
			}
		}
		// Store action type for this role (use "direct" if any CMK has direct, otherwise "indirect")
		if existingType, exists := roleToActionTypeMap[result.roleARN]; exists {
			// If we find direct decrypt for any CMK, mark the role as direct
			if result.actionType == "direct" || existingType == "direct" {
				roleToActionTypeMap[result.roleARN] = "direct"
			}
		} else {
			roleToActionTypeMap[result.roleARN] = result.actionType
		}
		resultMu.Unlock()
	}

	logging.LogDebug(fmt.Sprintf("Found %d role-CMK pairs with decrypt permissions", len(roleToCMKsMap)))
	return cmkToRolesMap, roleToCMKsMap, roleToActionTypeMap, nil
}

// ValidateS3AccessForRoles validates which roles can access which buckets
func ValidateS3AccessForRoles(
	ctx context.Context,
	iamClient *iam.Client,
	roleARNs []string,
	bucketARNs []string,
) (map[string][]string, error) {
	logging.LogDebug(fmt.Sprintf("Validating %d roles against %d buckets", len(roleARNs), len(bucketARNs)))
	if len(roleARNs) == 0 {
		logging.LogWarn("No roles provided for S3 access validation")
		return make(map[string][]string), nil
	}
	if len(bucketARNs) == 0 {
		logging.LogWarn("No buckets provided for S3 access validation")
		return make(map[string][]string), nil
	}

	type validationTask struct {
		roleARN   string
		bucketARN string
	}
	tasks := make([]validationTask, 0, len(roleARNs)*len(bucketARNs))
	for _, roleARN := range roleARNs {
		for _, bucketARN := range bucketARNs {
			tasks = append(tasks, validationTask{roleARN: roleARN, bucketARN: bucketARN})
		}
	}

	type validationResult struct {
		roleARN   string
		bucketARN string
		hasAccess bool
		err       error
	}

	resultChan := make(chan validationResult, len(tasks))
	var wg sync.WaitGroup

	const maxConcurrentValidations = 5
	semaphore := make(chan struct{}, maxConcurrentValidations)

	for _, task := range tasks {
		wg.Add(1)
		go func(t validationTask) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			hasAccess, err := retryWithBackoff(ctx, 3, func() (bool, error) {
				return simulateWithRateLimit(ctx, func() (bool, error) {
					objectARN := t.bucketARN + "/*"
					simInput := &iam.SimulatePrincipalPolicyInput{
						PolicySourceArn: aws.String(t.roleARN),
						ActionNames:     []string{"s3:GetObject", "s3:ListBucket"},
						ResourceArns:    []string{t.bucketARN, objectARN},
					}

					simOutput, err := iamClient.SimulatePrincipalPolicy(ctx, simInput)
					if err != nil {
						return false, err
					}

					for _, evalResult := range simOutput.EvaluationResults {
						if evalResult.EvalDecision == iamtypes.PolicyEvaluationDecisionTypeAllowed {
							return true, nil
						}
					}
					return false, nil
				})
			})

			resultChan <- validationResult{
				roleARN:   t.roleARN,
				bucketARN: t.bucketARN,
				hasAccess: hasAccess,
				err:       err,
			}
		}(task)
	}

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	bucketToRolesMap := make(map[string][]string)
	var mu sync.Mutex

	for result := range resultChan {
		if result.err == nil && result.hasAccess {
			mu.Lock()
			bucketToRolesMap[result.bucketARN] = append(bucketToRolesMap[result.bucketARN], result.roleARN)
			mu.Unlock()
		}
	}

	logging.LogDebug(fmt.Sprintf("Found %d bucket-role pairs with S3 access", len(bucketToRolesMap)))
	return bucketToRolesMap, nil
}

// ValidateRDSAccessForRoles validates which roles can access which RDS databases via IAM simulation
func ValidateRDSAccessForRoles(
	ctx context.Context,
	iamClient *iam.Client,
	roleARNs []string,
	dbARNs []string,
) (map[string][]string, error) {
	logging.LogDebug(fmt.Sprintf("Validating %d roles against %d RDS databases", len(roleARNs), len(dbARNs)))
	if len(roleARNs) == 0 || len(dbARNs) == 0 {
		return make(map[string][]string), nil
	}

	type task struct{ roleARN, dbARN string }
	tasks := make([]task, 0, len(roleARNs)*len(dbARNs))
	for _, r := range roleARNs {
		for _, d := range dbARNs {
			tasks = append(tasks, task{r, d})
		}
	}

	type result struct {
		roleARN, dbARN string
		hasAccess      bool
		err            error
	}

	resultChan := make(chan result, len(tasks))
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 5)

	for _, t := range tasks {
		wg.Add(1)
		go func(t task) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			hasAccess, err := retryWithBackoff(ctx, 3, func() (bool, error) {
				return simulateWithRateLimit(ctx, func() (bool, error) {
					simInput := &iam.SimulatePrincipalPolicyInput{
						PolicySourceArn: aws.String(t.roleARN),
						ActionNames:     []string{"rds-db:connect"},
						ResourceArns:    []string{t.dbARN},
					}
					simOutput, err := iamClient.SimulatePrincipalPolicy(ctx, simInput)
					if err != nil {
						return false, err
					}
					for _, eval := range simOutput.EvaluationResults {
						if eval.EvalDecision == iamtypes.PolicyEvaluationDecisionTypeAllowed {
							return true, nil
						}
					}
					return false, nil
				})
			})
			resultChan <- result{t.roleARN, t.dbARN, hasAccess, err}
		}(t)
	}

	go func() { wg.Wait(); close(resultChan) }()

	dbToRolesMap := make(map[string][]string)
	var mu sync.Mutex
	for r := range resultChan {
		if r.err == nil && r.hasAccess {
			mu.Lock()
			dbToRolesMap[r.dbARN] = append(dbToRolesMap[r.dbARN], r.roleARN)
			mu.Unlock()
		}
	}

	logging.LogDebug(fmt.Sprintf("Found %d database-role pairs with RDS access", len(dbToRolesMap)))
	return dbToRolesMap, nil
}
