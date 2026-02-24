package domain

// PathType represents the type of breach path
type PathType string

const (
	PathTypeEC2ToBucket    PathType = "EC2_TO_BUCKET"
	PathTypeLambdaToBucket PathType = "LAMBDA_TO_BUCKET"
	PathTypePublicBucket   PathType = "PUBLIC_BUCKET"
)

// VerifiedStatus represents the verification status of a breach path
type VerifiedStatus string

const (
	VerifiedStatusPotentiallyExploitable VerifiedStatus = "POTENTIALLY_EXPLOITABLE"
	VerifiedStatusDisproved              VerifiedStatus = "DISPROVED"
	VerifiedStatusVerificationFailed     VerifiedStatus = "VERIFICATION_FAILED"
	VerifiedStatusNotVerified            VerifiedStatus = "NOT_VERIFIED"
)

// S3AccessAction represents the scope of S3 access
type S3AccessAction string

const (
	S3AccessReadOnly   S3AccessAction = "READ_ONLY"
	S3AccessWrite      S3AccessAction = "WRITE"
	S3AccessAdmin      S3AccessAction = "FULL_ADMIN"
	S3AccessNarrowRead S3AccessAction = "NARROW_READ"
)

// LogLevel represents log levels
type LogLevel string

const (
	LogLevelDebug LogLevel = "DEBUG"
	LogLevelInfo  LogLevel = "INFO"
	LogLevelWarn  LogLevel = "WARN"
	LogLevelError LogLevel = "ERROR"
)
