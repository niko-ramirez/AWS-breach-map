package domain

// APIResponse contains the response from an AWS API call
type APIResponse struct {
	APIName         string `json:"api_name"`
	ResponseJSON    string `json:"response_json"`
	ResponseSummary string `json:"response_summary"`
	Error           string `json:"error,omitempty"`
	Success         bool   `json:"success"`
}

// QuestionAPIResponses maps a question ID to API responses
type QuestionAPIResponses struct {
	QuestionID string        `json:"question_id"`
	Responses  []APIResponse `json:"responses"`
}

// EvaluationRequest contains a question and API responses for evaluation
type EvaluationRequest struct {
	PathContext string        `json:"path_context"`
	QuestionID  string        `json:"question_id"`
	Context     string        `json:"context"`
	Question    string        `json:"question"`
	Responses   []APIResponse `json:"responses"`
}

// QuestionEvaluation contains the LLM's evaluation result
type QuestionEvaluation struct {
	PathID      string   `json:"path_id"`
	PathContext string   `json:"path_context"`
	QuestionID  string   `json:"question_id"`
	Context     string   `json:"context"`
	Question    string   `json:"question"`
	APINames    []string `json:"api_names"`
	Answer      string   `json:"answer"`
	Reasoning   string   `json:"reasoning"`
}

// BatchQuestionRequest is used within BatchEvaluationRequest
type BatchQuestionRequest struct {
	QuestionID string        `json:"question_id"`
	Context    string        `json:"context"`
	Question   string        `json:"question"`
	Responses  []APIResponse `json:"responses"`
}

// BatchEvaluationRequest contains multiple questions for batch evaluation
type BatchEvaluationRequest struct {
	PathContext string                 `json:"path_context"`
	Questions   []BatchQuestionRequest `json:"questions"`
}

// BatchEvaluationResponse contains evaluations for multiple questions
type BatchEvaluationResponse struct {
	Evaluations []QuestionEvaluation `json:"evaluations"`
}


// VerificationResult represents the outcome of a single check
type VerificationResult struct {
	QuestionID string `json:"question_id"`
	Context    string `json:"context"`
	Question   string `json:"question"`
	Result     string `json:"result"`
	Reasoning  string `json:"reasoning,omitempty"`
	Error      string `json:"error,omitempty"`
}

// PathVerificationResults contains all verification results for a breach path
type PathVerificationResults struct {
	PathID           string               `json:"path_id"`
	Results          []VerificationResult `json:"results"`
	Disproved        bool                 `json:"disproved"`
	DisprovedBy      []string             `json:"disproved_by,omitempty"`
	TotalChecks      int                  `json:"total_checks"`
	SuccessfulChecks int                  `json:"successful_checks"`
	FailedChecks     int                  `json:"failed_checks"`
}
