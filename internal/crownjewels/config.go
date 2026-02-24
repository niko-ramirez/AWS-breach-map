package crownjewels

import (
	_ "embed"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed crown_jewels.yaml
var defaultConfigYAML []byte

//go:embed arn_jewels.yaml
var defaultARNConfigYAML []byte

// PatternConfig holds categorized patterns for crown jewel detection
type PatternConfig struct {
	PositivePatterns map[string][]string `yaml:"positive_patterns"`
	NegativePatterns map[string][]string `yaml:"negative_patterns"`
}

// ARNConfig holds user-specified crown jewel ARNs
type ARNConfig struct {
	ARNJewels []string `yaml:"arn_jewels"`
}

// CompiledPatterns holds the compiled regex patterns
type CompiledPatterns struct {
	Positive *regexp.Regexp
	Negative *regexp.Regexp
}

var compiledPatterns *CompiledPatterns
var knownARNs = make(map[string]bool)

func init() {
	config, err := LoadConfig("")
	if err != nil {
		panic("failed to load default crown jewel config: " + err.Error())
	}
	compiledPatterns = CompilePatterns(config)

	// Load embedded ARN jewels
	var arnConfig ARNConfig
	if err := yaml.Unmarshal(defaultARNConfigYAML, &arnConfig); err == nil {
		for _, arn := range arnConfig.ARNJewels {
			knownARNs[arn] = true
		}
	}
}

// LoadConfig loads pattern configuration from YAML.
// If configPath is empty, uses embedded default config.
// If configPath is provided, loads from that file.
func LoadConfig(configPath string) (*PatternConfig, error) {
	var data []byte
	var err error

	if configPath == "" {
		data = defaultConfigYAML
	} else {
		data, err = os.ReadFile(configPath)
		if err != nil {
			return nil, err
		}
	}

	var config PatternConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

// CompilePatterns converts the pattern config into compiled regex patterns
func CompilePatterns(config *PatternConfig) *CompiledPatterns {
	positiveWords := flattenPatterns(config.PositivePatterns)
	negativeWords := flattenPatterns(config.NegativePatterns)

	return &CompiledPatterns{
		Positive: buildWordBoundaryRegex(positiveWords),
		Negative: buildWordBoundaryRegex(negativeWords),
	}
}

// flattenPatterns extracts all patterns from categorized map into a single slice
func flattenPatterns(categories map[string][]string) []string {
	var all []string
	for _, patterns := range categories {
		all = append(all, patterns...)
	}
	return all
}

// buildWordBoundaryRegex creates a regex that matches any of the words
// with word boundaries (supports hyphen, underscore, and camelCase separators)
func buildWordBoundaryRegex(words []string) *regexp.Regexp {
	if len(words) == 0 {
		return regexp.MustCompile(`^$`) // matches nothing
	}

	// Escape any regex special characters and join with |
	escaped := make([]string, len(words))
	for i, word := range words {
		escaped[i] = regexp.QuoteMeta(word)
	}

	// Pattern: word boundary or underscore, then any of the words, then word boundary or underscore
	pattern := `(?i)(?:\b|_)(` + strings.Join(escaped, "|") + `)(?:\b|_)`
	return regexp.MustCompile(pattern)
}

// GetPositiveRegex returns the compiled positive pattern regex
func GetPositiveRegex() *regexp.Regexp {
	return compiledPatterns.Positive
}

// GetNegativeRegex returns the compiled negative pattern regex
func GetNegativeRegex() *regexp.Regexp {
	return compiledPatterns.Negative
}

// IsKnownARN checks if an ARN is in the user-specified crown jewels list
func IsKnownARN(arn string) bool {
	return knownARNs[arn]
}
