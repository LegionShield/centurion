package predict

import (
	"bufio"
	_ "embed"
	"fmt"
	"strings"
	"sync"
)

//go:embed data/regular.cfg
var cfg string

//go:embed data/regular.dict
var dict string

// DomainGenerator
type DomainGenerator struct {
	categories map[string][]string
	patterns   []string
	subdomain  string
	domain     string
	output     chan string
	count      int
	mu         sync.Mutex
}

// NewDomainGenerator
func NewDomainGenerator(output chan string) (*DomainGenerator, error) {
	dg := &DomainGenerator{
		categories: make(map[string][]string),
		output:     output,
	}

	if err := dg.loadDictionary(); err != nil {
		return nil, fmt.Errorf("failed to load dictionary file: %v", err)
	}

	if err := dg.loadPatterns(); err != nil {
		return nil, fmt.Errorf("failed to load config file: %v", err)
	}

	return dg, nil
}

func (dg *DomainGenerator) loadDictionary() error {
	scanner := bufio.NewScanner(strings.NewReader(dict))
	var currentCategory string

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			currentCategory = line[1 : len(line)-1]
			dg.categories[currentCategory] = []string{}
		} else if currentCategory != "" {
			dg.categories[currentCategory] = append(dg.categories[currentCategory], line)
		}
	}

	return scanner.Err()
}

func (dg *DomainGenerator) loadPatterns() error {
	scanner := bufio.NewScanner(strings.NewReader(cfg))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			dg.patterns = append(dg.patterns, line)
		}
	}

	return scanner.Err()
}

// SetBaseDomain
func (dg *DomainGenerator) SetBaseDomain(domain string) {
	parts := strings.Split(domain, ".")
	if len(parts) <= 2 {
		dg.subdomain = ""
		dg.domain = domain
	} else {
		dg.subdomain = parts[0]
		dg.domain = strings.Join(parts[1:], ".")
	}
}

// GenerateDomains
func (dg *DomainGenerator) GenerateDomains() int {
	dg.mu.Lock()
	dg.count = 0
	dg.mu.Unlock()

	if dg.subdomain == "" && dg.domain == "" {
		return 0
	}

	for _, pattern := range dg.patterns {
		dg.processPattern(pattern, map[string]string{
			"subdomain": dg.subdomain,
			"domain":    dg.domain,
		})
	}

	dg.mu.Lock()
	result := dg.count
	dg.mu.Unlock()
	return result
}

// processPattern
func (dg *DomainGenerator) processPattern(pattern string, replacements map[string]string) {
	startIdx := strings.Index(pattern, "{")
	if startIdx == -1 {
		if pattern != "" && dg.output != nil {
			dg.mu.Lock()
			dg.output <- pattern
			dg.count++
			dg.mu.Unlock()
		}
		return
	}

	endIdx := strings.Index(pattern, "}")
	if endIdx == -1 || endIdx < startIdx {
		return
	}

	tagName := pattern[startIdx+1 : endIdx]

	if value, exists := replacements[tagName]; exists {
		newPattern := pattern[:startIdx] + value + pattern[endIdx+1:]
		dg.processPattern(newPattern, replacements)
		return
	}

	values, exists := dg.categories[tagName]
	if !exists || len(values) == 0 {
		newPattern := pattern[:startIdx] + pattern[endIdx+1:]
		dg.processPattern(newPattern, replacements)
		return
	}

	for _, value := range values {
		newReplacements := make(map[string]string)
		for k, v := range replacements {
			newReplacements[k] = v
		}
		newReplacements[tagName] = value

		newPattern := pattern[:startIdx] + value + pattern[endIdx+1:]
		dg.processPattern(newPattern, newReplacements)
	}
}

// PredictDomains
func PredictDomains(domain string, output chan string) (int, error) {
	if output == nil {
		return 0, fmt.Errorf("output object cannot be nil")
	}

	generator, err := NewDomainGenerator(output)
	if err != nil {
		return 0, err
	}

	generator.SetBaseDomain(domain)

	return generator.GenerateDomains(), nil
}
