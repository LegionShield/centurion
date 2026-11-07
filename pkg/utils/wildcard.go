package utils

import (
	"github.com/LegionShield/legion-subdomain/v2/pkg/core/gologger"
	"github.com/LegionShield/legion-subdomain/v2/pkg/runner/result"
	"sort"
	"strings"
)

type Pair struct {
	Key   string
	Value int
}
type PairList []Pair

func (p PairList) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }
func (p PairList) Len() int           { return len(p) }
func (p PairList) Less(i, j int) bool { return p[i].Value > p[j].Value }

// A function to turn a map into a PairList, then sort and return it.
func sortMapByValue(m map[string]int) PairList {
	p := make(PairList, len(m))
	i := 0
	for k, v := range m {
		p[i] = Pair{k, v}
		i++
	}
	sort.Sort(p)
	return p
}

// WildFilterOutputResult
func WildFilterOutputResult(outputType string, results []result.Result) []result.Result {
	if outputType == "none" {
		return results
	} else if outputType == "basic" {
		return FilterWildCard(results)
	} else if outputType == "advanced" {
		return FilterWildCardAdvanced(results)
	}
	return nil
}

// FilterWildCard
func FilterWildCard(results []result.Result) []result.Result {
	if len(results) == 0 {
		return results
	}

	gologger.Debugf("Wildcard filter processing %d records...\n", len(results))

	ipFrequency := make(map[string]int)
	ipToDomains := make(map[string][]string)
	totalDomains := len(results)

	for _, res := range results {
		for _, answer := range res.Answers {
			if !strings.HasPrefix(answer, "CNAME ") && !strings.HasPrefix(answer, "NS ") &&
				!strings.HasPrefix(answer, "TXT ") && !strings.HasPrefix(answer, "PTR ") {
				ipFrequency[answer]++
				ipToDomains[answer] = append(ipToDomains[answer], res.Subdomain)
			}
		}
	}

	sortedIPs := sortMapByValue(ipFrequency)

	// 1. IP
	// 2.
	suspiciousIPs := make(map[string]bool)

	for _, pair := range sortedIPs {
		ip := pair.Key
		count := pair.Value

		percentage := float64(count) / float64(totalDomains) * 100

		var threshold float64
		if totalDomains < 100 {
			threshold = 30
		} else if totalDomains < 1000 {
			threshold = 20
		} else {
			threshold = 10
		}

		absoluteThreshold := 70

		if percentage > threshold || count > absoluteThreshold {
			gologger.Debugf("Suspicious wildcard IP: %s (resolved %d domains, %.2f%%)\n",
				ip, count, percentage)
			suspiciousIPs[ip] = true
		}
	}

	var filteredResults []result.Result

	for _, res := range results {
		validRecord := false
		var filteredAnswers []string

		for _, answer := range res.Answers {
			if strings.HasPrefix(answer, "CNAME ") || strings.HasPrefix(answer, "NS ") ||
				strings.HasPrefix(answer, "TXT ") || strings.HasPrefix(answer, "PTR ") {
				validRecord = true
				filteredAnswers = append(filteredAnswers, answer)
			} else if !suspiciousIPs[answer] {
				validRecord = true
				filteredAnswers = append(filteredAnswers, answer)
			}
		}

		if validRecord && len(filteredAnswers) > 0 {
			filteredRes := result.Result{
				Subdomain: res.Subdomain,
				Answers:   filteredAnswers,
			}
			filteredResults = append(filteredResults, filteredRes)
		}
	}

	gologger.Infof("Wildcard filter done: %d records → %d valid\n",
		totalDomains, len(filteredResults))

	return filteredResults
}

// FilterWildCardAdvanced
func FilterWildCardAdvanced(results []result.Result) []result.Result {
	if len(results) == 0 {
		return results
	}

	gologger.Debugf("Advanced wildcard detection: processing %d records...\n", len(results))

	ipFrequency := make(map[string]int)
	ipPrefixVariety := make(map[string]map[string]bool)
	ipTLDVariety := make(map[string]map[string]bool)
	ipToDomains := make(map[string][]string)
	cnameRecords := make(map[string][]string)

	totalDomains := len(results)

	for _, res := range results {
		subdomain := res.Subdomain
		parts := strings.Split(subdomain, ".")

		prefix := ""
		tld := ""
		if len(parts) > 1 {
			prefix = parts[0]
			tld = strings.Join(parts[1:], ".")
		} else {
			prefix = subdomain
			tld = subdomain
		}

		for _, answer := range res.Answers {
			if strings.HasPrefix(answer, "CNAME ") {
				cnameParts := strings.SplitN(answer, " ", 2)
				if len(cnameParts) == 2 {
					cnameTarget := cnameParts[1]
					cnameRecords[subdomain] = append(cnameRecords[subdomain], cnameTarget)
				}
				continue
			}

			if !strings.HasPrefix(answer, "NS ") &&
				!strings.HasPrefix(answer, "TXT ") &&
				!strings.HasPrefix(answer, "PTR ") {
				ipFrequency[answer]++

				if ipPrefixVariety[answer] == nil {
					ipPrefixVariety[answer] = make(map[string]bool)
				}
				if ipTLDVariety[answer] == nil {
					ipTLDVariety[answer] = make(map[string]bool)
				}

				ipPrefixVariety[answer][prefix] = true
				ipTLDVariety[answer][tld] = true

				ipToDomains[answer] = append(ipToDomains[answer], subdomain)
			}
		}
	}

	sortedIPs := sortMapByValue(ipFrequency)

	suspiciousIPs := make(map[string]float64) // IP ->

	for _, pair := range sortedIPs {
		ip := pair.Key
		count := pair.Value

		suspiciousScore := 0.0

		freqPercentage := float64(count) / float64(totalDomains) * 100

		prefixVariety := len(ipPrefixVariety[ip])
		prefixVarietyRatio := float64(prefixVariety) / float64(count) * 100

		tldVariety := len(ipTLDVariety[ip])

		// 1.
		if freqPercentage > 30 {
			suspiciousScore += 40
		} else if freqPercentage > 10 {
			suspiciousScore += 20
		} else if freqPercentage > 5 {
			suspiciousScore += 10
		}

		// 2.
		if prefixVarietyRatio > 90 && prefixVariety > 10 {
			suspiciousScore += 30
		} else if prefixVarietyRatio > 70 && prefixVariety > 5 {
			suspiciousScore += 20
		}

		// 3.
		if count > 100 {
			suspiciousScore += 20
		} else if count > 50 {
			suspiciousScore += 10
		} else if count > 20 {
			suspiciousScore += 5
		}

		// 4. TLD
		if tldVariety > 3 {
			suspiciousScore -= 20
		} else if tldVariety > 1 {
			suspiciousScore -= 10
		}

		if suspiciousScore >= 35 {
			gologger.Debugf("Suspicious IP: %s (domains: %d, %.2f%%, prefix variety: %d/%d, score: %.2f)\n",
				ip, count, freqPercentage, prefixVariety, count, suspiciousScore)
			suspiciousIPs[ip] = suspiciousScore
		}
	}

	var filteredResults []result.Result

	// CNAME
	cnameTargetCount := make(map[string]int)
	for _, targets := range cnameRecords {
		for _, target := range targets {
			cnameTargetCount[target]++
		}
	}

	suspiciousCnames := make(map[string]bool)
	for cname, count := range cnameTargetCount {
		if count > 5 && float64(count)/float64(totalDomains)*100 > 10 {
			gologger.Debugf("Suspicious CNAME target: %s (count: %d)\n", cname, count)
			suspiciousCnames[cname] = true
		}
	}

	for _, res := range results {
		hasSuspiciousCname := false
		if targets, ok := cnameRecords[res.Subdomain]; ok {
			for _, target := range targets {
				if suspiciousCnames[target] {
					hasSuspiciousCname = true
					break
				}
			}
		}

		validRecord := !hasSuspiciousCname
		var filteredAnswers []string

		for _, answer := range res.Answers {
			isIP := !strings.HasPrefix(answer, "CNAME ") &&
				!strings.HasPrefix(answer, "NS ") &&
				!strings.HasPrefix(answer, "TXT ") &&
				!strings.HasPrefix(answer, "PTR ")

			if !isIP {
				if strings.HasPrefix(answer, "CNAME ") {
					cnameParts := strings.SplitN(answer, " ", 2)
					if len(cnameParts) == 2 && suspiciousCnames[cnameParts[1]] {
						continue
					}
				}
				validRecord = true
				filteredAnswers = append(filteredAnswers, answer)
			} else {
				suspiciousScore, isSuspicious := suspiciousIPs[answer]

				if !isSuspicious || suspiciousScore < 50 {
					validRecord = true
					filteredAnswers = append(filteredAnswers, answer)
				}
			}
		}

		if validRecord && len(filteredAnswers) > 0 {
			filteredRes := result.Result{
				Subdomain: res.Subdomain,
				Answers:   filteredAnswers,
			}
			filteredResults = append(filteredResults, filteredRes)
		}
	}

	gologger.Infof("Advanced wildcard filter done: %d records → %d valid\n",
		totalDomains, len(filteredResults))

	return filteredResults
}
