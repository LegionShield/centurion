package output

import (
	"encoding/csv"
	"os"

	"github.com/LegionShield/legion-subdomain/v2/pkg/core/gologger"
	"github.com/LegionShield/legion-subdomain/v2/pkg/runner/result"
	"github.com/LegionShield/legion-subdomain/v2/pkg/utils"
)

type CsvOutput struct {
	domains        []result.Result
	filename       string
	wildFilterMode string
}

func NewCsvOutput(filename string, wildFilterMode string) *CsvOutput {
	f := new(CsvOutput)
	f.domains = make([]result.Result, 0)
	f.filename = filename
	f.wildFilterMode = wildFilterMode
	return f
}

func (f *CsvOutput) WriteDomainResult(domain result.Result) error {
	f.domains = append(f.domains, domain)
	return nil
}

func (f *CsvOutput) Close() error {
	gologger.Infof("Writing csv file: %s\n", f.filename)

	if len(f.domains) == 0 {
		gologger.Infof("No subdomain results found, CSV will be empty\n")
		return nil
	}

	results := utils.WildFilterOutputResult(f.wildFilterMode, f.domains)
	gologger.Infof("Results after filter: %d\n", len(results))

	if len(results) == 0 {
		gologger.Infof("No valid results after wildcard filter, CSV will be empty\n")
		return nil
	}

	file, err := os.Create(f.filename)
	if err != nil {
		gologger.Errorf("Failed to create CSV file: %v", err)
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)

	err = writer.Write([]string{"Subdomain", "Answers"})
	if err != nil {
		gologger.Errorf("Failed to write CSV header: %v", err)
		return err
	}

	for _, result := range results {
		answersStr := ""
		if len(result.Answers) > 0 {
			answersStr = result.Answers[0]
			for i := 1; i < len(result.Answers); i++ {
				answersStr += ";" + result.Answers[i]
			}
		}

		err = writer.Write([]string{result.Subdomain, answersStr})
		if err != nil {
			gologger.Errorf("Failed to write CSV row: %v", err)
			continue
		}
	}
	writer.Flush()
	gologger.Infof("CSV written successfully, %d records", len(results))
	return nil
}
