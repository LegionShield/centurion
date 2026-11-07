package output

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/LegionShield/legion-subdomain/v2/pkg/runner/result"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---- ScreenOutput ----

func TestNewScreenOutput_NoWidth_NoPanic(t *testing.T) {
	w, err := NewScreenOutputNoWidth(false)
	require.NoError(t, err)
	assert.NotNil(t, w)
}

func TestScreenOutput_WriteDomainResult_Silent(t *testing.T) {
	w, err := NewScreenOutputNoWidth(true)
	require.NoError(t, err)
	err = w.WriteDomainResult(result.Result{
		Subdomain: "www.example.com",
		Answers:   []string{"1.2.3.4"},
	})
	assert.NoError(t, err)
}

func TestScreenOutput_WriteDomainResult_NonSilent(t *testing.T) {
	w, err := NewScreenOutputNoWidth(false)
	require.NoError(t, err)
	err = w.WriteDomainResult(result.Result{
		Subdomain: "www.example.com",
		Answers:   []string{"1.2.3.4", "5.6.7.8"},
	})
	assert.NoError(t, err)
}

func TestScreenOutput_Close(t *testing.T) {
	w, err := NewScreenOutputNoWidth(false)
	require.NoError(t, err)
	assert.NoError(t, w.Close())
}

// ---- PlainOutput (file) ----

func TestNewPlainOutput_CreatesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.txt")
	w, err := NewPlainOutput(path, "none")
	require.NoError(t, err)
	require.NotNil(t, w)

	err = w.WriteDomainResult(result.Result{
		Subdomain: "sub.example.com",
		Answers:   []string{"1.2.3.4"},
	})
	assert.NoError(t, err)
	assert.NoError(t, w.Close())

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Contains(t, string(data), "sub.example.com")
}

func TestNewPlainOutput_WildcardFilter_Basic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.txt")
	w, err := NewPlainOutput(path, "basic")
	require.NoError(t, err)
	require.NotNil(t, w)
	assert.NoError(t, w.Close())
}

// ---- JSONOutput ----

func TestNewJsonOutput_WritesJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.json")
	w := NewJsonOutput(path, "none")
	require.NotNil(t, w)

	err := w.WriteDomainResult(result.Result{
		Subdomain: "api.example.com",
		Answers:   []string{"10.0.0.1"},
	})
	assert.NoError(t, err)
	assert.NoError(t, w.Close())

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Contains(t, string(data), "api.example.com")
}

// ---- CSVOutput ----

func TestNewCsvOutput_WritesCSV(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.csv")
	w := NewCsvOutput(path, "none")
	require.NotNil(t, w)

	err := w.WriteDomainResult(result.Result{
		Subdomain: "mail.example.com",
		Answers:   []string{"10.0.0.2"},
	})
	assert.NoError(t, err)
	assert.NoError(t, w.Close())

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Contains(t, string(data), "mail.example.com")
}

// ---- JSONLOutput ----

func TestNewJSONLOutput_WritesJSONL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.jsonl")
	w, err := NewJSONLOutput(path)
	require.NoError(t, err)
	require.NotNil(t, w)

	err = w.WriteDomainResult(result.Result{
		Subdomain: "cdn.example.com",
		Answers:   []string{"10.0.0.3"},
	})
	assert.NoError(t, err)
	assert.NoError(t, w.Close())

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	lines := string(data)
	assert.Contains(t, lines, "cdn.example.com")
}

// ---- BeautifiedOutput ----

func TestNewBeautifiedOutput_NoPanic(t *testing.T) {
	w, err := NewBeautifiedOutput(false, false, false)
	require.NoError(t, err)
	require.NotNil(t, w)

	err = w.WriteDomainResult(result.Result{
		Subdomain: "test.example.com",
		Answers:   []string{"1.1.1.1"},
	})
	assert.NoError(t, err)
	assert.NoError(t, w.Close())
}

func TestNewBeautifiedOutput_Silent(t *testing.T) {
	w, err := NewBeautifiedOutput(true, false, false)
	require.NoError(t, err)
	err = w.WriteDomainResult(result.Result{
		Subdomain: "test.example.com",
		Answers:   []string{"1.1.1.1"},
	})
	assert.NoError(t, err)
}

func TestNewBeautifiedOutput_OnlyDomain(t *testing.T) {
	w, err := NewBeautifiedOutput(false, false, true)
	require.NoError(t, err)
	err = w.WriteDomainResult(result.Result{
		Subdomain: "test.example.com",
		Answers:   []string{"1.1.1.1"},
	})
	assert.NoError(t, err)
}
