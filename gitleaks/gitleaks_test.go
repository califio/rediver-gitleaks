package gitleaks

import (
	"context"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/califio/rediver-sdk-go"
	"github.com/zricethezav/gitleaks/v8/report"
)

func TestToSASTFinding_WithCommit(t *testing.T) {
	f := report.Finding{
		Description: "Generic API Key",
		File:        "config.yaml",
		StartLine:   10,
		EndLine:     10,
		Match:       "api_key: AKIAIOSFODNN7EXAMPLE",
		Secret:      "AKIAIOSFODNN7EXAMPLE",
		RuleID:      "generic-api-key",
		Commit:      "abc123def456789",
	}

	result := toSASTFinding(f)

	if result.Name != "Generic API Key" {
		t.Errorf("Name = %q, want %q", result.Name, "Generic API Key")
	}
	if result.Description != "Generic API Key (commit: abc123de)" {
		t.Errorf("Description = %q, want %q", result.Description, "Generic API Key (commit: abc123de)")
	}
	if result.Severity != rediver.SeverityHigh {
		t.Errorf("Severity = %q, want %q", result.Severity, rediver.SeverityHigh)
	}
	if result.File != "config.yaml" {
		t.Errorf("File = %q, want %q", result.File, "config.yaml")
	}
	if result.StartLine != 10 {
		t.Errorf("StartLine = %d, want %d", result.StartLine, 10)
	}
	if result.EndLine != 10 {
		t.Errorf("EndLine = %d, want %d", result.EndLine, 10)
	}
	if result.Category != "Hardcoded Secret" {
		t.Errorf("Category = %q, want %q", result.Category, "Hardcoded Secret")
	}
	if result.RuleID != "generic-api-key" {
		t.Errorf("RuleID = %q, want %q", result.RuleID, "generic-api-key")
	}
	// Snippet is the raw match string (no redaction)
	if result.Snippet != "api_key: AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("Snippet = %q, want %q", result.Snippet, "api_key: AKIAIOSFODNN7EXAMPLE")
	}
	// CommitSha should be mapped from finding's Commit field
	if result.CommitSha != "abc123def456789" {
		t.Errorf("CommitSha = %q, want %q", result.CommitSha, "abc123def456789")
	}
}

func TestToSASTFinding_WithoutCommit(t *testing.T) {
	f := report.Finding{
		Description: "AWS Access Key",
		File:        "env.sh",
		StartLine:   5,
		EndLine:     5,
		Match:       "AWS_KEY=secret",
		Secret:      "secret",
		RuleID:      "aws-access-key",
		Commit:      "",
	}

	result := toSASTFinding(f)

	// Without commit, description should equal raw Description
	if result.Description != "AWS Access Key" {
		t.Errorf("Description = %q, want %q", result.Description, "AWS Access Key")
	}
}

func TestToSASTFinding_ShortCommit(t *testing.T) {
	f := report.Finding{
		Description: "Token",
		File:        "main.go",
		StartLine:   1,
		EndLine:     1,
		Match:       "tok",
		Secret:      "tok",
		RuleID:      "token",
		Commit:      "abc123", // 6 chars, <= 8
	}

	result := toSASTFinding(f)

	// Short commit should not be truncated
	if result.Description != "Token (commit: abc123)" {
		t.Errorf("Description = %q, want %q", result.Description, "Token (commit: abc123)")
	}
}

func TestScanInvalidRepoPath(t *testing.T) {
	logger := slog.Default()
	_, err := Scan(context.Background(), logger, "/nonexistent/path/that/does/not/exist", Options{})
	if err == nil {
		t.Fatal("expected error for nonexistent path, got nil")
	}
	if got := err.Error(); !strings.Contains(got, "path does not exist") {
		t.Errorf("error = %q, want to contain %q", got, "path does not exist")
	}
}

func TestScanDetectsSecret(t *testing.T) {
	// Create temp dir with a git repo containing a secret
	dir := t.TempDir()
	runGit := func(args ...string) {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v failed: %s\n%s", args, err, out)
		}
	}

	runGit("init")
	runGit("config", "user.email", "test@test.com")
	runGit("config", "user.name", "Test")

	// Write file with AWS key pattern (high-entropy key required to pass gitleaks entropy filter)
	secretFile := filepath.Join(dir, "config.env")
	if err := os.WriteFile(secretFile, []byte("AWS_ACCESS_KEY_ID=AKIAZ7V5RCJQ42WRGX4D\n"), 0644); err != nil {
		t.Fatalf("write secret file: %v", err)
	}
	runGit("add", ".")
	runGit("commit", "-m", "add config")

	// Run scan
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	findings, err := Scan(context.Background(), logger, dir, Options{})
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected at least 1 finding, got 0")
	}

	// Verify finding shape
	f := findings[0]
	if f.Severity != rediver.SeverityHigh {
		t.Errorf("Severity = %q, want High", f.Severity)
	}
	if f.Category != "Hardcoded Secret" {
		t.Errorf("Category = %q, want 'Hardcoded Secret'", f.Category)
	}
	if f.File == "" {
		t.Error("File should not be empty")
	}
	if f.RuleID == "" {
		t.Error("RuleID should not be empty")
	}
	// Snippet should contain the match context
	if f.Snippet == "" {
		t.Error("Snippet should not be empty")
	}
}
