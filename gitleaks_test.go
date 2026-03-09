package main

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/califio/rediver-sdk-go"
	"github.com/califio/rediver-sdk-go/utils"
)

// mockJob implements rediver.Job for testing. Only RepoDir and Logger
// are called by gitleaksHandler; other methods return zero values.
type mockJob struct {
	repoDir string
	logger  *slog.Logger
}

func (m *mockJob) ID() string                              { return "test-job-1" }
func (m *mockJob) Type() rediver.JobType                   { return rediver.JobTypeDiscovery }
func (m *mockJob) Domains() []rediver.DomainTarget         { return nil }
func (m *mockJob) IPs() []rediver.IPTarget                 { return nil }
func (m *mockJob) Subnets() []rediver.SubnetTarget         { return nil }
func (m *mockJob) Services() []rediver.ServiceTarget       { return nil }
func (m *mockJob) Param(_ string) rediver.ParamValue       { return nil }
func (m *mockJob) Repository() (*rediver.Repository, bool) { return nil, false }
func (m *mockJob) RepoDir() string                         { return m.repoDir }
func (m *mockJob) ChangedFiles(_ context.Context) (*utils.ChangedFiles, error) {
	return nil, nil
}
func (m *mockJob) ClusterInfo() rediver.ClusterInfo  { return rediver.ClusterInfo{} }
func (m *mockJob) Integration() *rediver.Integration { return nil }
func (m *mockJob) Scanner() string                   { return "gitleaks" }
func (m *mockJob) TimeoutMinutes() int               { return 0 }
func (m *mockJob) Version() int                      { return 1 }
func (m *mockJob) Logger() *slog.Logger {
	if m.logger != nil {
		return m.logger
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestNewGitleaksScanner(t *testing.T) {
	s := NewGitleaksScanner(GitleaksDefaults{})

	if s.Name() != "gitleaks" {
		t.Errorf("Name() = %q, want %q", s.Name(), "gitleaks")
	}

	types := s.AssetTypes()
	if len(types) != 1 {
		t.Fatalf("AssetTypes() len = %d, want 1", len(types))
	}
	if types[0] != rediver.TargetTypeRepository {
		t.Errorf("AssetTypes()[0] = %q, want %q", types[0], rediver.TargetTypeRepository)
	}
}

// TestGitleaksHandler_ScanRediverSDK runs the full handler against local rediver-sdk repo.
// Skip in CI. Run manually: go test -run TestGitleaksHandler_ScanRediverSDK -v -timeout 5m
func TestGitleaksHandler_ScanRediverSDK(t *testing.T) {
	if os.Getenv("CI") != "" {
		t.Skip("skipping integration test in CI")
	}

	sdkDir := filepath.Join("..", "..", "rediver-sdk")
	absDir, err := filepath.Abs(sdkDir)
	if err != nil {
		t.Fatalf("resolve sdk path: %v", err)
	}
	if _, err := os.Stat(filepath.Join(absDir, ".git")); os.IsNotExist(err) {
		t.Skipf("rediver-sdk not found at %s", absDir)
	}

	job := &mockJob{
		repoDir: absDir,
		logger:  slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})),
	}

	var results []rediver.Result
	emit := func(r rediver.Result) { results = append(results, r) }

	err = gitleaksHandler(GitleaksDefaults{})(context.Background(), job, emit)
	if err != nil {
		t.Fatalf("gitleaksHandler error: %v", err)
	}

	t.Logf("emitted %d result batches", len(results))
}

func TestGitleaksHandler_NoRepoDir(t *testing.T) {
	job := &mockJob{
		repoDir: "", // no repo available
	}

	var results []rediver.Result
	emit := func(r rediver.Result) { results = append(results, r) }

	err := gitleaksHandler(GitleaksDefaults{})(context.Background(), job, emit)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !strings.Contains(err.Error(), "no repository available") {
		t.Errorf("error = %q, want to contain %q", err.Error(), "no repository available")
	}
	if len(results) != 0 {
		t.Errorf("expected 0 emitted results, got %d", len(results))
	}
}
