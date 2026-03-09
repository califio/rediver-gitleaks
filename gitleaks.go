package main

import (
	"context"
	"fmt"
	"gitlab.com/califengineering/rediver/rediver-gitleaks/gitleaks"

	"github.com/califio/rediver-sdk-go"
)

// GitleaksDefaults holds CLI-level defaults for the gitleaks scanner parameters.
type GitleaksDefaults struct {
	FullHistory bool
	Verbose     bool
}

// NewGitleaksScanner creates a scanner for secret detection using gitleaks.
func NewGitleaksScanner(defaults GitleaksDefaults) rediver.Scanner {
	return rediver.NewScanner(
		"gitleaks",
		[]rediver.TargetType{rediver.TargetTypeRepository},
		gitleaksHandler,
		rediver.WithParam(rediver.BoolParam("full_history").
			Label("Full History Scan").
			Description("Scan all git commits instead of only the HEAD commit").
			Default(defaults.FullHistory).
			Build()),
		rediver.WithParam(rediver.BoolParam("verbose").
			Label("Verbose Output").
			Description("Show detailed gitleaks finding output with redacted secrets (20% redaction)").
			Default(defaults.Verbose).
			Build()),
	)
}

func gitleaksHandler(ctx context.Context, job rediver.Job, emit func(rediver.Result)) error {
	log := job.Logger()

	repoDir := job.RepoDir()
	if repoDir == "" {
		return fmt.Errorf("no repository available")
	}

	var fullHistory bool
	if p := job.Param("full_history"); p != nil {
		fullHistory = p.Bool()
	}
	var verbose bool
	if p := job.Param("verbose"); p != nil {
		verbose = p.Bool()
	}
	log.Info("scanning repository", "path", repoDir, "fullHistory", fullHistory, "verbose", verbose)

	opts := gitleaks.Options{
		FullHistory: fullHistory,
		Verbose:     verbose,
		RedactPct:   20,
	}
	findings, err := gitleaks.Scan(ctx, log, repoDir, opts)
	if err != nil {
		return fmt.Errorf("scan error: %w", err)
	}

	if len(findings) == 0 {
		log.Info("no secrets found")
		return nil
	}

	log.Info("secrets found", "count", len(findings))
	emit(rediver.SASTFindings(findings...))
	return nil
}
