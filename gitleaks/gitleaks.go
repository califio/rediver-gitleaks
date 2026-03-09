package gitleaks

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/califio/rediver-sdk-go"
	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/report"
	"github.com/zricethezav/gitleaks/v8/sources"
)

// init suppresses gitleaks' internal zerolog output which floods stdout with trace logs.
// Safe because this binary only runs gitleaks — no other zerolog consumers exist.
func init() {
	//zerolog.SetGlobalLevel(zerolog.Disabled)
}

// Options holds configuration for a gitleaks scan.
type Options struct {
	FullHistory   bool
	Verbose       bool
	RedactPct     uint   // percentage of secret to redact (0-100), 0 means no redaction
	BaseCommitSHA string // PR/MR base commit — when set with HeadCommitSHA, scans only the diff range
	HeadCommitSHA string // PR/MR head commit
}

// Scan runs gitleaks on the specified directory and returns SAST findings.
// When fullHistory is true, scans all commits; otherwise scans only the HEAD commit.
func Scan(ctx context.Context, log *slog.Logger, repoPath string, opts Options) ([]rediver.SASTFinding, error) {
	absPath, err := filepath.Abs(repoPath)
	if err != nil {
		return nil, fmt.Errorf("resolve path: %w", err)
	}
	if _, err := os.Stat(absPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("path does not exist: %s", absPath)
	}

	log.Info("running gitleaks", "path", absPath)

	detector, err := detect.NewDetectorDefaultConfig()
	if err != nil {
		return nil, fmt.Errorf("create detector: %w", err)
	}

	if opts.Verbose {
		detector.Verbose = true
		detector.NoColor = false
	}
	if opts.RedactPct > 0 {
		detector.Redact = opts.RedactPct
	}

	// Determine scan scope:
	// 1. PR/MR diff range (base..head) takes priority when both commits are available
	// 2. Full history scans all commits
	// 3. Default: scan only HEAD commit
	var logOpts string
	switch {
	case opts.BaseCommitSHA != "" && opts.HeadCommitSHA != "":
		logOpts = fmt.Sprintf("%s..%s", opts.BaseCommitSHA, opts.HeadCommitSHA)
		log.Info("scanning PR/MR commit range", "base", opts.BaseCommitSHA[:minLen(opts.BaseCommitSHA, 8)], "head", opts.HeadCommitSHA[:minLen(opts.HeadCommitSHA, 8)])
	case opts.FullHistory:
		logOpts = ""
	default:
		logOpts = "-1"
	}
	gitCmd, err := sources.NewGitLogCmdContext(ctx, absPath, logOpts)
	if err != nil {
		return nil, fmt.Errorf("create git source: %w", err)
	}

	// Remote must be non-nil to prevent nil pointer panic in gitleaks' createScmLink (v8.30.0).
	gitSource := &sources.Git{
		Cmd:    gitCmd,
		Config: &detector.Config,
		Sema:   detector.Sema,
		Remote: &sources.RemoteInfo{},
	}

	findings, err := detector.DetectSource(ctx, gitSource)
	if err != nil {
		return nil, fmt.Errorf("gitleaks detection failed: %w", err)
	}

	if len(findings) == 0 {
		return nil, nil
	}

	results := make([]rediver.SASTFinding, 0, len(findings))
	for _, f := range findings {
		results = append(results, toSASTFinding(f))
	}
	return results, nil
}

func minLen(s string, n int) int {
	if len(s) < n {
		return len(s)
	}
	return n
}

func toSASTFinding(f report.Finding) rediver.SASTFinding {
	description := f.Description
	if f.Commit != "" {
		commitShort := f.Commit
		if len(commitShort) > 8 {
			commitShort = commitShort[:8]
		}
		description = fmt.Sprintf("%s (commit: %s)", f.Description, commitShort)
	}

	return rediver.SASTFinding{
		Name:        f.Description,
		Description: description,
		Severity:    rediver.SeverityHigh,
		File:        f.File,
		StartLine:   f.StartLine,
		EndLine:     f.EndLine,
		Snippet:     f.Match,
		Category:    "Hardcoded Secret",
		RuleID:      f.RuleID,
		CommitSha:   f.Commit,
	}
}
