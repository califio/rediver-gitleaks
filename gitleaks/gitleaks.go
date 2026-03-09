package gitleaks

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

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
	// Keep Redact=0 so f.Secret contains raw value for PR/MR filtering.
	// Redaction is applied manually in toSASTFinding.

	isPRScan := opts.BaseCommitSHA != "" && opts.HeadCommitSHA != ""

	var findings []report.Finding
	if isPRScan {
		log.Info("scanning PR/MR changed files at HEAD",
			"base", opts.BaseCommitSHA[:minLen(opts.BaseCommitSHA, 8)],
			"head", opts.HeadCommitSHA[:minLen(opts.HeadCommitSHA, 8)])

		changedFiles, err := gitDiffFileList(ctx, absPath, opts.BaseCommitSHA, opts.HeadCommitSHA)
		if err != nil {
			return nil, fmt.Errorf("list changed files: %w", err)
		}
		if len(changedFiles) == 0 {
			log.Info("no changed files in range")
			return nil, nil
		}
		log.Info("changed files", "count", len(changedFiles))

		source := &gitChangedFilesSource{
			repoPath:  absPath,
			headSHA:   opts.HeadCommitSHA,
			files:     changedFiles,
		}
		findings, err = detector.DetectSource(ctx, source)
		if err != nil {
			return nil, fmt.Errorf("gitleaks detection failed: %w", err)
		}
	} else {
		var logOpts string
		if opts.FullHistory {
			logOpts = ""
		} else {
			logOpts = "-1"
		}
		gitCmd, err := sources.NewGitLogCmdContext(ctx, absPath, logOpts)
		if err != nil {
			return nil, fmt.Errorf("create git source: %w", err)
		}

		gitSource := &sources.Git{
			Cmd:    gitCmd,
			Config: &detector.Config,
			Sema:   detector.Sema,
			Remote: &sources.RemoteInfo{},
		}

		findings, err = detector.DetectSource(ctx, gitSource)
		if err != nil {
			return nil, fmt.Errorf("gitleaks detection failed: %w", err)
		}
	}

	if len(findings) == 0 {
		return nil, nil
	}

	results := make([]rediver.SASTFinding, 0, len(findings))
	for _, f := range findings {
		results = append(results, toSASTFinding(f, opts.RedactPct))
	}
	return results, nil
}

func minLen(s string, n int) int {
	if len(s) < n {
		return len(s)
	}
	return n
}

// gitDiffFileList returns the list of added/changed/modified/renamed files between two commits.
func gitDiffFileList(ctx context.Context, repoPath, base, head string) ([]string, error) {
	cmd := exec.CommandContext(ctx, "git", "diff", "--name-only", "--diff-filter=ACMR", base, head)
	cmd.Dir = repoPath
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git diff --name-only: %w", err)
	}
	raw := strings.TrimSpace(string(out))
	if raw == "" {
		return nil, nil
	}
	return strings.Split(raw, "\n"), nil
}

// gitChangedFilesSource implements sources.Source by reading changed files at a specific commit.
type gitChangedFilesSource struct {
	repoPath string
	headSHA  string
	files    []string
}

func (s *gitChangedFilesSource) Fragments(ctx context.Context, yield sources.FragmentsFunc) error {
	for _, filePath := range s.files {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		content, err := gitShowFile(ctx, s.repoPath, s.headSHA, filePath)
		if err != nil {
			// File may have been deleted or is binary — skip
			continue
		}

		fragment := sources.Fragment{
			Raw:       content,
			FilePath:  filePath,
			CommitSHA: s.headSHA,
		}
		if err := yield(fragment, nil); err != nil {
			return err
		}
	}
	return nil
}

func gitShowFile(ctx context.Context, repoPath, ref, filePath string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", "show", ref+":"+filePath)
	cmd.Dir = repoPath
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func toSASTFinding(f report.Finding, redactPct uint) rediver.SASTFinding {
	snippet := f.Match
	if redactPct > 0 && f.Secret != "" {
		redacted := redactSecret(f.Secret, redactPct)
		snippet = strings.Replace(snippet, f.Secret, redacted, 1)
	}

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
		Snippet:     snippet,
		Category:    "Hardcoded Secret",
		RuleID:      f.RuleID,
		CommitSha:   f.Commit,
	}
}

// redactSecret replaces the last N% of a secret with asterisks.
func redactSecret(secret string, pct uint) string {
	n := len(secret) * int(pct) / 100
	if n < 1 {
		n = 1
	}
	return secret[:len(secret)-n] + strings.Repeat("*", n)
}
