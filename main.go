package main

import (
	"context"
	"os/signal"
	"syscall"
	"time"

	"github.com/alecthomas/kong"
	"github.com/califio/rediver-sdk-go"
	"github.com/joho/godotenv"
)

var Version = "0.0.1"

type CLI struct {
	Url              string `help:"Rediver API URL" env:"REDIVER_URL" default:"https://api.rediver.ai" required:"true"`
	Token            string `help:"Rediver cluster token" env:"REDIVER_TOKEN" required:"true"`
	MaxConcurrentJob int    `help:"Max concurrent job" env:"MAX_CONCURRENT_JOB" default:"10"`
	PollingInterval  int    `help:"Polling interval in seconds" env:"POLLING_INTERVAL" default:"10"`
	Mode             string `help:"Run mode: worker (long-running poll loop), ci (auto-detect CI env, scan, exit), task (single job, exit)" env:"MODE" enum:"worker,ci,task" default:"ci"`
	RepoDir          string `help:"Override repository directory for scanning" env:"REPO_DIR"`
	FullHistory      bool   `help:"Scan all git commits instead of only HEAD" env:"FULL_HISTORY" default:"false"`
	Verbose          bool   `help:"Show verbose output from sca" env:"VERBOSE" default:"false"`
	BaseCommit       string `help:"Base commit SHA for PR/MR diff scanning" env:"BASE_COMMIT"`
	HeadCommit       string `help:"Head commit SHA for PR/MR diff scanning" env:"HEAD_COMMIT"`
}

func (cli *CLI) Run() error {
	opts := []rediver.Option{
		rediver.WithVersion(Version),
		rediver.WithMaxConcurrency(cli.MaxConcurrentJob),
		rediver.WithPollInterval(time.Duration(cli.PollingInterval) * time.Second),
	}

	switch cli.Mode {
	case "worker":
		opts = append(opts, rediver.WithWorkerMode())
	case "ci":
		opts = append(opts, rediver.WithCIMode())
	case "task":
		opts = append(opts, rediver.WithTaskMode())
	}
	if cli.RepoDir != "" {
		opts = append(opts, rediver.WithRepoDir(cli.RepoDir))
	}

	agent, err := rediver.NewAgent(cli.Url, cli.Token, opts...)
	if err != nil {
		return err
	}
	if err := agent.Register(NewGitleaksScanner(GitleaksDefaults{
		FullHistory: cli.FullHistory,
		Verbose:     cli.Verbose,
		BaseCommit:  cli.BaseCommit,
		HeadCommit:  cli.HeadCommit,
	})); err != nil {
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	return agent.Run(ctx)
}

func main() {
	_ = godotenv.Load(".env")
	cli := CLI{}
	ctx := kong.Parse(&cli, kong.Name("rediver-gitleaks"), kong.UsageOnError())
	err := ctx.Run()
	ctx.FatalIfErrorf(err)
}
