// Command strongbox runs the CUI-grade blob and structured data store.
//
//	strongbox init            create schema (and a dev keyring when using local KMS)
//	strongbox serve           run the REST API
//	strongbox mcp             run the MCP server (stdio or streamable HTTP)
//	strongbox principal ...   register or list principals
//	strongbox token SUBJECT   mint a development token
//	strongbox audit-verify    verify the audit hash chain
//	strongbox gc              remove abandoned uploads
//	strongbox fips-check      report FIPS 140-3 module status
//	strongbox keyring ...     manage the local development keyring
//	strongbox openapi         print the OpenAPI document
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/paulmalmquist/storage_relspace/internal/api"
	"github.com/paulmalmquist/storage_relspace/internal/audit"
	"github.com/paulmalmquist/storage_relspace/internal/auth"
	"github.com/paulmalmquist/storage_relspace/internal/config"
	"github.com/paulmalmquist/storage_relspace/internal/crypto"
	"github.com/paulmalmquist/storage_relspace/internal/mcpserver"
	"github.com/paulmalmquist/storage_relspace/internal/service"
	"github.com/paulmalmquist/storage_relspace/internal/store"
	"github.com/paulmalmquist/storage_relspace/pkg/client"
)

var version = "0.2.0"

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	cmds := map[string]func(context.Context, []string) error{
		"init": cmdInit, "serve": cmdServe, "mcp": cmdMCP, "principal": cmdPrincipal, "token": cmdToken,
		"audit-verify": cmdAuditVerify, "gc": cmdGC, "fips-check": cmdFIPS, "keyring": cmdKeyring,
		"openapi": func(context.Context, []string) error { _, err := os.Stdout.Write(api.OpenAPI); return err },
		"version": func(context.Context, []string) error { fmt.Println(version); return nil },
	}
	fn, ok := cmds[os.Args[1]]
	if !ok {
		usage()
		os.Exit(2)
	}
	if err := fn(ctx, os.Args[2:]); err != nil {
		var exit exitCode
		if errors.As(err, &exit) {
			os.Exit(int(exit))
		}
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

type exitCode int

func (e exitCode) Error() string { return fmt.Sprintf("exit %d", int(e)) }

func usage() {
	fmt.Fprintln(os.Stderr, "usage: strongbox {init|serve|mcp|principal|token|audit-verify|gc|fips-check|keyring|openapi|version} [flags]")
}

func setupLogging(level string) {
	var lv slog.Level
	_ = lv.UnmarshalText([]byte(level))
	h := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lv, ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
		switch a.Key {
		case slog.LevelKey:
			a.Key = "severity" // Cloud Logging
		case slog.MessageKey:
			a.Key = "message"
		}
		return a
	}})
	slog.SetDefault(slog.New(h))
}

func load() (*config.Config, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, err
	}
	setupLogging(cfg.LogLevel)
	for _, d := range cfg.Deprecations {
		slog.Warn("deprecated configuration", "detail", d)
	}
	return cfg, nil
}

func openDB(ctx context.Context, cfg *config.Config) (*service.Container, error) {
	return service.Build(ctx, cfg, service.Overrides{})
}

// ---- init -----------------------------------------------------------------------------------------

func cmdInit(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	wait := fs.Duration("wait", 60*time.Second, "how long to wait for the database to accept connections")
	shutdownURL := fs.String("shutdown-url", "", "POST here when done (e.g. Cloud SQL proxy /quitquitquit)")
	_ = fs.Parse(args)
	if *shutdownURL != "" {
		defer shutdownSidecar(*shutdownURL)
	}
	cfg, err := load()
	if err != nil {
		return err
	}
	if cfg.KMSBackend == "local" {
		if _, err := os.Stat(cfg.LocalKeyringPath); errors.Is(err, os.ErrNotExist) {
			if _, err := crypto.CreateLocalKeyring(cfg.LocalKeyringPath); err != nil {
				return err
			}
			fmt.Printf("created local keyring %s (development only)\n", cfg.LocalKeyringPath)
		}
	}
	if cfg.BlobBackend == "local" {
		if err := os.MkdirAll(cfg.BlobLocalPath, 0o700); err != nil {
			return err
		}
	}
	pool, err := store.Open(ctx, cfg.DatabaseURL, "")
	if err != nil {
		return err
	}
	defer pool.Close()
	deadline := time.Now().Add(*wait)
	for {
		err := pool.Ping(ctx)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("database not reachable: %w", err)
		}
		time.Sleep(2 * time.Second)
	}
	if err := store.Migrate(ctx, pool); err != nil {
		return err
	}
	fmt.Println("schema ready")
	return nil
}

func shutdownSidecar(url string) {
	req, _ := http.NewRequest(http.MethodPost, url, nil)
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sidecar shutdown request failed:", err)
		return
	}
	_ = resp.Body.Close()
}

// ---- serve ----------------------------------------------------------------------------------------

func listen(ctx context.Context, addr string, h http.Handler) error {
	srv := &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 120 * time.Second}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	slog.Info("listening", "addr", addr)
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return srv.Shutdown(shutdown)
	}
}

func defaultAddr() string {
	if p := os.Getenv("PORT"); p != "" { // Cloud Run
		return ":" + p
	}
	return ":8080"
}

func cmdServe(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", defaultAddr(), "listen address")
	_ = fs.Parse(args)
	cfg, err := load()
	if err != nil {
		return err
	}
	c, err := openDB(ctx, cfg)
	if err != nil {
		return err
	}
	defer c.DB.Close()
	slog.Info("strongbox api", "version", version, "kms", c.KMS.Describe(), "blobs", c.Backend.Describe(), "fips", crypto.FIPSStatus())
	return listen(ctx, *addr, api.New(c))
}

// ---- mcp ------------------------------------------------------------------------------------------

func agentClient(ctx context.Context) (*client.Client, error) {
	url := os.Getenv("STRONGBOX_MCP_API_URL")
	if url == "" {
		return nil, errors.New("STRONGBOX_MCP_API_URL is required")
	}
	if aud := os.Getenv("STRONGBOX_MCP_GOOGLE_AUDIENCE"); aud != "" {
		ts, err := client.GoogleIDToken(ctx, aud)
		if err != nil {
			return nil, err
		}
		return client.New(url, ts, client.WithServerlessAuth()), nil
	}
	tok := os.Getenv("STRONGBOX_MCP_TOKEN")
	if tok == "" {
		return nil, errors.New("set STRONGBOX_MCP_TOKEN (agent token) or STRONGBOX_MCP_GOOGLE_AUDIENCE")
	}
	return client.New(url, client.StaticToken(tok)), nil
}

func cmdMCP(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("mcp", flag.ExitOnError)
	transport := fs.String("transport", "stdio", "stdio or streamable-http")
	addr := fs.String("addr", defaultAddr(), "listen address (streamable-http)")
	_ = fs.Parse(args)
	cl, err := agentClient(ctx)
	if err != nil {
		return err
	}
	var maxRead int64 = 256 * 1024
	if v := os.Getenv("STRONGBOX_MCP_MAX_READ_BYTES"); v != "" {
		if _, err := fmt.Sscan(v, &maxRead); err != nil {
			return fmt.Errorf("STRONGBOX_MCP_MAX_READ_BYTES: %w", err)
		}
	}
	switch *transport {
	case "stdio":
		srv := mcpserver.New(cl, mcpserver.Options{DefaultOnBehalfOf: os.Getenv("STRONGBOX_MCP_ON_BEHALF_OF"), MaxReadBytes: maxRead})
		return srv.Run(ctx, &mcp.StdioTransport{})
	case "streamable-http":
		cfg, err := load()
		if err != nil {
			return err
		}
		publicURL := os.Getenv("STRONGBOX_MCP_PUBLIC_URL")
		if publicURL == "" {
			return errors.New("STRONGBOX_MCP_PUBLIC_URL is required for streamable-http")
		}
		verifier, err := service.BuildVerifier(ctx, cfg, cfg.DelegationAudiences)
		if err != nil {
			return err
		}
		issuer := cfg.OIDCIssuer
		if cfg.AuthMode != "oidc" {
			issuer = auth.DevIssuer
		}
		verify := func(ctx context.Context, tok string) (string, time.Time, error) {
			vt, err := verifier.Verify(ctx, tok)
			if err != nil {
				return "", time.Time{}, err
			}
			return vt.Subject, vt.ExpiresAt, nil
		}
		srv := mcpserver.New(cl, mcpserver.Options{MaxReadBytes: maxRead})
		return listen(ctx, *addr, mcpserver.HTTPHandler(srv, verify, publicURL, issuer))
	default:
		return fmt.Errorf("unknown transport %q", *transport)
	}
}

// ---- admin ----------------------------------------------------------------------------------------

func cmdPrincipal(ctx context.Context, args []string) error {
	if len(args) == 0 || (args[0] != "put" && args[0] != "list") {
		return errors.New("usage: strongbox principal put SUBJECT [flags] | strongbox principal list")
	}
	cfg, err := load()
	if err != nil {
		return err
	}
	pool, err := store.Open(ctx, cfg.DatabaseURL, "")
	if err != nil {
		return err
	}
	defer pool.Close()
	reg := auth.NewRegistry(pool)
	if args[0] == "list" {
		items, err := reg.List(ctx)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(items)
	}
	if len(args) < 2 || strings.HasPrefix(args[1], "-") {
		return errors.New("principal put requires a subject")
	}
	fs := flag.NewFlagSet("principal put", flag.ExitOnError)
	var scopes, cats, ldcs stringList
	kind := fs.String("kind", "user", "user, service or agent")
	fs.Var(&scopes, "scope", "repeatable; '*' for all")
	us := fs.Bool("us-person", false, "U.S. person")
	cui := fs.Bool("cui-access", false, "authorized for CUI (training + lawful government purpose)")
	fs.Var(&cats, "category", "authorized CUI category, e.g. SP-EXPT; '*' for all (repeatable)")
	fs.Var(&ldcs, "ldc", "authorized dissemination control, e.g. FEDCON (repeatable)")
	llm := fs.Bool("llm-boundary", false, "agent runs inside an authorized LLM boundary")
	name := fs.String("display-name", "", "display name")
	disabled := fs.Bool("disabled", false, "disable this principal")
	_ = fs.Parse(args[2:])
	if err := reg.Put(ctx, auth.Spec{Subject: args[1], Kind: auth.Kind(*kind), Scopes: scopes, USPerson: *us, CUIAccess: *cui,
		CUICategories: cats, Dissemination: ldcs, LLMBoundaryAuthorized: *llm, DisplayName: *name, Disabled: *disabled}); err != nil {
		return err
	}
	fmt.Printf("principal %s saved\n", args[1])
	return nil
}

func cmdToken(_ context.Context, args []string) error {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return errors.New("usage: strongbox token SUBJECT [-audience A] [-ttl 1h]")
	}
	fs := flag.NewFlagSet("token", flag.ExitOnError)
	aud := fs.String("audience", "strongbox", "token audience")
	ttl := fs.Duration("ttl", time.Hour, "lifetime")
	_ = fs.Parse(args[1:])
	cfg, err := load()
	if err != nil {
		return err
	}
	if cfg.Env == "production" || cfg.AuthMode != "dev-hs256" {
		return errors.New("dev tokens are only available in dev-hs256 mode")
	}
	tok, err := auth.MintDevToken(cfg.DevJWTSecret, args[0], *aud, *ttl)
	if err != nil {
		return err
	}
	fmt.Println(tok)
	return nil
}

func cmdAuditVerify(ctx context.Context, _ []string) error {
	cfg, err := load()
	if err != nil {
		return err
	}
	pool, err := store.Open(ctx, cfg.DatabaseURL, "")
	if err != nil {
		return err
	}
	defer pool.Close()
	r, err := audit.New(pool).Verify(ctx)
	if err != nil {
		return err
	}
	_ = json.NewEncoder(os.Stdout).Encode(r)
	if !r.OK {
		return exitCode(1)
	}
	return nil
}

func cmdGC(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("gc", flag.ExitOnError)
	older := fs.Duration("older-than", time.Hour, "age of pending uploads to remove")
	_ = fs.Parse(args)
	cfg, err := load()
	if err != nil {
		return err
	}
	c, err := openDB(ctx, cfg)
	if err != nil {
		return err
	}
	defer c.DB.Close()
	n, err := c.Blobs.SweepPending(ctx, *older)
	if err != nil {
		return err
	}
	fmt.Printf("removed %d abandoned uploads\n", n)
	return nil
}

func cmdFIPS(context.Context, []string) error {
	s := crypto.FIPSStatus()
	_ = json.NewEncoder(os.Stdout).Encode(s)
	if s["fips_enabled"] != true {
		return exitCode(1)
	}
	return nil
}

func cmdKeyring(_ context.Context, args []string) error {
	if len(args) == 0 || (args[0] != "create" && args[0] != "rotate") {
		return errors.New("usage: strongbox keyring create|rotate [-path P]")
	}
	fs := flag.NewFlagSet("keyring", flag.ExitOnError)
	path := fs.String("path", "", "keyring path (default STRONGBOX_LOCAL_KEYRING_PATH)")
	_ = fs.Parse(args[1:])
	if *path == "" {
		*path = os.Getenv("STRONGBOX_LOCAL_KEYRING_PATH")
		if *path == "" {
			*path = ".strongbox/keyring.json"
		}
	}
	fn := crypto.CreateLocalKeyring
	if args[0] == "rotate" {
		fn = crypto.RotateLocalKeyring
	}
	id, err := fn(*path)
	if err != nil {
		return err
	}
	fmt.Printf("%sd local keyring %s; active key %s\n", args[0], *path, id)
	return nil
}
