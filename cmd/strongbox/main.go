// Command strongbox runs Strongbox, the shared persistence service for Dreamcatcher apps.
//
//	strongbox init              migrate the schema (privileged login); dev: create a keyring
//	strongbox db ...            bootstrap roles, check the runtime login, show migration status
//	strongbox serve             run the REST API (and the background worker unless -worker=false)
//	strongbox worker            run the background worker alone (or -once)
//	strongbox mcp               run the MCP server (stdio or streamable HTTP)
//	strongbox admin ...         privileged operations: apps, clients, members, legacy data, owners
//	strongbox principal ...     register or list principals
//	strongbox token SUBJECT     mint a development token
//	strongbox audit-verify      verify every audit hash chain
//	strongbox fips-check        report FIPS 140-3 module status
//	strongbox keyring ...       manage the local development keyring
//	strongbox openapi           print the OpenAPI document
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

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/paulmalmquist/storage_relspace/internal/admin"
	"github.com/paulmalmquist/storage_relspace/internal/api"
	"github.com/paulmalmquist/storage_relspace/internal/audit"
	"github.com/paulmalmquist/storage_relspace/internal/auth"
	"github.com/paulmalmquist/storage_relspace/internal/config"
	"github.com/paulmalmquist/storage_relspace/internal/crypto"
	"github.com/paulmalmquist/storage_relspace/internal/mcpserver"
	"github.com/paulmalmquist/storage_relspace/internal/service"
	"github.com/paulmalmquist/storage_relspace/internal/store"
	"github.com/paulmalmquist/storage_relspace/internal/telemetry"
	"github.com/paulmalmquist/storage_relspace/pkg/client"
)

var version = "0.3.0"

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

var commands = map[string]func(context.Context, []string) error{}

func main() {
	for k, v := range map[string]func(context.Context, []string) error{
		"init": cmdInit, "db": cmdDB, "serve": cmdServe, "worker": cmdWorker, "mcp": cmdMCP, "admin": cmdAdmin,
		"principal": cmdPrincipal, "token": cmdToken, "usage": cmdUsage, "audit-verify": cmdAuditVerify, "fips-check": cmdFIPS,
		"keyring": cmdKeyring, "gc": cmdGC, "export": cmdExport, "validate-export": cmdValidateExport, "restore": cmdRestore,
		"inventory": cmdInventory, "reconcile": cmdReconcile, "restore-drill": cmdRestoreDrill,
		"openapi": func(context.Context, []string) error { _, err := os.Stdout.Write(api.OpenAPI); return err },
		"version": func(context.Context, []string) error { fmt.Println(version); return nil },
	} {
		commands[k] = v
	}
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	fn, ok := commands[os.Args[1]]
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
	names := make([]string, 0, len(commands))
	for k := range commands {
		names = append(names, k)
	}
	fmt.Fprintf(os.Stderr, "usage: strongbox {%s} [flags]\n", strings.Join(names, "|"))
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

// privileged opens the migration login (member of strongbox_owner).
func privileged(ctx context.Context, cfg *config.Config) (*pgxpool.Pool, error) {
	return store.Open(ctx, cfg.MigrationDatabaseURL, store.Options{Schema: cfg.DBSchema, MaxConns: 4, AppName: "strongbox-admin"})
}

func waitFor(ctx context.Context, pool *pgxpool.Pool, wait time.Duration) error {
	deadline := time.Now().Add(wait)
	for {
		err := pool.Ping(ctx)
		if err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("database not reachable: %w", err)
		}
		time.Sleep(2 * time.Second)
	}
}

// ---- init / db ------------------------------------------------------------------------------------

func cmdInit(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	wait := fs.Duration("wait", 60*time.Second, "how long to wait for the database to accept connections")
	shutdownURL := fs.String("shutdown-url", "", "POST here when done (e.g. Cloud SQL proxy /quitquitquit)")
	bootstrap := fs.Bool("bootstrap-roles", false, "create roles and schema first (needs CREATEROLE)")
	var logins stringList
	fs.Var(&logins, "runtime-login", "with -bootstrap-roles: login role to grant strongbox_runtime (repeatable)")
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
	if *bootstrap {
		pool, err := store.Open(ctx, cfg.MigrationDatabaseURL, store.Options{})
		if err != nil {
			return err
		}
		err = waitFor(ctx, pool, *wait)
		if err == nil {
			err = store.Bootstrap(ctx, pool, store.BootstrapOptions{Schema: cfg.DBSchema, RuntimeLogins: logins})
		}
		pool.Close()
		if err != nil {
			return err
		}
	}
	pool, err := privileged(ctx, cfg)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := waitFor(ctx, pool, *wait); err != nil {
		return err
	}
	if err := store.Migrate(ctx, pool); err != nil {
		return err
	}
	fmt.Println("schema ready")
	return nil
}

func cmdDB(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: strongbox db bootstrap [-runtime-login L]... | check-roles | status")
	}
	cfg, err := load()
	if err != nil {
		return err
	}
	switch args[0] {
	case "bootstrap":
		fs := flag.NewFlagSet("db bootstrap", flag.ExitOnError)
		var logins stringList
		fs.Var(&logins, "runtime-login", "login role to grant strongbox_runtime (repeatable)")
		_ = fs.Parse(args[1:])
		pool, err := store.Open(ctx, cfg.MigrationDatabaseURL, store.Options{})
		if err != nil {
			return err
		}
		defer pool.Close()
		if err := store.Bootstrap(ctx, pool, store.BootstrapOptions{Schema: cfg.DBSchema, RuntimeLogins: logins}); err != nil {
			return err
		}
		fmt.Printf("roles %s and %s ready; schema %s\n", store.OwnerRole, store.RuntimeRole, cfg.DBSchema)
		return nil
	case "check-roles":
		pool, err := store.Open(ctx, cfg.DatabaseURL, store.Options{Schema: cfg.DBSchema})
		if err != nil {
			return err
		}
		defer pool.Close()
		rep, err := store.CheckRuntime(ctx, pool)
		if err != nil {
			return err
		}
		_ = json.NewEncoder(os.Stdout).Encode(rep)
		if !rep.OK() {
			return exitCode(1)
		}
		return nil
	case "status":
		pool, err := privileged(ctx, cfg)
		if err != nil {
			return err
		}
		defer pool.Close()
		applied, embedded, err := store.MigrationVersion(ctx, pool)
		if err != nil {
			return err
		}
		_ = json.NewEncoder(os.Stdout).Encode(map[string]int{"applied": applied, "embedded": embedded})
		if applied != embedded {
			return exitCode(1)
		}
		return nil
	}
	return fmt.Errorf("unknown db command %q", args[0])
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

// ---- serve / worker -------------------------------------------------------------------------------

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

// runtimeContainer builds the container on the runtime login after checking that the login is
// restricted and the schema is fully migrated. Migrations never run here.
func runtimeContainer(ctx context.Context, cfg *config.Config) (*service.Container, error) {
	c, err := service.Build(ctx, cfg, service.Overrides{})
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*service.Container, error) { c.Pool.Close(); return nil, err }
	rep, err := store.CheckRuntime(ctx, c.Pool)
	if err != nil {
		return fail(err)
	}
	if !rep.OK() {
		if !cfg.AllowPrivilegedDBRole {
			return fail(fmt.Errorf("refusing to serve with database login %s (create a restricted login with `strongbox db bootstrap -runtime-login`)", rep))
		}
		slog.Warn("database login is not restricted (development override)", "report", rep.String())
	}
	applied, embedded, err := store.MigrationVersion(ctx, c.Pool)
	if err != nil {
		return fail(fmt.Errorf("read schema version: %w", err))
	}
	if applied != embedded {
		return fail(fmt.Errorf("schema is at migration %d, this build needs %d: run `strongbox init`", applied, embedded))
	}
	return c, nil
}

// metrics installs the OpenTelemetry provider for a runtime process. Shutdown flushes on exit.
func metrics(ctx context.Context, cfg *config.Config, c *service.Container, name string) func() {
	shutdown, err := telemetry.Setup(ctx, cfg.MetricsExporter, name, version, telemetry.Gauges{
		Pool: func() (int64, int64, int64, int64) {
			st := c.DB.Stat()
			return int64(st.AcquiredConns()), int64(st.IdleConns()), int64(st.TotalConns()), int64(st.MaxConns())
		},
		OutboxLag:    func() time.Duration { return c.Worker.LastStats().OldestPendingJob },
		AuditBacklog: func() int64 { return c.Worker.LastStats().AuditUndelivered },
		DeadJobs:     func() int64 { return c.Worker.LastStats().DeadJobs },
		CacheStats: func() (int64, int64) {
			_, hits, misses, _ := c.Keys.CacheStats()
			return hits, misses
		},
	})
	if err != nil {
		slog.Error("metrics disabled", "exporter", cfg.MetricsExporter, "error", err)
		return func() {}
	}
	return func() {
		flush, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = shutdown(flush)
	}
}

func cmdServe(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", defaultAddr(), "listen address")
	worker := fs.Bool("worker", true, "also run the background worker in this process")
	_ = fs.Parse(args)
	cfg, err := load()
	if err != nil {
		return err
	}
	c, err := runtimeContainer(ctx, cfg)
	if err != nil {
		return err
	}
	defer c.Pool.Close()
	defer metrics(ctx, cfg, c, "strongbox-api")()
	if *worker {
		go c.Worker.Run(ctx)
	}
	slog.Info("strongbox api", "version", version, "app_env", cfg.AppEnv, "kms", c.KMS.Describe(), "blobs", c.Backend.Describe(),
		"fips", crypto.FIPSStatus())
	return listen(ctx, *addr, api.New(c))
}

func cmdWorker(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("worker", flag.ExitOnError)
	once := fs.Bool("once", false, "run one pass and exit")
	_ = fs.Parse(args)
	cfg, err := load()
	if err != nil {
		return err
	}
	c, err := runtimeContainer(ctx, cfg)
	if err != nil {
		return err
	}
	defer c.Pool.Close()
	defer metrics(ctx, cfg, c, "strongbox-worker")()
	if *once {
		stats, err := c.Worker.RunOnce(ctx)
		_ = json.NewEncoder(os.Stdout).Encode(stats)
		return err
	}
	c.Worker.Run(ctx)
	return nil
}

// cmdGC is the old name for one worker pass. Deprecated: use `strongbox worker -once`.
func cmdGC(ctx context.Context, _ []string) error {
	fmt.Fprintln(os.Stderr, "strongbox gc is deprecated; use `strongbox worker -once`")
	return cmdWorker(ctx, []string{"-once"})
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
	opts := mcpserver.Options{MaxReadBytes: maxRead, DefaultApp: os.Getenv("STRONGBOX_MCP_APP")}
	switch *transport {
	case "stdio":
		opts.DefaultOnBehalfOf = os.Getenv("STRONGBOX_MCP_ON_BEHALF_OF")
		return mcpserver.New(cl, opts).Run(ctx, &mcp.StdioTransport{})
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
		return listen(ctx, *addr, mcpserver.HTTPHandler(mcpserver.New(cl, opts), verify, publicURL, issuer))
	default:
		return fmt.Errorf("unknown transport %q", *transport)
	}
}

// ---- admin ----------------------------------------------------------------------------------------

const adminUsage = `usage:
  strongbox admin app create APP -admin SUBJECT [-name NAME]     APP is <app_id>:<env>, e.g. notes:prod
  strongbox admin app status APP active|suspended
  strongbox admin client add|remove APP SUBJECT                  workloads that may act for members
  strongbox admin member set APP SUBJECT ROLE                    recovery: viewer|member|editor|admin
  strongbox admin legacy-assign -app APP [-dry-run] [-verify]    move pre-app-scoping rows into APP
  strongbox admin transfer-owner -app APP -kind record|blob -id ID -to SUBJECT
  strongbox admin quota set APP [-max-blob-bytes N] [-max-blobs N] [-max-records N] [-max-record-bytes N]   (omitted: unlimited)`

func cmdAdmin(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New(adminUsage)
	}
	cfg, err := load()
	if err != nil {
		return err
	}
	pool, err := privileged(ctx, cfg)
	if err != nil {
		return err
	}
	defer pool.Close()
	actor := "admin-cli:" + firstNonEmpty(os.Getenv("STRONGBOX_ADMIN_ACTOR"), os.Getenv("USER"), "unknown")
	a := &admin.Admin{Pool: pool, Actor: actor, Stripes: cfg.AuditStripes}
	need := func(n int) error {
		if len(args) < n {
			return errors.New(adminUsage)
		}
		return nil
	}
	switch args[0] {
	case "app":
		if err := need(3); err != nil {
			return err
		}
		switch args[1] {
		case "create":
			fs := flag.NewFlagSet("admin app create", flag.ExitOnError)
			first := fs.String("admin", "", "first admin (a registered principal)")
			name := fs.String("name", "", "display name")
			_ = fs.Parse(args[3:])
			if *first == "" {
				return errors.New("-admin is required")
			}
			return a.CreateApp(ctx, args[2], *name, *first)
		case "status":
			if err := need(4); err != nil {
				return err
			}
			return a.SetAppStatus(ctx, args[2], args[3])
		}
	case "client":
		if err := need(4); err != nil {
			return err
		}
		if args[1] == "add" {
			return a.AddClient(ctx, args[2], args[3])
		}
		if args[1] == "remove" {
			return a.RemoveClient(ctx, args[2], args[3])
		}
	case "member":
		if len(args) < 5 || args[1] != "set" {
			return errors.New(adminUsage)
		}
		return a.SetMember(ctx, args[2], args[3], args[4])
	case "legacy-assign":
		fs := flag.NewFlagSet("admin legacy-assign", flag.ExitOnError)
		app := fs.String("app", "", "target app <app_id>:<env>")
		dry := fs.Bool("dry-run", false, "count and verify only")
		verify := fs.Bool("verify", true, "decrypt every legacy object under its original context before moving")
		_ = fs.Parse(args[1:])
		kp, err := service.BuildKMS(ctx, cfg)
		if err != nil {
			return err
		}
		a.KMS = kp
		rep, err := a.AssignLegacy(ctx, service.NewKeys(kp, cfg.DataKeyRotation, cfg.DataKeyCacheTTL, 1024), *app, *dry, *verify)
		_ = json.NewEncoder(os.Stdout).Encode(rep)
		return err
	case "quota":
		if len(args) < 3 || args[1] != "set" {
			return errors.New(adminUsage)
		}
		fs := flag.NewFlagSet("admin quota set", flag.ExitOnError)
		limit := func(name, usage string) *int64 { return fs.Int64(name, -1, usage+" (-1: unlimited)") }
		bb, nb := limit("max-blob-bytes", "blob bytes, including pending uploads"), limit("max-blobs", "blobs")
		nr, rb := limit("max-records", "live records"), limit("max-record-bytes", "stored bytes of live records")
		_ = fs.Parse(args[3:])
		opt := func(v *int64) *int64 {
			if *v < 0 {
				return nil
			}
			return v
		}
		return a.SetQuota(ctx, args[2], admin.Quota{MaxBlobBytes: opt(bb), MaxBlobs: opt(nb), MaxRecords: opt(nr), MaxRecordBytes: opt(rb)})
	case "transfer-owner":
		fs := flag.NewFlagSet("admin transfer-owner", flag.ExitOnError)
		app := fs.String("app", "", "app <app_id>:<env>")
		kind := fs.String("kind", "record", "record or blob")
		id := fs.String("id", "", "resource id")
		to := fs.String("to", "", "new owner (an app member)")
		_ = fs.Parse(args[1:])
		return a.TransferOwner(ctx, *app, *kind, *id, *to)
	}
	return errors.New(adminUsage)
}

// cmdUsage reports what one app (or every app) stores, from the counters or with a full recount.
func cmdUsage(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("usage", flag.ExitOnError)
	app := fs.String("app", "", "one app (<app_id>:<env>); default every app")
	recount := fs.Bool("recount", false, "also scan the tables and report counter drift")
	fix := fs.Bool("fix", false, "rewrite drifted counters from the scan (locks records and blobs briefly)")
	_ = fs.Parse(args)
	cfg, err := load()
	if err != nil {
		return err
	}
	pool, err := privileged(ctx, cfg)
	if err != nil {
		return err
	}
	defer pool.Close()
	a := &admin.Admin{Pool: pool, Actor: "admin-cli:" + firstNonEmpty(os.Getenv("STRONGBOX_ADMIN_ACTOR"), os.Getenv("USER"), "unknown"),
		Stripes: cfg.AuditStripes}
	apps := []string{*app}
	if *app == "" {
		if apps, err = a.Apps(ctx); err != nil {
			return err
		}
	}
	drift := false
	enc := json.NewEncoder(os.Stdout)
	for _, name := range apps {
		u, err := a.AppUsage(ctx, name, *recount, *fix)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		drift = drift || u.Drift
		_ = enc.Encode(u)
	}
	if drift && !*fix {
		return exitCode(1)
	}
	return nil
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

func cmdPrincipal(ctx context.Context, args []string) error {
	if len(args) == 0 || (args[0] != "put" && args[0] != "list") {
		return errors.New("usage: strongbox principal put SUBJECT [flags] | strongbox principal list")
	}
	cfg, err := load()
	if err != nil {
		return err
	}
	pool, err := privileged(ctx, cfg)
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

// cmdAuditVerify checks every chain (or one app's chains) as the privileged login.
func cmdAuditVerify(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("audit-verify", flag.ExitOnError)
	app := fs.String("app", "", "only this app's chains (<app_id>:<env>)")
	_ = fs.Parse(args)
	cfg, err := load()
	if err != nil {
		return err
	}
	pool, err := privileged(ctx, cfg)
	if err != nil {
		return err
	}
	defer pool.Close()
	out := audit.VerifyResult{OK: true, Chains: []audit.ChainResult{}}
	err = pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL ROLE `+store.OwnerRole); err != nil {
			return err
		}
		chains, err := audit.Chains(ctx, tx)
		if err != nil {
			return err
		}
		for _, ch := range chains {
			if *app != "" && !strings.HasPrefix(ch, "app:"+*app+":") {
				continue
			}
			r, err := audit.VerifyChain(ctx, tx, ch)
			if err != nil {
				return err
			}
			out.OK = out.OK && r.OK
			out.Chains = append(out.Chains, r)
		}
		return nil
	})
	if err != nil {
		return err
	}
	_ = json.NewEncoder(os.Stdout).Encode(out)
	if !out.OK {
		return exitCode(1)
	}
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
