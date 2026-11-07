"""`strongbox` command line: init, keyring, principals, dev tokens, audit, serve, mcp."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from strongbox.auth.principal import PrincipalKind, PrincipalRegistry, PrincipalSpec
from strongbox.config import AuthMode, Environment, KmsBackend, get_settings
from strongbox.crypto.kms import LocalKeyProvider
from strongbox.storage.database import Database


def _db() -> Database:
    s = get_settings()
    return Database(s.database_url)


def cmd_init(_: argparse.Namespace) -> int:
    s = get_settings()
    if s.kms_backend is KmsBackend.LOCAL and not s.local_keyring_path.exists():
        LocalKeyProvider.create(s.local_keyring_path)
        print(f"created local keyring {s.local_keyring_path} (development only)")
    if s.blob_backend.value == "local":
        s.blob_local_path.mkdir(parents=True, exist_ok=True)
    if s.database_url.startswith("sqlite:///"):
        Path(s.database_url.removeprefix("sqlite:///")).parent.mkdir(parents=True, exist_ok=True)
    _db().create_all()
    print("schema ready")
    return 0


def cmd_keyring(args: argparse.Namespace) -> int:
    s = get_settings()
    path = args.path or s.local_keyring_path
    kid = LocalKeyProvider.create(path) if args.action == "create" else LocalKeyProvider.rotate(path)
    print(f"{args.action}d local keyring {path}; active key {kid}")
    return 0


def cmd_principal(args: argparse.Namespace) -> int:
    reg = PrincipalRegistry(_db())
    if args.action == "list":
        print(json.dumps(reg.list(), indent=2, default=str))
        return 0
    reg.put(
        PrincipalSpec(
            subject=args.subject,
            kind=PrincipalKind(args.kind),
            scopes=args.scope or [],
            us_person=args.us_person,
            cui_access=args.cui_access,
            cui_categories=args.category or [],
            dissemination=args.ldc or [],
            llm_boundary_authorized=args.llm_boundary,
            display_name=args.display_name,
            disabled=args.disabled,
        )
    )
    print(f"principal {args.subject} saved")
    return 0


def cmd_token(args: argparse.Namespace) -> int:
    s = get_settings()
    if s.env is Environment.PRODUCTION or s.auth_mode is not AuthMode.DEV_HS256 or s.dev_jwt_secret is None:
        print("dev tokens are only available in dev-hs256 mode", file=sys.stderr)
        return 2
    from strongbox.auth.tokens import mint_dev_token

    print(mint_dev_token(s.dev_jwt_secret.get_secret_value(), args.subject, args.audience, args.ttl))
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    from strongbox.audit import AuditLog

    r = AuditLog(_db()).verify()
    print(
        json.dumps(
            {
                "ok": r.ok,
                "checked": r.checked,
                "head_seq": r.head_seq,
                "first_invalid_seq": r.first_invalid_seq,
            }
        )
    )
    return 0 if r.ok else 1


def cmd_gc(args: argparse.Namespace) -> int:
    from strongbox.services.container import Container

    c = Container.build(get_settings())
    print(f"removed {c.blobs.sweep_pending(args.older_than)} abandoned uploads")
    return 0


def cmd_fips(_: argparse.Namespace) -> int:
    from strongbox.crypto.fips import fips_status

    status = fips_status()
    print(json.dumps(status))
    return 0 if status["fips_enabled"] else 1


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    from strongbox.logging_setup import configure_logging

    configure_logging(get_settings().log_level)
    uvicorn.run(
        "strongbox.api.app:create_app",
        factory=True,
        host=args.host,
        port=args.port,
        proxy_headers=True,
        forwarded_allow_ips="*",
        log_config=None,
        server_header=False,
    )
    return 0


def cmd_mcp(args: argparse.Namespace) -> int:
    from strongbox.mcp_server import run

    run(args.transport, args.host, args.port)
    return 0


def cmd_openapi(_: argparse.Namespace) -> int:
    from strongbox.api.app import create_app

    print(json.dumps(create_app().openapi(), indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="strongbox", description="CUI-grade blob and structured data store")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init", help="create schema (and a dev keyring when using local KMS)").set_defaults(
        fn=cmd_init
    )

    k = sub.add_parser("keyring", help="manage the local development keyring")
    k.add_argument("action", choices=["create", "rotate"])
    k.add_argument("--path")
    k.set_defaults(fn=cmd_keyring)

    pr = sub.add_parser("principal", help="register or list principals")
    pr.add_argument("action", choices=["put", "list"])
    pr.add_argument("subject", nargs="?")
    pr.add_argument("--kind", choices=[k.value for k in PrincipalKind], default="user")
    pr.add_argument("--scope", action="append", help="repeatable; '*' for all")
    pr.add_argument("--us-person", action="store_true")
    pr.add_argument("--cui-access", action="store_true")
    pr.add_argument("--category", action="append", help="authorized CUI category, e.g. SP-EXPT; '*' for all")
    pr.add_argument("--ldc", action="append", help="authorized dissemination control, e.g. FEDCON")
    pr.add_argument(
        "--llm-boundary", action="store_true", help="agent runs inside an authorized LLM boundary"
    )
    pr.add_argument("--display-name")
    pr.add_argument("--disabled", action="store_true")
    pr.set_defaults(fn=cmd_principal)

    t = sub.add_parser("token", help="mint a development token")
    t.add_argument("subject")
    t.add_argument("--audience", default="strongbox")
    t.add_argument("--ttl", type=int, default=3600)
    t.set_defaults(fn=cmd_token)

    sub.add_parser("audit-verify", help="verify the audit hash chain").set_defaults(fn=cmd_audit)

    g = sub.add_parser("gc", help="remove abandoned uploads")
    g.add_argument("--older-than", type=int, default=3600)
    g.set_defaults(fn=cmd_gc)

    sub.add_parser("fips-check", help="report whether the crypto module is in FIPS mode").set_defaults(
        fn=cmd_fips
    )

    sv = sub.add_parser("serve", help="run the REST API")
    sv.add_argument("--host", default="0.0.0.0")  # noqa: S104  # nosec B104
    sv.add_argument("--port", type=int, default=8080)
    sv.set_defaults(fn=cmd_serve)

    m = sub.add_parser("mcp", help="run the MCP server")
    m.add_argument("--transport", choices=["stdio", "streamable-http"], default="stdio")
    m.add_argument("--host", default="127.0.0.1")
    m.add_argument("--port", type=int, default=8090)
    m.set_defaults(fn=cmd_mcp)

    sub.add_parser("openapi", help="print the OpenAPI document").set_defaults(fn=cmd_openapi)
    return p


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.cmd == "principal" and args.action == "put" and not args.subject:
        print("principal put requires a subject", file=sys.stderr)
        return 2
    return int(args.fn(args))


if __name__ == "__main__":
    raise SystemExit(main())
