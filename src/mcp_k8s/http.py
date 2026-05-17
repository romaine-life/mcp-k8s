"""HTTP entrypoint — streamable-http transport, layered auth.

Two layers gate inbound calls:

  1. **kube-rbac-proxy** (in front of this process): validates the
     caller's K8s SA token via TokenReview + SubjectAccessReview
     (see ../k8s-mcp-k8s/templates/proxy-config.yaml). "Some pod with
     an allowed SA is talking to me" — no human identity. Binding
     loopback so direct pod-IP:8080 access bypasses nothing.

  2. **auth.romaine.life JWT** (in this process): if the caller also
     presents an Authorization: Bearer JWT signed by auth.romaine.life,
     CallerJWTMiddleware verifies it against the IdP's JWKS and binds
     the resolved Caller (sub, email, role, actor_email) to a
     ContextVar. Tool handlers can attribute their work to a specific
     human via Caller.display_actor.

Layer 2 is OPTIONAL on the way in (no JWT means caller is "unknown"
to this process, layer 1 is still gating connectivity), but when
present the JWT must verify or the request is 401'd. Half-trusting
a malformed JWT would be worse than ignoring the header entirely.

Outbound auth (kubectl + helm) uses the in-cluster ServiceAccount
token at /var/run/secrets/kubernetes.io/serviceaccount/token. No
kubeconfig needed — the binaries pick that up automatically.
"""

import logging
import os
from contextlib import asynccontextmanager

import jwt
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Mount, Route

from romaine_auth import (
    CALLER,
    AuthRomaineLifeVerifier,
    default_verifier,
    warn_jwks_unreachable,
)
from .tools import register_tools

log = logging.getLogger(__name__)


class CallerJWTMiddleware(BaseHTTPMiddleware):
    """Verify Authorization: Bearer JWT against auth.romaine.life's JWKS
    and bind the resolved Caller to a ContextVar.

    Verification is best-effort: missing or empty Authorization header
    leaves the Caller as None and proceeds (kube-rbac-proxy is still
    gating connectivity). A *present* but invalid JWT is rejected with
    401 — a malformed token is more suspect than no token.
    """

    # Routes that should bypass JWT verification entirely. /healthz is
    # the liveness probe path and shouldn't require auth.
    _BYPASS_PATHS = frozenset({"/healthz"})

    def __init__(self, app, verifier: AuthRomaineLifeVerifier | None = None):
        super().__init__(app)
        self._verifier = verifier

    async def dispatch(self, request: Request, call_next):
        if request.url.path in self._BYPASS_PATHS:
            return await call_next(request)

        authz = request.headers.get("authorization", "")
        if not authz.lower().startswith("bearer "):
            # No JWT presented. kube-rbac-proxy is still doing its job;
            # we just don't get user attribution this call.
            return await call_next(request)

        if self._verifier is None:
            # Verifier not constructed (test env or misconfig). Skip
            # verification but log so we notice in production.
            log.warning("inbound bearer present but JWT verifier not configured; skipping")
            return await call_next(request)

        token = authz[len("bearer "):].strip()
        try:
            caller = self._verifier.verify(token)
        except (jwt.PyJWTError, ValueError) as exc:
            log.info("inbound JWT verification failed: %s", exc)
            return JSONResponse(
                {"error": "invalid auth.romaine.life JWT", "detail": str(exc)},
                status_code=401,
            )
        except Exception as exc:
            # PyJWKClient raises URLError / OSError on network failure.
            # Rate-limit the warning so a JWKS outage doesn't flood logs.
            warn_jwks_unreachable(
                os.environ.get("AUTH_ROMAINE_LIFE_JWKS_URL", "<default>"), exc
            )
            return JSONResponse(
                {"error": "JWKS unreachable; cannot verify inbound JWT"},
                status_code=503,
            )

        token_ctx = CALLER.set(caller)
        try:
            return await call_next(request)
        finally:
            CALLER.reset(token_ctx)


def build_app() -> Starlette:
    # Same DNS-rebinding-protection workaround as mcp-github: the streamable_http
    # transport ships a middleware that 421s any Host header not in
    # `allowed_hosts`. The default whitelist only covers localhost, so
    # in-cluster requests to mcp-k8s.mcp-k8s.svc would be rejected. Disable
    # here — kube-rbac-proxy in front of us already gates auth via K8s SA
    # tokens, so DNS rebinding can't reach an unauthorized caller anyway.
    # streamable_http_path="/" avoids Starlette's trailing-slash redirect
    # (was 307 → 421 loop in mcp-github).
    mcp = FastMCP(
        "k8s-mcp",
        stateless_http=True,
        streamable_http_path="/",
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=False,
        ),
    )
    register_tools(mcp)

    async def healthz(_: Request) -> Response:
        return Response("ok", media_type="text/plain")

    async def delete_session(_: Request) -> Response:
        # FastMCP stateless mode returns 405 for DELETE, but Claude Code's MCP
        # client treats 405 as fatal. Return 200 so it can reconnect cleanly.
        return Response(status_code=200)

    # Starlette's Mount doesn't forward lifespan events to the inner app, so
    # FastMCP's session_manager.run() — which sets up the anyio task group
    # the streamable-http handler depends on — never fires when we mount it.
    # Wire the run() context into the outer app's lifespan ourselves; without
    # this every request 500s with "Task group is not initialized".
    @asynccontextmanager
    async def lifespan(_app: Starlette):
        async with mcp.session_manager.run():
            yield

    # JWT verifier shared across all inbound requests. Construction
    # touches no network — PyJWKClient defers JWKS fetch until first
    # verify — so it's safe at import time. If env points it at a
    # broken JWKS URL, the first verify fails with 503 (handled in
    # CallerJWTMiddleware) and the absence of a JWT on subsequent
    # requests is tolerated.
    verifier = default_verifier()

    return Starlette(
        routes=[
            Route("/healthz", healthz),
            Route("/", delete_session, methods=["DELETE"]),
            Mount("/", app=mcp.streamable_http_app()),
        ],
        middleware=[
            Middleware(CallerJWTMiddleware, verifier=verifier),
        ],
        lifespan=lifespan,
    )


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    import uvicorn

    port = int(os.environ.get("PORT", "8080"))
    uvicorn.run(build_app(), host="127.0.0.1", port=port)


if __name__ == "__main__":
    main()
