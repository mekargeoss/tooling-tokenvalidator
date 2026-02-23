# 2026 Mekarge OSS and Maintainers
# Licensed under the MIT License. See LICENSE file in the project root for full license information.

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

import httpx
from jose import jwt

@dataclass
class A3Discovery:
    issuer: str
    jwks_uri: str
    authorization_endpoint: str
    token_endpoint: str

def fetch_discovery(issuer: str, timeout: float = 10.0) -> A3Discovery:
    issuer = issuer.rstrip("/")
    url = f"https://a3.mekarge.com/auth/{issuer}/.well-known/openid-configuration"
    with httpx.Client(timeout=timeout, verify=True) as client:
        r = client.get(url)
        r.raise_for_status()
        data = r.json()
    if "jwks_uri" not in data:
        raise RuntimeError("Discovery document missing 'jwks_uri'")
    return A3Discovery(
        issuer=data.get("issuer", issuer),
        jwks_uri=data["jwks_uri"],
        authorization_endpoint=data.get("authorization_endpoint"),
        token_endpoint=data.get("token_endpoint"),
    )

def fetch_jwks(jwks_uri: str, timeout: float = 10.0) -> Dict[str, Any]:
    with httpx.Client(timeout=timeout, verify=True) as client:
        r = client.get(jwks_uri)
        r.raise_for_status()
        return r.json()

def choose_jwk(jwks: Dict[str, Any], kid: Optional[str]) -> Dict[str, Any]:
    keys = jwks.get("keys", [])
    if not keys:
        raise RuntimeError("JWKS has no keys")
    if kid is None:
        return keys[0]
    for k in keys:
        if k.get("kid") == kid:
            return k
    raise RuntimeError(f"No matching JWK found for kid={kid}")

def claim_contains_scope(claim_scope: Any, required_scope: str) -> bool:
    if claim_scope is None:
        return False

    parts = claim_scope.split()
    return required_scope in parts

def decode_and_verify_jwt_access_token(
    token: str,
    discovery_issuer: str,
    jwks: Dict[str, Any],
    audience: Optional[str],
    scope_token: Optional[str],
) -> Dict[str, Any]:

    header = jwt.get_unverified_header(token)
    kid = header.get("kid")
    jwk_key = choose_jwk(jwks, kid)

    options = {
        "verify_signature": True,
        "verify_aud": audience is not None,
        "verify_iss": True,
        "verify_exp": True,
        "verify_nbf": True,
        "verify_iat": True,
        "require_exp": True,
    }

    claims = jwt.decode(
        token,
        jwk_key,
        algorithms=[jwk_key.get("alg", "RS256")] if jwk_key.get("alg") else None,
        issuer=discovery_issuer.rstrip("/"),
        audience=audience,
        options=options,
    )

    if scope_token:
        if not claim_contains_scope(claims.get("scope"), scope_token):
            raise RuntimeError(f"Required scope '{scope_token}' not present in token scope={claims.get('scope')}")

    return claims


def read_token_from_args(token: Optional[str], token_file: Optional[str]) -> str:
    if token and token_file:
        raise ValueError("Use either --token or --token-file, not both.")
    if token:
        return token.strip()
    if token_file:
        with open(token_file, "r", encoding="utf-8") as f:
            return f.read().strip()

    if not sys.stdin.isatty():
        return sys.stdin.read().strip()
    raise ValueError("No token provided. Use --token, --token-file, or pipe via stdin.")

def main() -> int:
    p = argparse.ArgumentParser(description="Mekarge A3 Access Token validation tool. Use with tokens signed with asymmetric keys (i.e RS256).")
    p.add_argument("--issuer-path", required=True, help="Issuer Path defined for the Environment (e.g., alias-00000000000000000000000000000000)")
    p.add_argument("--token", help="Access Token string (JWT).")
    p.add_argument("--token-file", help="Path to a file containing the access token.")
    p.add_argument("--aud", help="Expected audience (aud). If omitted, aud validation is skipped.")
    p.add_argument("--scope", help="Expected scope token. If omitted, scope token check is skipped.")
    p.add_argument("--timeout", type=float, default=10.0, help="HTTP timeout seconds (default 10)")
    args = p.parse_args()

    token = read_token_from_args(args.token, args.token_file)

    try:
        discovery = fetch_discovery(args.issuer_path, timeout=args.timeout)
        jwks = fetch_jwks(discovery.jwks_uri, timeout=args.timeout)

        claims = decode_and_verify_jwt_access_token(
            token,
            discovery_issuer=discovery.issuer,
            jwks=jwks,
            audience=args.aud,
            scope_token=args.scope,
        )

        now = int(time.time())
        exp = claims.get("exp")
        print("✅ Token is valid")
        if exp:
            print(f"Expires in: {int(exp) - now}s")
        print(f"Claims: \n {json.dumps(claims, indent=2, sort_keys=True)}")

        return 0

    except Exception as e:
        print(f"❌ Token validation failed! Cause: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
