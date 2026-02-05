"""OAuth helper module for Microsoft (Outlook/Microsoft 365) email.

Provides an interactive OAuth 2.0 flow using Microsoft Authentication Library (MSAL)
that launches the system browser, stores refresh tokens securely on disk, and
returns an access token suitable for XOAUTH2 IMAP authentication.

Prerequisites
-------------
1. Install optional dependencies::

       pip install msal

2. Register an application in Azure AD (https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationsListBlade):
   - Choose "Personal Microsoft accounts only" or "Accounts in any organizational directory and personal Microsoft accounts"
   - Add "Mobile and desktop applications" platform with redirect URI: http://localhost
   - Under API permissions, add "IMAP.AccessAsUser.All" (Microsoft Graph or Office 365 Exchange Online)

3. Set ``MICROSOFT_OAUTH_CLIENT_ID`` to your Application (client) ID from Azure portal,
   or store it in a JSON file and set ``MICROSOFT_OAUTH_CLIENT_SECRETS`` to point to that file.

Tokens are cached in ``~/.email-backup`` (or the directory set by
``EMAIL_BACKUP_TOKEN_DIR``) so repeat runs won't require re-authorisation.
"""

from __future__ import annotations

import json
import os
import re
import webbrowser
from pathlib import Path
from typing import Any, Dict, Optional

# Microsoft IMAP/SMTP OAuth scopes - use outlook.office.com for personal accounts
SCOPES = [
    "https://outlook.office.com/IMAP.AccessAsUser.All",
    "https://outlook.office.com/SMTP.Send",
]

CLIENT_ID_ENV = "MICROSOFT_OAUTH_CLIENT_ID"
CLIENT_SECRET_FILE_ENV = "MICROSOFT_OAUTH_CLIENT_SECRETS"
TOKEN_DIR_ENV = "EMAIL_BACKUP_TOKEN_DIR"

# Authority for personal Microsoft accounts (hotmail, outlook.com, live.com)
AUTHORITY = "https://login.microsoftonline.com/common"

DEFAULT_CLIENT_FILENAMES = (
    "microsoft_client_secret.json",
    "ms_client_secret.json",
    "outlook_client_secret.json",
)


def _token_dir() -> Path:
    custom_dir = os.getenv(TOKEN_DIR_ENV)
    if custom_dir:
        return Path(custom_dir).expanduser()
    return Path.home() / ".email-backup"


def _sanitize_email(email: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", email.lower())


def _get_client_id() -> str:
    """Get Microsoft OAuth client ID from environment or config file."""
    # Check environment variable first
    client_id = os.getenv(CLIENT_ID_ENV, "").strip()
    if client_id:
        return client_id

    # Check for JSON config file
    candidates = []
    env_path = os.getenv(CLIENT_SECRET_FILE_ENV)
    if env_path:
        candidates.append(Path(env_path).expanduser())

    cwd = Path.cwd()
    for filename in DEFAULT_CLIENT_FILENAMES:
        candidates.append(cwd / filename)

    for path in candidates:
        if path.is_file():
            try:
                with open(path, 'r') as f:
                    config = json.load(f)
                    # Support different JSON structures
                    if isinstance(config, dict):
                        client_id = config.get("client_id") or config.get("application_id") or config.get("app_id")
                        if client_id:
                            return client_id
            except (json.JSONDecodeError, KeyError):
                continue

    raise ValueError(
        f"Microsoft OAuth client ID not found. Set the {CLIENT_ID_ENV} environment variable "
        f"or create a JSON file with 'client_id' field and set {CLIENT_SECRET_FILE_ENV} to point to it."
    )


def _load_token_cache(cache_path: Path):
    """Load MSAL token cache from disk."""
    try:
        from msal import SerializableTokenCache  # type: ignore[import-not-found]
    except ImportError as exc:
        raise RuntimeError(
            "msal is required for Microsoft OAuth support. Install with `pip install msal`."
        ) from exc

    cache = SerializableTokenCache()
    if cache_path.exists():
        with open(cache_path, 'r') as f:
            cache.deserialize(f.read())
    return cache


def _save_token_cache(cache, cache_path: Path):
    """Save MSAL token cache to disk."""
    if cache.has_state_changed:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        with open(cache_path, 'w') as f:
            f.write(cache.serialize())


def _acquire_token_interactive(app, scopes: list[str], email: str):
    """Launch browser-based OAuth flow."""
    print("\n" + "="*60)
    print("Microsoft OAuth Authentication")
    print("="*60)
    print("A browser window will open for you to sign in...")
    print("="*60 + "\n")

    # Use interactive browser flow
    result = app.acquire_token_interactive(
        scopes=scopes,
        login_hint=email,
    )
    return result


def start_microsoft_oauth_flow(
    email: str,
    imap_server: Optional[str] = None,
    imap_port: Optional[int] = None,
) -> Dict[str, Any]:
    """Start a Microsoft OAuth flow for the given email address.

    Args:
        email: The email account to authenticate (Outlook, Hotmail, Live, Microsoft 365).
        imap_server: Suggested IMAP server (defaults to outlook.office365.com).
        imap_port: Suggested IMAP port (defaults to 993).

    Returns:
        A dictionary containing ``access_token`` (mandatory) plus optional
        metadata such as ``token_path``, ``imap_server`` and ``imap_port``.
    """
    try:
        from msal import PublicClientApplication  # type: ignore[import-not-found]
    except ImportError as exc:
        raise RuntimeError(
            "msal is required for Microsoft OAuth support. Install with `pip install msal`."
        ) from exc

    email = email.strip()
    if not email or "@" not in email:
        raise ValueError("A valid email address is required for OAuth authentication.")

    client_id = _get_client_id()

    # Use outlook.office365.com for Microsoft email services
    if not imap_server:
        imap_server = "outlook.office365.com"
    if not imap_port:
        imap_port = 993

    token_dir = _token_dir()
    token_dir.mkdir(parents=True, exist_ok=True)
    cache_path = token_dir / f"ms-token-{_sanitize_email(email)}.json"

    cache = _load_token_cache(cache_path)

    app = PublicClientApplication(
        client_id=client_id,
        authority=AUTHORITY,
        token_cache=cache,
    )

    # Try to get cached token first
    accounts = app.get_accounts()
    result = None

    # Filter accounts by email if available
    matching_accounts = [acc for acc in accounts if acc.get("username", "").lower() == email.lower()]
    if matching_accounts:
        result = app.acquire_token_silent(SCOPES, account=matching_accounts[0])
    elif accounts:
        # Try any cached account
        result = app.acquire_token_silent(SCOPES, account=accounts[0])

    # If no cached token, do interactive flow
    if not result or "access_token" not in result:
        result = _acquire_token_interactive(app, SCOPES, email)

    _save_token_cache(cache, cache_path)

    if not result or "access_token" not in result:
        error_desc = result.get("error_description", "Unknown error") if result else "No result returned"
        raise RuntimeError(f"Microsoft OAuth authentication failed: {error_desc}")

    access_token = result["access_token"]

    return {
        "access_token": access_token,
        "imap_server": imap_server,
        "imap_port": imap_port,
        "token_path": str(cache_path),
        "scopes": SCOPES,
    }
