"""OAuth helper module for email-backup.

Provides an interactive OAuth 2.0 flow (currently targeting Gmail) that
launches the system browser, stores refresh tokens securely on disk, and
returns an access token suitable for XOAUTH2 IMAP authentication.

Prerequisites
-------------
1. Install optional dependencies::

       pip install google-auth google-auth-oauthlib

2. Create an OAuth 2.0 "Desktop App" client in Google Cloud Console and
   download the client secret JSON file.

3. Set ``GOOGLE_OAUTH_CLIENT_SECRETS`` to point to that JSON file (or place
   ``client_secret.json`` in the project root).

Tokens are cached in ``~/.email-backup`` (or the directory set by
``EMAIL_BACKUP_TOKEN_DIR``) so repeat runs won't require re-authorisation.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Dict, Optional

PRIMARY_SCOPE = "https://mail.google.com/"
SCOPES = [
    PRIMARY_SCOPE,
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
]
CLIENT_SECRET_ENV = "GOOGLE_OAUTH_CLIENT_SECRETS"
TOKEN_DIR_ENV = "EMAIL_BACKUP_TOKEN_DIR"
DEFAULT_CLIENT_FILENAMES = (
    "client_secret.json",
    "google_client_secret.json",
    "oauth_client_secret.json",
)


def _token_dir() -> Path:
    custom_dir = os.getenv(TOKEN_DIR_ENV)
    if custom_dir:
        return Path(custom_dir).expanduser()
    return Path.home() / ".email-backup"


def _sanitize_email(email: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", email.lower())


def _locate_client_secret() -> Path:
    candidates = []
    env_path = os.getenv(CLIENT_SECRET_ENV)
    if env_path:
        candidates.append(Path(env_path).expanduser())

    cwd = Path.cwd()
    for filename in DEFAULT_CLIENT_FILENAMES:
        candidates.append(cwd / filename)

    for path in candidates:
        if path.is_file():
            return path

    raise FileNotFoundError(
        "Could not locate a Google OAuth client secret file. Set the "
        f"{CLIENT_SECRET_ENV} environment variable or place client_secret.json "
        "in the project directory."
    )


def _load_credentials(token_path: Path, email: str):
    try:
        from google.oauth2.credentials import Credentials  # type: ignore[import-not-found]
    except ImportError as exc:
        raise RuntimeError(
            "google-auth is required for OAuth support. Install with `pip install google-auth`."
        ) from exc

    if token_path.exists():
        creds = Credentials.from_authorized_user_file(str(token_path))
        if not creds:
            return None

        scopes = set(getattr(creds, "scopes", []) or [])
        if PRIMARY_SCOPE not in scopes:
            return None

        if getattr(creds, "client_id", None):
            # Ensure this token belongs to the same email when available
            token_email = getattr(creds, "username", None)
            if token_email and token_email.lower() != email.lower():
                return None
        return creds
    return None


def _refresh_credentials(creds) -> None:
    from google.auth.transport.requests import Request  # type: ignore[import-not-found]

    if creds and creds.expired and creds.refresh_token:
        creds.refresh(Request())


def _run_flow(client_secret_path: Path, email: str):
    try:
        from google_auth_oauthlib.flow import InstalledAppFlow  # type: ignore[import-not-found]
    except ImportError as exc:
        raise RuntimeError(
            "google-auth-oauthlib is required for OAuth support. Install with `pip install google-auth-oauthlib`."
        ) from exc

    flow = InstalledAppFlow.from_client_secrets_file(str(client_secret_path), scopes=SCOPES)
    creds = flow.run_local_server(
        host="localhost",
        port=0,
        authorization_prompt_message="[32mPlease authorise email-backup to access your mailbox.[0m",
        success_message="Authorisation complete. You may close this tab.",
        open_browser=True,
        prompt='consent',
        login_hint=email,
        access_type='offline',
        include_granted_scopes='true',
    )
    return creds


def start_oauth_flow(
    email: str,
    imap_server: Optional[str] = None,
    imap_port: Optional[int] = None,
) -> Dict[str, Any]:
    """Start an OAuth flow for the given email address.

    Args:
        email: The email account to authenticate.
        imap_server: Suggested IMAP server inferred earlier (if any).
        imap_port: Suggested IMAP port inferred earlier (if any).

    Returns:
        A dictionary containing ``access_token`` (mandatory) plus optional
        metadata such as ``refresh_token``, ``token_path``, ``imap_server`` and
        ``imap_port``.
    """

    email = email.strip()
    if not email or "@" not in email:
        raise ValueError("A valid email address is required for OAuth authentication.")

    client_secret_path = _locate_client_secret()
    token_dir = _token_dir()
    token_dir.mkdir(parents=True, exist_ok=True)
    token_path = token_dir / f"token-{_sanitize_email(email)}.json"

    creds = _load_credentials(token_path, email)

    if creds:
        _refresh_credentials(creds)
        if not creds.valid:
            creds = None

    if not creds:
        creds = _run_flow(client_secret_path, email)

    if not creds:
        raise RuntimeError("OAuth flow did not return credentials.")

    _refresh_credentials(creds)

    if not creds.valid:
        raise RuntimeError("OAuth credentials could not be validated after authentication.")

    token_path.write_text(creds.to_json())

    access_token = creds.token
    if not access_token:
        raise RuntimeError("OAuth credentials did not include an access token.")

    result: Dict[str, Any] = {
        "access_token": access_token,
        "imap_server": imap_server,
        "imap_port": imap_port,
        "token_path": str(token_path),
        "scopes": list(creds.scopes or []),
    }

    if getattr(creds, "refresh_token", None):
        result["refresh_token"] = creds.refresh_token

    return result
