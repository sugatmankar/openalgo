import json
import os
from urllib.parse import parse_qs, urlparse

import httpx

from utils.httpx_client import get_httpx_client
from utils.logging import get_logger

logger = get_logger(__name__)


def authenticate_broker(code):
    try:
        BROKER_API_KEY = os.getenv("BROKER_API_KEY")
        BROKER_API_SECRET = os.getenv("BROKER_API_SECRET")
        REDIRECT_URL = os.getenv("REDIRECT_URL")

        if not all([BROKER_API_KEY, BROKER_API_SECRET, REDIRECT_URL]):
            logger.error(
                "Broker API key, secret, or redirect URL is not set in environment variables."
            )
            return None, "Configuration error: Missing API credentials."

        url = "https://api.upstox.com/v2/login/authorization/token"
        data = {
            "code": code,
            "client_id": BROKER_API_KEY,
            "client_secret": BROKER_API_SECRET,
            "redirect_uri": REDIRECT_URL,
            "grant_type": "authorization_code",
        }

        client = get_httpx_client()
        response = client.post(url, data=data)

        if response.status_code == 200:
            response_data = response.json()
            access_token = response_data.get("access_token")
            if access_token:
                logger.debug("Successfully authenticated with Upstox and received access token.")
                return access_token, None
            else:
                error_msg = "Authentication succeeded but no access token was returned."
                logger.error(f"{error_msg} Response: {response_data}")
                return None, error_msg
        else:
            error_msg = "Upstox API authentication failed."
            try:
                error_detail = response.json()
                errors = error_detail.get("errors", [])
                detailed_message = "; ".join(
                    [err.get("message", "Unknown error") for err in errors]
                )
                error_msg = f"Upstox API Error: {detailed_message}"
                logger.error(
                    f"{error_msg} | Status: {response.status_code}, Response: {response.text}"
                )
            except json.JSONDecodeError:
                logger.error(
                    f"{error_msg} | Status: {response.status_code}, Response: {response.text}"
                )
            return None, error_msg

    except httpx.RequestError as e:
        logger.exception("An HTTP request error occurred during Upstox authentication.")
        return None, f"An HTTP request error occurred: {e}"

    except Exception:
        logger.exception("An unexpected error occurred during Upstox authentication.")
        return None, "An unexpected error occurred during authentication."


def _normalize_mobile(mobile_no):
    """Normalize to 10-digit Indian mobile (Upstox expects digits only, no +91)."""
    s = (mobile_no or "").strip()
    for prefix in ("+91", "91", "0"):
        if s.startswith(prefix):
            s = s[len(prefix):].strip()
            break
    return "".join(c for c in s if c.isdigit())[-10:] if s else s


def _get_token_via_raw_flow(api_key, client_secret, mobile_no, password, totp_key, pin, redirect_uri):
    """
    Fallback: run the upstox-totp TOTP flow but extract the access_token
    from the raw JSON response, bypassing the library's Pydantic models.
    """
    from pydantic import SecretStr
    from upstox_totp import UpstoxTOTP

    upx = UpstoxTOTP(
        username=mobile_no,
        password=SecretStr(password),
        pin_code=SecretStr(pin),
        totp_secret=SecretStr(totp_key),
        client_id=api_key,
        client_secret=SecretStr(client_secret),
        redirect_uri=redirect_uri,
    )

    # Run TOTP flow up to getting the OAuth auth code
    oauth_response = upx.app_token.oauth_authorization()
    if oauth_response.data is None:
        raise Exception("OAuth response missing data")

    parsed = urlparse(oauth_response.data.redirectUri)
    params = parse_qs(parsed.query)
    code_list = params.get("code")
    if not code_list:
        raise Exception(f"Authorization code not found in redirect URI. Got params: {params}")
    code = code_list[0]

    # Exchange the code for access token using raw HTTP (bypass library's model)
    import requests as req
    token_url = "https://api.upstox.com/v2/login/authorization/token"
    payload = {
        "code": code,
        "client_id": api_key,
        "client_secret": client_secret,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code",
    }
    headers = {
        "accept": "application/json",
        "content-type": "application/x-www-form-urlencoded",
    }
    resp = req.post(token_url, data=payload, headers=headers, timeout=15)
    if not resp.ok:
        raise Exception(f"Token exchange failed ({resp.status_code}): {resp.text}")
    data = resp.json()
    access_token = data.get("access_token")
    if not access_token:
        raise Exception(f"No access_token in response: {data}")
    logger.info("Upstox: access token obtained via raw fallback flow")
    return access_token


def authenticate_broker_totp(mobile_number, password, totp_key, pin):
    """
    Authenticate with Upstox using the upstox-totp library (pure HTTP, no browser).
    Uses curl_cffi with Chrome impersonation to bypass bot detection.

    Args:
        mobile_number: 10-digit mobile number (or with +91/91 prefix)
        password: Upstox login password
        totp_key: TOTP secret key (not the generated code – we generate it internally)
        pin: Upstox 4-6 digit trading PIN

    Returns:
        Tuple of (access_token, error_message)
    """
    try:
        BROKER_API_KEY = os.getenv("BROKER_API_KEY", "")
        BROKER_API_SECRET = os.getenv("BROKER_API_SECRET", "")
        REDIRECT_URL = os.getenv("REDIRECT_URL", "")

        if not all([BROKER_API_KEY, BROKER_API_SECRET, REDIRECT_URL]):
            return None, "BROKER_API_KEY, BROKER_API_SECRET, or REDIRECT_URL not configured"

        mobile = _normalize_mobile(mobile_number)
        if len(mobile) != 10:
            return None, f"Expected 10-digit mobile number, got {len(mobile)} digits"

        # Log for debugging (mask sensitive data)
        _mask = lambda s: (s[:4] + "..." + s[-4:]) if s and len(s) > 10 else "****"
        logger.info(f"Upstox TOTP login: client_id={_mask(BROKER_API_KEY)} redirect_uri={REDIRECT_URL}")

        try:
            from pydantic import SecretStr
            from upstox_totp import UpstoxTOTP
        except ImportError:
            return None, ("upstox-totp library not installed. "
                          "Install with: uv add upstox-totp curl_cffi")

        # Patch upstox-totp AccessTokenData model: Upstox API can return null
        # for poa/ddpi/is_active fields, causing Pydantic validation errors.
        try:
            from typing import Optional
            from upstox_totp.models import AccessTokenData
            _needs_rebuild = False
            for _field_name in ("poa", "ddpi", "is_active"):
                if _field_name in AccessTokenData.model_fields:
                    _finfo = AccessTokenData.model_fields[_field_name]
                    if _finfo.annotation is bool:
                        _finfo.annotation = Optional[bool]
                        _finfo.default = None
                        _needs_rebuild = True
            if _needs_rebuild:
                AccessTokenData.model_rebuild(force=True)
                logger.debug("Patched upstox-totp AccessTokenData: poa/ddpi/is_active now Optional[bool]")
        except Exception as patch_err:
            logger.warning(f"Failed to patch upstox-totp model: {patch_err}")

        # Try the library's full flow first
        try:
            upx = UpstoxTOTP(
                username=mobile,
                password=SecretStr(password),
                pin_code=SecretStr(str(pin)),
                totp_secret=SecretStr(totp_key),
                client_id=BROKER_API_KEY,
                client_secret=SecretStr(BROKER_API_SECRET),
                redirect_uri=REDIRECT_URL,
            )
            response = upx.app_token.get_access_token()
            if not response.success or not response.data:
                error_detail = getattr(response, "error", None) or "unknown error"
                return None, f"Upstox TOTP login failed: {error_detail}"
            logger.info("Upstox TOTP authentication successful")
            return response.data.access_token, None

        except Exception as e:
            err_str = str(e)
            # If Pydantic validation error, fall back to raw flow
            if "poa" in err_str or "ddpi" in err_str or "is_active" in err_str:
                logger.warning("upstox-totp model validation failed, attempting raw token extraction...")
                try:
                    token = _get_token_via_raw_flow(
                        api_key=BROKER_API_KEY,
                        client_secret=BROKER_API_SECRET,
                        mobile_no=mobile,
                        password=password,
                        totp_key=totp_key,
                        pin=str(pin),
                        redirect_uri=REDIRECT_URL,
                    )
                    logger.info("Upstox TOTP authentication successful (raw fallback)")
                    return token, None
                except Exception as raw_err:
                    return None, f"Upstox TOTP login error (fallback also failed): {raw_err}"
            raise

    except Exception as e:
        logger.exception(f"Upstox TOTP auth exception: {e}")
        return None, f"Upstox TOTP auth error: {str(e)}"
