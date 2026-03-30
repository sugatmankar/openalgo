import base64
import hashlib
import json
import os
import time
from typing import Any, Dict, Optional, Tuple
from urllib.parse import parse_qs, urlparse

from utils.httpx_client import get_httpx_client
from utils.logging import get_logger

logger = get_logger(__name__)


def authenticate_broker(request_token: str) -> tuple[str | None, dict[str, Any] | None]:
    """
    Authenticate with FYERS API using request token and return access token with user details.

    Args:
        request_token: The authorization code received from FYERS

    Returns:
        Tuple of (access_token, response_data).
        - access_token: The authentication token if successful, None otherwise
        - response_data: Full response data or error details
    """
    # Initialize response data
    response_data = {"status": "error", "message": "Authentication failed", "data": None}

    # Get environment variables
    broker_api_key = os.getenv("BROKER_API_KEY")
    broker_api_secret = os.getenv("BROKER_API_SECRET")

    # Validate environment variables
    if not broker_api_key or not broker_api_secret:
        error_msg = "Missing BROKER_API_KEY or BROKER_API_SECRET in environment variables"
        logger.error(error_msg)
        response_data["message"] = error_msg
        return None, response_data

    if not request_token:
        error_msg = "No request token provided"
        logger.error(error_msg)
        response_data["message"] = error_msg
        return None, response_data

    # FYERS's endpoint for session token exchange
    url = "https://api-t1.fyers.in/api/v3/validate-authcode"

    try:
        # Generate the checksum as a SHA-256 hash of concatenated api_key and api_secret
        checksum_input = f"{broker_api_key}:{broker_api_secret}"
        app_id_hash = hashlib.sha256(checksum_input.encode("utf-8")).hexdigest()

        # Prepare the request payload
        payload = {
            "grant_type": "authorization_code",
            "appIdHash": app_id_hash,
            "code": request_token,
        }

        headers = {"Content-Type": "application/json", "Accept": "application/json"}

        # Get shared HTTP client with connection pooling
        client = get_httpx_client()

        logger.debug(f"Authenticating with FYERS API. Request: {json.dumps(payload, indent=2)}")

        # Make the authentication request
        response = client.post(
            url,
            headers=headers,
            json=payload,
            timeout=30.0,  # Increased timeout for auth requests
        )

        # Process the response
        response.raise_for_status()
        auth_data = response.json()
        logger.debug(f"FYERS auth API response: {json.dumps(auth_data, indent=2)}")

        if auth_data.get("s") == "ok":
            access_token = auth_data.get("access_token")
            if not access_token:
                error_msg = "Authentication succeeded but no access token was returned"
                logger.error(error_msg)
                response_data["message"] = error_msg
                return None, response_data

            # Prepare success response
            response_data.update(
                {
                    "status": "success",
                    "message": "Authentication successful",
                    "data": {
                        "access_token": access_token,
                        "refresh_token": auth_data.get("refresh_token"),
                        "expires_in": auth_data.get("expires_in"),
                    },
                }
            )

            logger.debug("Successfully authenticated with FYERS API")
            return access_token, response_data

        else:
            # Handle API error response
            error_msg = auth_data.get("message", "Authentication failed")
            logger.error(f"FYERS API error: {error_msg}")
            response_data["message"] = f"API error: {error_msg}"
            return None, response_data

    except Exception as e:
        error_msg = f"Authentication failed: {e}"
        logger.exception("Authentication failed due to an unexpected error")
        response_data["message"] = error_msg
        return None, response_data


# ---------------------------------------------------------------------------
# Auto-TOTP authentication (programmatic login without browser redirect)
# ---------------------------------------------------------------------------

FYERS_AUTH_HOST = "https://api-t2.fyers.in/vagator/v2"
FYERS_TOKEN_URL = "https://api-t1.fyers.in/api/v3/token"


def _b64(value: str) -> str:
    """Base64-encode a string (ASCII)."""
    return base64.b64encode(value.encode("ascii")).decode("ascii")


def authenticate_broker_totp(
    fy_id: str,
    pin: str,
    totp_code: str,
) -> tuple[str | None, str | None]:
    """
    Authenticate with Fyers using auto-TOTP (no browser redirect).

    Steps:
      1. send_login_otp_v2  → request_key
      2. verify_otp (TOTP)  → new request_key
      3. verify_pin_v2      → bearer token
      4. Get auth_code via /api/v3/token
      5. Exchange auth_code for access_token via validate-authcode

    Args:
        fy_id: Fyers user/client ID (e.g. "XY12345")
        pin: 4-digit login PIN
        totp_code: 6-digit TOTP code (pre-generated)

    Returns:
        (access_token, error_message)
    """
    broker_api_key = os.getenv("BROKER_API_KEY", "")
    broker_api_secret = os.getenv("BROKER_API_SECRET", "")
    redirect_url = os.getenv("REDIRECT_URL", "")

    if not broker_api_key or not broker_api_secret:
        return None, "Missing BROKER_API_KEY or BROKER_API_SECRET"
    if not redirect_url:
        return None, "Missing REDIRECT_URL — required for Fyers auto-TOTP authentication"

    # Use a DEDICATED httpx client with cookie persistence for the entire auth flow.
    # Fyers -200 (User Apps / static IP) needs cookies from the login steps
    # to be passed to generate-authcode to get the redirect with auth_code.
    import httpx
    with httpx.Client(timeout=30.0, follow_redirects=False) as client:
      try:
        # Log cookies throughout to debug -200 flow
        def _log_cookies(label):
            jar = dict(client.cookies)
            if jar:
                logger.info(f"Fyers cookies after {label}: {list(jar.keys())}")

        # Step 1: Send login OTP
        res1 = client.post(
            f"{FYERS_AUTH_HOST}/send_login_otp_v2",
            json={"fy_id": _b64(fy_id), "app_id": "2"},
            timeout=30.0,
        )
        res1_data = res1.json()
        logger.debug(f"Fyers send_login_otp response status: {res1_data.get('s')}")
        _log_cookies("send_login_otp")

        if "request_key" not in res1_data:
            return None, f"Fyers login OTP failed: {res1_data.get('message', str(res1_data))}"

        # Step 2: Verify TOTP
        res2 = client.post(
            f"{FYERS_AUTH_HOST}/verify_otp",
            json={"request_key": res1_data["request_key"], "otp": totp_code},
            timeout=30.0,
        )
        res2_data = res2.json()
        logger.debug(f"Fyers verify_otp response status: {res2_data.get('s')}")
        _log_cookies("verify_otp")

        if "request_key" not in res2_data:
            return None, f"Fyers TOTP verification failed: {res2_data.get('message', str(res2_data))}"

        # Step 3: Verify PIN
        res3 = client.post(
            f"{FYERS_AUTH_HOST}/verify_pin_v2",
            json={
                "request_key": res2_data["request_key"],
                "identity_type": "pin",
                "identifier": _b64(pin),
            },
            timeout=30.0,
        )
        res3_data = res3.json()
        logger.debug(f"Fyers verify_pin response status: {res3_data.get('s')}")
        _log_cookies("verify_pin")

        data_block = res3_data.get("data", {})
        bearer_token = data_block.get("access_token") if isinstance(data_block, dict) else None
        if not bearer_token:
            return None, f"Fyers PIN verification failed: {res3_data.get('message', str(res3_data))}"

        # Step 4: Get authorization code
        if "-" in broker_api_key:
            app_prefix = broker_api_key.rsplit("-", 1)[0]
            app_type = broker_api_key.rsplit("-", 1)[1]
        else:
            app_prefix = broker_api_key[:-4] if len(broker_api_key) > 4 else broker_api_key
            app_type = "100"

        logger.info(f"Fyers app_id={app_prefix}, appType={app_type}")
        callback_url = redirect_url

        token_payload = {
            "fyers_id": fy_id,
            "app_id": app_prefix,
            "redirect_uri": callback_url,
            "appType": app_type,
            "code_challenge": "",
            "state": "None",
            "scope": "",
            "nonce": "",
            "response_type": "code",
            "create_cookie": True,
        }

        res4 = client.post(
            FYERS_TOKEN_URL,
            json=token_payload,
            headers={"Authorization": f"Bearer {bearer_token}"},
            timeout=30.0,
        )
        _log_cookies("token_endpoint")
        logger.info(f"Fyers token HTTP status: {res4.status_code}, Location: {res4.headers.get('Location', 'none')}")

        # Check if the token endpoint itself redirected with auth_code
        if res4.status_code in (301, 302, 303, 307, 308):
            location = res4.headers.get("Location", "")
            logger.info(f"Fyers token redirect: {location[:300]}")
            if "auth_code=" in location:
                parsed_loc = urlparse(location)
                qs_loc = parse_qs(parsed_loc.query)
                auth_code = qs_loc.get("auth_code", [None])[0]
                if auth_code:
                    logger.info(f"Fyers: got auth_code from token redirect! (length={len(auth_code)})")
                    access_token, resp_data = authenticate_broker(auth_code)
                    if access_token:
                        logger.info("Fyers: SUCCESS via token endpoint redirect")
                        return access_token, None

        res4_data = res4.json()
        logger.info(f"Fyers token response: status={res4_data.get('s')}, code={res4_data.get('code')}, keys={list(res4_data.keys())}")

        # Legacy flow for -100 apps: extract auth_code from "Url" field
        url_str = res4_data.get("Url")
        if url_str:
            parsed = urlparse(url_str)
            qs = parse_qs(parsed.query)
            auth_code = qs.get("auth_code", [None])[0]
            if auth_code:
                logger.info("Fyers: extracted auth_code from Url field (legacy flow)")
                access_token, resp_data = authenticate_broker(auth_code)
                if access_token:
                    return access_token, None
                else:
                    err_msg = resp_data.get("message", "Token exchange failed") if isinstance(resp_data, dict) else str(resp_data)
                    return None, err_msg

        # For static IP apps (-200): token response returns data.auth JWT
        # With cookie persistence, generate-authcode should now redirect properly
        data_block = res4_data.get("data", {})
        if isinstance(data_block, dict) and data_block.get("auth"):
            auth_jwt = data_block["auth"]
            logger.info(f"Fyers: got data.auth JWT for static IP flow (length={len(auth_jwt)})")

            generate_url = "https://api-t1.fyers.in/api/v3/generate-authcode"
            auth_params = {
                "client_id": broker_api_key,
                "redirect_uri": callback_url,
                "response_type": "code",
                "state": "None",
            }

            # Method 1: GET generate-authcode with cookies from login flow
            try:
                gen_resp = client.get(
                    generate_url,
                    params=auth_params,
                    headers={"Authorization": f"Bearer {auth_jwt}"},
                    timeout=30.0,
                )
                logger.info(f"Fyers GET generate-authcode: status={gen_resp.status_code}")
                _log_cookies("generate_authcode_GET")
                if gen_resp.status_code in (301, 302, 303, 307, 308):
                    location = gen_resp.headers.get("Location", "")
                    logger.info(f"Fyers GET redirect Location: {location[:200]}")
                    if "auth_code=" in location:
                        parsed_loc = urlparse(location)
                        qs_loc = parse_qs(parsed_loc.query)
                        auth_code = qs_loc.get("auth_code", [None])[0]
                        if auth_code:
                            logger.info(f"Fyers: got auth_code from GET redirect!")
                            access_token, resp_data = authenticate_broker(auth_code)
                            if access_token:
                                logger.info("Fyers: SUCCESS via GET generate-authcode redirect")
                                return access_token, None
                else:
                    body_preview = gen_resp.text[:300]
                    logger.info(f"Fyers GET generate-authcode body: {body_preview}")
            except Exception as e:
                logger.warning(f"Fyers GET generate-authcode failed: {e}")

            # Method 2: Try data.auth as access token (client_id:token format)
            try:
                test_resp = client.get(
                    "https://api-t1.fyers.in/api/v3/profile",
                    headers={"Authorization": f"{broker_api_key}:{auth_jwt}"},
                    timeout=10.0,
                )
                test_body = test_resp.json()
                logger.info(f"Fyers profile test: status={test_resp.status_code}, s={test_body.get('s')}, code={test_body.get('code')}")
                if test_body.get("s") == "ok" or test_body.get("code") == 200:
                    logger.info("Fyers: data.auth WORKS as access token!")
                    return auth_jwt, None
            except Exception as te:
                logger.warning(f"Fyers profile test failed: {te}")

            # None worked — return JWT as fallback
            logger.warning("Fyers: data.auth JWT did not work, returning as fallback")
            return auth_jwt, None

        return None, f"Fyers auth code generation failed: {res4_data.get('message', str(res4_data))}"

      except Exception as e:
        logger.exception(f"Fyers auto-TOTP authentication failed: {e}")
        return None, f"Fyers auto-TOTP error: {str(e)}"
