import hashlib
import json
import os
from urllib.parse import parse_qs, urlparse

import requests

from utils.httpx_client import get_httpx_client
from utils.logging import get_logger

logger = get_logger(__name__)

KITE_LOGIN_URL = "https://kite.zerodha.com/api/login"
KITE_TWOFA_URL = "https://kite.zerodha.com/api/twofa"
KITE_CONNECT_LOGIN_URL = "https://kite.trade/connect/login"


def authenticate_broker(request_token):
    try:
        # Fetching the necessary credentials from environment variables
        BROKER_API_KEY = os.getenv("BROKER_API_KEY")
        BROKER_API_SECRET = os.getenv("BROKER_API_SECRET")

        # Zerodha's endpoint for session token exchange
        url = "https://api.kite.trade/session/token"

        # Generating the checksum as a SHA-256 hash of concatenated api_key, request_token, and api_secret
        checksum_input = f"{BROKER_API_KEY}{request_token}{BROKER_API_SECRET}"
        checksum = hashlib.sha256(checksum_input.encode()).hexdigest()

        # The payload for the POST request
        data = {"api_key": BROKER_API_KEY, "request_token": request_token, "checksum": checksum}

        # Get the shared httpx client with connection pooling
        client = get_httpx_client()

        # Setting the headers as specified by Zerodha's documentation
        headers = {"X-Kite-Version": "3"}

        try:
            # Performing the POST request using the shared client
            response = client.post(
                url,
                headers=headers,
                data=data,
            )
            response.raise_for_status()  # Raises an exception for 4XX/5XX responses

            response_data = response.json()
            if "data" in response_data and "access_token" in response_data["data"]:
                # Access token found in response data
                return response_data["data"]["access_token"], None
            else:
                # Access token not present in the response
                return (
                    None,
                    "Authentication succeeded but no access token was returned. Please check the response.",
                )

        except Exception as e:
            # Handle HTTP errors and timeouts
            error_message = str(e)
            try:
                if hasattr(e, "response") and e.response is not None:
                    error_detail = e.response.json()
                    error_message = error_detail.get("message", str(e))
            except:
                pass

            return None, f"API error: {error_message}"
    except Exception as e:
        # Exception handling
        return None, f"An exception occurred: {str(e)}"


def authenticate_broker_totp(user_id, password, totp_code):
    """
    Authenticate with Zerodha using programmatic TOTP flow (no browser redirect).
    
    Steps:
    1. Visit Kite login page (set session cookies to avoid CAPTCHA)
    2. POST /api/login with user_id + password → request_id
    3. POST /api/twofa with user_id + request_id + totp_code → session cookie
    4. Follow Kite Connect OAuth redirect to extract request_token
    5. Exchange request_token for access_token via existing authenticate_broker()
    
    Args:
        user_id: Zerodha client ID
        password: Zerodha login password
        totp_code: Generated TOTP code
    
    Returns:
        Tuple of (access_token, error_message)
    """
    try:
        BROKER_API_KEY = os.getenv("BROKER_API_KEY", "")
        BROKER_API_SECRET = os.getenv("BROKER_API_SECRET", "")

        if not BROKER_API_KEY or not BROKER_API_SECRET:
            return None, "BROKER_API_KEY or BROKER_API_SECRET not configured"

        browser_headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "en-US,en;q=0.9",
            "X-Kite-Version": "3",
        }

        session = requests.Session()
        session.headers.update(browser_headers)

        # Step 1: Visit login page to set cookies (avoids CAPTCHA)
        login_page_url = f"https://kite.zerodha.com/connect/login?v=3&api_key={BROKER_API_KEY}"
        session.get(login_page_url, timeout=15)
        logger.debug("Zerodha login page visited, cookies set")

        # Step 2: Login with user_id + password
        login_resp = session.post(
            KITE_LOGIN_URL,
            data={"user_id": user_id, "password": password},
            timeout=15,
        )
        login_data = login_resp.json()

        if login_data.get("status") != "success":
            # Check for CAPTCHA
            if (login_data.get("data") or {}).get("captcha"):
                return None, f"CAPTCHA required for {user_id}. Please login manually first to clear the lockout."
            error_msg = login_data.get("message", "Login failed")
            return None, f"Zerodha login failed: {error_msg}"

        request_id = login_data["data"]["request_id"]
        logger.debug(f"Zerodha login successful, request_id obtained")

        # Step 3: TOTP 2FA
        twofa_resp = session.post(
            KITE_TWOFA_URL,
            data={
                "user_id": user_id,
                "request_id": request_id,
                "twofa_value": totp_code,
            },
            timeout=15,
        )
        twofa_data = twofa_resp.json()

        if twofa_data.get("status") != "success":
            error_msg = twofa_data.get("message", "TOTP 2FA failed")
            return None, f"Zerodha 2FA failed: {error_msg}"
        logger.debug("Zerodha 2FA successful")

        # Step 4: Follow Kite Connect OAuth redirect to get request_token
        request_token = None
        connect_url = f"{KITE_CONNECT_LOGIN_URL}?api_key={BROKER_API_KEY}"

        r = session.get(connect_url, allow_redirects=False, timeout=15)

        for _hop in range(10):
            location = r.headers.get("Location", "")
            if location:
                loc_params = parse_qs(urlparse(location).query)
                if "request_token" in loc_params:
                    request_token = loc_params["request_token"][0]
                    break

            if r.status_code in (301, 302, 303, 307, 308) and location:
                if location.startswith("/"):
                    location = f"https://kite.zerodha.com{location}"

                if "/connect/authorize" in location:
                    try:
                        r = session.post(
                            location,
                            data={"api_key": BROKER_API_KEY},
                            allow_redirects=False,
                            timeout=15,
                        )
                    except requests.exceptions.ConnectionError as e:
                        # The redirect URL might be unreachable (e.g., localhost)
                        # Extract request_token from the failed request URL
                        if e.request and e.request.url:
                            loc_params = parse_qs(urlparse(str(e.request.url)).query)
                            if "request_token" in loc_params:
                                request_token = loc_params["request_token"][0]
                                break
                        raise
                else:
                    try:
                        r = session.get(location, allow_redirects=False, timeout=15)
                    except requests.exceptions.ConnectionError as e:
                        if e.request and e.request.url:
                            loc_params = parse_qs(urlparse(str(e.request.url)).query)
                            if "request_token" in loc_params:
                                request_token = loc_params["request_token"][0]
                                break
                        raise
            else:
                break

        if not request_token:
            return None, "Could not obtain request_token from Zerodha OAuth redirect"

        logger.debug("Zerodha request_token obtained, exchanging for access_token")

        # Step 5: Exchange request_token for access_token using existing function
        access_token, error = authenticate_broker(request_token)
        if access_token:
            logger.info(f"Zerodha TOTP authentication successful for {user_id}")
            return access_token, None
        else:
            return None, error or "Zerodha token exchange failed"

    except Exception as e:
        logger.exception(f"Zerodha TOTP auth exception: {e}")
        return None, f"Zerodha TOTP auth error: {str(e)}"
