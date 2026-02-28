import hashlib
import json
import os
from urllib.parse import parse_qs, urlparse

import httpx

from utils.httpx_client import get_httpx_client
from utils.logging import get_logger

logger = get_logger(__name__)

FLATTRADE_AUTH_HOST = "https://authapi.flattrade.in"


def sha256_hash(text):
    """Generate SHA256 hash."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def authenticate_broker(code, password=None, totp_code=None):
    """
    Authenticate with Flattrade using OAuth flow
    """
    try:
        full_api_key = os.getenv("BROKER_API_KEY")
        logger.debug(f"Full API Key: {full_api_key}")  # Debug print

        # Split the API key to get the actual key part
        BROKER_API_KEY = full_api_key.split(":::")[1]
        BROKER_API_SECRET = os.getenv("BROKER_API_SECRET")

        logger.debug(f"Using API Key: {BROKER_API_KEY}")  # Debug print
        logger.debug(f"Request Code: {code}")  # Debug print

        # Create the security hash as per Flattrade docs
        hash_input = f"{BROKER_API_KEY}{code}{BROKER_API_SECRET}"
        security_hash = hashlib.sha256(hash_input.encode()).hexdigest()

        logger.debug(f"Hash Input: {hash_input}")  # Debug print
        logger.debug(f"Security Hash: {security_hash}")  # Debug print

        url = "https://authapi.flattrade.in/trade/apitoken"
        data = {"api_key": BROKER_API_KEY, "request_code": code, "api_secret": security_hash}

        logger.debug(f"Request Data: {data}")  # Debug print

        # Get the shared httpx client
        client = get_httpx_client()

        response = client.post(url, json=data)

        logger.debug(f"Response Status: {response.status_code}")  # Debug print
        logger.debug(f"Response Content: {response.text}")  # Debug print

        if response.status_code == 200:
            response_data = response.json()
            if response_data.get("stat") == "Ok" and "token" in response_data:
                return response_data["token"], None
            else:
                error_msg = response_data.get(
                    "emsg", "Authentication failed without specific error"
                )
                logger.error(f"Auth Error: {error_msg}")  # Debug print
                return None, error_msg
        else:
            try:
                error_detail = response.json()
                error_msg = f"API error: {error_detail.get('emsg', 'Unknown error')}"
            except:
                error_msg = f"API error: Status {response.status_code}, Response: {response.text}"
            logger.error(f"Request Error: {error_msg}")  # Debug print
            return None, error_msg

    except Exception as e:
        logger.debug(f"Exception: {e}")  # Debug print
        return None, f"An exception occurred: {str(e)}"


def authenticate_broker_oauth(code):
    try:
        BROKER_API_KEY = os.getenv("BROKER_API_KEY").split(":::")[1]  # Get only the API key part
        BROKER_API_SECRET = os.getenv("BROKER_API_SECRET")

        # Create the security hash as per Flattrade docs
        # api_secret:SHA-256 hash of (api_key + request_token + api_secret)
        hash_input = f"{BROKER_API_KEY}{code}{BROKER_API_SECRET}"
        security_hash = hashlib.sha256(hash_input.encode()).hexdigest()

        url = "https://authapi.flattrade.in/trade/apitoken"
        data = {"api_key": BROKER_API_KEY, "request_code": code, "api_secret": security_hash}

        # Get the shared httpx client
        client = get_httpx_client()

        response = client.post(url, json=data)

        if response.status_code == 200:
            response_data = response.json()
            if response_data.get("stat") == "Ok" and "token" in response_data:
                return response_data["token"], None
            else:
                return None, response_data.get(
                    "emsg", "Authentication failed without specific error"
                )
        else:
            error_detail = response.json()
            return None, f"API error: {error_detail.get('emsg', 'Unknown error')}"

    except Exception as e:
        return None, f"An exception occurred: {str(e)}"


def authenticate_broker_totp(user_id, password, totp_code):
    """
    Authenticate with Flattrade using programmatic TOTP flow (no browser redirect).
    
    Steps:
    1. Get session ID (SID)
    2. SHA-256 hash the password
    3. POST /ftauth with user_id, hashed password, TOTP → get redirect URL with code
    4. Compute api_secret = SHA-256(api_key + code + secret_key)
    5. POST /trade/apitoken → get access token
    
    Args:
        user_id: Flattrade user ID
        password: Flattrade login password (will be SHA-256 hashed)
        totp_code: Generated TOTP code
    
    Returns:
        Tuple of (access_token, error_message)
    """
    try:
        full_api_key = os.getenv("BROKER_API_KEY", "")
        BROKER_API_KEY = full_api_key.split(":::")[1] if ":::" in full_api_key else full_api_key
        BROKER_API_SECRET = os.getenv("BROKER_API_SECRET", "")

        if not BROKER_API_KEY or not BROKER_API_SECRET:
            return None, "BROKER_API_KEY or BROKER_API_SECRET not configured"

        headers = {
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Referer": "https://auth.flattrade.in/",
        }

        with httpx.Client(timeout=30.0, follow_redirects=True, headers=headers) as client:
            # Step 1: Get session ID
            ses_url = f"{FLATTRADE_AUTH_HOST}/auth/session"
            res = client.post(ses_url)
            sid = res.text.strip()
            if not sid:
                return None, "Failed to get session ID from Flattrade"
            logger.debug(f"Flattrade SID obtained: {sid[:10]}...")

            # Step 2: SHA-256 hash the password
            password_hash = hashlib.sha256(password.encode()).hexdigest()

            # Step 3: Authenticate with TOTP
            auth_url = f"{FLATTRADE_AUTH_HOST}/ftauth"
            payload = {
                "UserName": user_id,
                "Password": password_hash,
                "PAN_DOB": totp_code,
                "App": "",
                "ClientID": "",
                "Key": "",
                "APIKey": BROKER_API_KEY,
                "Sid": sid,
                "Override": "Y",
                "Source": "AUTHPAGE",
            }
            res2 = client.post(auth_url, json=payload)
            res2_json = res2.json()

            if "RedirectURL" not in res2_json or not res2_json["RedirectURL"]:
                error_msg = res2_json.get("emsg", "No RedirectURL in response")
                logger.error(f"Flattrade TOTP auth failed: {error_msg}")
                return None, f"Flattrade auth failed: {error_msg}"

            redirect_url = res2_json["RedirectURL"]
            logger.debug(f"Flattrade redirect URL obtained")

            # Step 4: Extract request code from redirect URL
            parsed = urlparse(redirect_url)
            query_params = parse_qs(parsed.query)
            if "code" not in query_params:
                return None, f"No 'code' found in redirect URL: {redirect_url}"
            req_code = query_params["code"][0]

            # Step 5: Generate API secret and exchange for token
            api_secret_raw = BROKER_API_KEY + req_code + BROKER_API_SECRET
            api_secret = hashlib.sha256(api_secret_raw.encode()).hexdigest()

            token_url = f"{FLATTRADE_AUTH_HOST}/trade/apitoken"
            token_payload = {
                "api_key": BROKER_API_KEY,
                "request_code": req_code,
                "api_secret": api_secret,
            }
            res3 = client.post(token_url, json=token_payload)
            res3_json = res3.json()

            if res3_json.get("stat") == "Ok" and "token" in res3_json:
                logger.info(f"Flattrade TOTP authentication successful for {user_id}")
                return res3_json["token"], None
            else:
                error_msg = res3_json.get("emsg", "Token exchange failed")
                return None, f"Flattrade token exchange failed: {error_msg}"

    except Exception as e:
        logger.exception(f"Flattrade TOTP auth exception: {e}")
        return None, f"Flattrade TOTP auth error: {str(e)}"