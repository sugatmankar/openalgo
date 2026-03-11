import json
import logging
import os

import httpx

from broker.dhan.api.baseurl import BASE_URL, get_url
from utils.httpx_client import get_httpx_client

logger = logging.getLogger(__name__)

# Dhan Auth API endpoints
AUTH_BASE_URL = "https://auth.dhan.co"


def generate_consent(dhan_client_id):
    """Step 1: Generate consent to initiate login session - requires valid Dhan Client ID"""
    try:
        BROKER_API_KEY = os.getenv("BROKER_API_KEY")
        BROKER_API_SECRET = os.getenv("BROKER_API_SECRET")

        # Extract client_id from API key if format is client_id:::api_key
        if ":::" in BROKER_API_KEY:
            extracted_client_id, BROKER_API_KEY = BROKER_API_KEY.split(":::")
            # Use extracted client_id if dhan_client_id not provided
            if not dhan_client_id:
                dhan_client_id = extracted_client_id

        if not dhan_client_id:
            logger.error("Dhan Client ID is required for generating consent")
            return None, "Dhan Client ID is required"

        client = get_httpx_client()

        headers = {"app_id": BROKER_API_KEY, "app_secret": BROKER_API_SECRET}

        # Build URL with client_id parameter - REQUIRED by Dhan API
        url = f"{AUTH_BASE_URL}/app/generate-consent"

        logger.info(f"Generating consent for Dhan Client ID: {dhan_client_id}")
        logger.info(f"Using API Key: {BROKER_API_KEY[:8] if BROKER_API_KEY else 'None'}...")
        logger.info(
            f"Using API Secret: {BROKER_API_SECRET[:8] if BROKER_API_SECRET else 'None'}..."
        )

        # Make the POST request with the client_id as a query parameter
        # The client_id parameter is REQUIRED for generate-consent
        full_url = f"{url}?client_id={dhan_client_id}"
        response = client.post(full_url, headers=headers)

        logger.info(f"Generate consent response status: {response.status_code}")
        logger.info(f"Generate consent response: {response.text}")

        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "success":
                consent_app_id = data.get("consentAppId")
                logger.info(f"Consent generated successfully: {consent_app_id}")
                return consent_app_id, None
            else:
                error_msg = f"Failed to generate consent: {data}"
                logger.error(error_msg)
                return None, error_msg
        else:
            error_msg = f"Failed to generate consent: HTTP {response.status_code} - {response.text}"
            logger.error(error_msg)
            return None, error_msg

    except Exception as e:
        logger.error(f"Exception in generate_consent: {str(e)}")
        return None, f"An exception occurred: {str(e)}"


def get_login_url(consent_app_id):
    """Step 2: Get browser login URL"""
    if not consent_app_id:
        return None

    return f"{AUTH_BASE_URL}/login/consentApp-login?consentAppId={consent_app_id}"


def consume_consent(token_id):
    """Step 3: Consume consent to get access token"""
    try:
        BROKER_API_KEY = os.getenv("BROKER_API_KEY")
        BROKER_API_SECRET = os.getenv("BROKER_API_SECRET")

        # Extract client_id from API key if format is client_id:::api_key
        if ":::" in BROKER_API_KEY:
            extracted_client_id, BROKER_API_KEY = BROKER_API_KEY.split(":::")

        client = get_httpx_client()

        headers = {
            "app_id": BROKER_API_KEY,
            "app_secret": BROKER_API_SECRET,
            "Content-Type": "application/json",
        }

        url = f"{AUTH_BASE_URL}/app/consumeApp-consent"
        params = {"tokenId": token_id}

        logger.debug(f"Consuming consent with tokenId: {token_id}")
        response = client.post(url, headers=headers, params=params)

        if response.status_code == 200:
            data = response.json()
            access_token = data.get("accessToken")
            if access_token:
                # Return additional data along with the access token
                additional_data = {
                    "dhan_client_id": data.get("dhanClientId"),
                    "dhan_client_name": data.get("dhanClientName"),
                    "dhan_client_ucc": data.get("dhanClientUcc"),
                    "ddpi_status": data.get("givenPowerOfAttorney", False),
                    "token_expiry": data.get("expiryTime"),
                }
                logger.debug(f"Access Token obtained: {access_token}")
                logger.debug(f"Additional Data: {additional_data}")
                return access_token, additional_data
            else:
                return None, "Access token not found in response"
        else:
            return None, f"Failed to consume consent: {response.status_code}"

    except Exception as e:
        logger.error(f"Exception in consume_consent: {str(e)}")
        return None, f"An exception occurred: {str(e)}"


def get_direct_access_token(access_token):
    """Validate a direct access token obtained from Dhan web"""
    try:
        # Validate the token format (should be a JWT)
        if not access_token or len(access_token) < 50:
            return None, "Invalid access token format"

        logger.info("Using direct access token from Dhan web")
        return access_token, None
    except Exception as e:
        logger.error(f"Exception in get_direct_access_token: {str(e)}")
        return None, f"An exception occurred: {str(e)}"


def authenticate_broker(code):
    """Main authentication function - handles direct token or OAuth flow"""
    try:
        # Check if code is actually a direct access token (for manual entry)
        if code and len(code) > 100:  # Access tokens are typically long JWT strings
            logger.info("Detected direct access token input")
            # For direct token, we don't have client_id immediately
            # It will be fetched when needed during order placement
            return get_direct_access_token(code)
        # Otherwise, handle OAuth flow with tokenId
        elif code:
            access_token, additional_data = consume_consent(code)
            if access_token and isinstance(additional_data, dict):
                # Extract the dhanClientId to return as user_id
                dhan_client_id = additional_data.get("dhan_client_id")
                logger.debug(f"Dhan authentication successful, client_id: {dhan_client_id}")
                # Return access_token, user_id (dhanClientId), error_message format
                # This matches the format expected by brlogin.py for brokers with user_id
                return access_token, dhan_client_id, None
            else:
                # additional_data contains error message if failed
                return None, None, additional_data
        else:
            return None, None, "No token ID provided for authentication"

    except Exception as e:
        logger.error(f"Exception in authenticate_broker: {str(e)}")
        return None, None, f"An exception occurred: {str(e)}"


def authenticate_broker_totp(pin, totp_code):
    """
    Authenticate with Dhan using the direct generateAccessToken API (pure HTTP, no browser).

    Dhan provides a direct endpoint for TOTP-enabled accounts:
      POST https://auth.dhan.co/app/generateAccessToken?dhanClientId=...&pin=...&totp=...

    This returns an access token directly without any browser-based consent flow.

    Args:
        pin: 6-digit Dhan login PIN
        totp_code: 6-digit TOTP code (pre-generated by the caller)

    Returns:
        Tuple of (access_token, error_message)
    """
    BROKER_API_KEY = os.getenv("BROKER_API_KEY", "")

    if not BROKER_API_KEY:
        return None, "Missing BROKER_API_KEY"

    # Extract client_id from API key if format is client_id:::api_key
    dhan_client_id = None
    if ":::" in BROKER_API_KEY:
        dhan_client_id, _ = BROKER_API_KEY.split(":::", 1)
    else:
        dhan_client_id = BROKER_API_KEY

    if not dhan_client_id:
        return None, "Dhan Client ID not found in BROKER_API_KEY"

    try:
        client = get_httpx_client()

        url = f"{AUTH_BASE_URL}/app/generateAccessToken"
        params = {
            "dhanClientId": dhan_client_id,
            "pin": pin,
            "totp": totp_code,
        }

        logger.info(f"Dhan auto-TOTP: generating access token for client {dhan_client_id}")
        response = client.post(url, params=params, timeout=30.0)

        logger.debug(f"Dhan generateAccessToken response status: {response.status_code}")
        logger.debug(f"Dhan generateAccessToken response: {response.text}")

        if response.status_code == 200:
            data = response.json()
            access_token = data.get("accessToken")
            if access_token:
                dhan_client_name = data.get("dhanClientName", "")
                logger.info(
                    f"Dhan auto-TOTP authentication successful for {dhan_client_id} "
                    f"({dhan_client_name})"
                )
                return access_token, None
            else:
                error_msg = data.get("errorMessage") or data.get("message") or str(data)
                return None, f"Dhan generateAccessToken failed: {error_msg}"
        else:
            try:
                error_data = response.json()
                error_msg = (
                    error_data.get("errorMessage")
                    or error_data.get("message")
                    or response.text
                )
            except Exception:
                error_msg = response.text
            return None, f"Dhan generateAccessToken HTTP {response.status_code}: {error_msg}"

    except Exception as e:
        logger.exception(f"Dhan auto-TOTP authentication failed: {e}")
        return None, f"Dhan auto-TOTP error: {str(e)}"
