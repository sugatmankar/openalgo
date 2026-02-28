import json
import os

import httpx

from utils.httpx_client import get_httpx_client
from utils.logging import get_logger

# Initialize logger
logger = get_logger(__name__)


def authenticate_broker(mobile_number, totp, mpin):
    """
    Authenticate with Kotak using TOTP and MPIN flow.
    Legacy interface for brlogin.py (single-account mode).

    In single-account mode:
    - BROKER_API_KEY = consumer_key (access token for Authorization header)
    - BROKER_API_SECRET = consumer_secret (not used for auth)
    - UCC comes from the form or is not needed if consumer_key encodes it

    Args:
        mobile_number: Mobile number with +91 prefix
        totp: 6-digit TOTP from authenticator app
        mpin: 6-digit trading MPIN

    Returns:
        Tuple of (auth_string, error_message)
    """
    from utils.config import get_broker_api_key, get_broker_api_secret

    consumer_key = get_broker_api_key()
    return _authenticate_kotak(mobile_number, totp, mpin, consumer_key=consumer_key)


def authenticate_broker_totp(mobile_number, mpin, totp_code, consumer_key=None, ucc=None):
    """
    Authenticate with Kotak using TOTP and MPIN flow.
    Used by multi-account auto-auth.

    Args:
        mobile_number: Mobile number
        mpin: 6-digit trading MPIN
        totp_code: 6-digit TOTP code (pre-generated)
        consumer_key: Consumer key / access token for Authorization header
        ucc: Unique Client Code (optional, for the login payload)

    Returns:
        Tuple of (auth_string, error_message)
    """
    if not consumer_key:
        from utils.config import get_broker_api_key
        consumer_key = get_broker_api_key()

    return _authenticate_kotak(mobile_number, totp_code, mpin, consumer_key=consumer_key, ucc=ucc)


def _authenticate_kotak(mobile_number, totp, mpin, consumer_key=None, ucc=None):
    """
    Internal Kotak authentication implementation.

    Steps:
    1. Login with TOTP to get View token and sid
    2. Validate with MPIN to get Trading token and sid

    Args:
        mobile_number: Mobile number
        totp: 6-digit TOTP code
        mpin: 6-digit trading MPIN
        consumer_key: Consumer key for Authorization header (from BROKER_API_KEY or account)
        ucc: Unique Client Code (optional)

    Returns:
        Tuple of (auth_string, error_message)
        auth_string format: "trading_token:::trading_sid:::base_url:::consumer_key"
    """
    try:
        logger.info("Starting Kotak TOTP authentication flow")

        if not consumer_key:
            from utils.config import get_broker_api_key
            consumer_key = get_broker_api_key()

        if not consumer_key:
            logger.error("Consumer key (BROKER_API_KEY) is not configured")
            return None, "Consumer key (BROKER_API_KEY) is required"

        logger.debug(f"Consumer key length: {len(consumer_key)}, UCC: {ucc or 'not provided'}")

        # Ensure mobile number has +91 prefix
        # Handle all cases: +919876543210, 919876543210, 9876543210
        mobile_number = mobile_number.strip()
        # Remove any existing +91 or 91 prefix
        mobile_number = mobile_number.replace("+91", "").replace(" ", "")
        if mobile_number.startswith("91") and len(mobile_number) == 12:
            mobile_number = mobile_number[2:]  # Remove leading 91
        # Add +91 prefix
        mobile_number = f"+91{mobile_number}"

        # Get the shared httpx client with connection pooling
        client = get_httpx_client()

        # Step 1: Login with TOTP
        # UCC is required by Kotak's API
        if not ucc:
            logger.error("UCC (Client Code) is required for Kotak authentication")
            return None, "UCC (Client Code) is required for Kotak authentication"

        login_body = {"mobileNumber": mobile_number, "ucc": ucc, "totp": totp}
        payload = json.dumps(login_body)

        headers = {
            "Authorization": consumer_key,
            "neo-fin-key": "neotradeapi",
            "Content-Type": "application/json",
        }

        logger.debug(f"TOTP Login Request - Mobile: {mobile_number[:5]}***, UCC: {ucc or 'not set'}")

        response = client.post(
            "https://mis.kotaksecurities.com/login/1.0/tradeApiLogin",
            headers=headers,
            content=payload,
        )

        logger.debug(f"TOTP Login Response Status: {response.status_code}")
        logger.debug(f"TOTP Login Response: {response.text}")

        data_dict = json.loads(response.text)

        # Check for errors in TOTP login
        if "data" not in data_dict or data_dict.get("data", {}).get("status") != "success":
            error_msg = data_dict.get("errMsg", data_dict.get("message", "TOTP login failed"))
            logger.error(f"TOTP Login Failed - Response: {data_dict}")
            return None, f"TOTP Login Error: {error_msg}"

        # Extract View token and sid
        view_token = data_dict["data"]["token"]
        view_sid = data_dict["data"]["sid"]

        logger.info("TOTP Login successful, proceeding with MPIN validation")

        # Step 2: Validate with MPIN
        payload = json.dumps({"mpin": mpin})

        headers = {
            "Authorization": consumer_key,
            "neo-fin-key": "neotradeapi",
            "sid": view_sid,
            "Auth": view_token,
            "Content-Type": "application/json",
        }

        logger.debug("MPIN Validation Request initiated")

        response = client.post(
            "https://mis.kotaksecurities.com/login/1.0/tradeApiValidate",
            headers=headers,
            content=payload,
        )

        logger.debug(f"MPIN Validation Response Status: {response.status_code}")
        logger.debug(f"MPIN Validation Response: {response.text}")

        data_dict = json.loads(response.text)

        # Check for errors in MPIN validation
        if "data" not in data_dict or data_dict.get("data", {}).get("status") != "success":
            error_msg = data_dict.get("errMsg", data_dict.get("message", "MPIN validation failed"))
            logger.error(f"MPIN Validation Failed - Response: {data_dict}")
            return None, f"MPIN Validation Error: {error_msg}"

        # Extract Trading token, sid, and baseUrl
        trading_token = data_dict["data"]["token"]
        trading_sid = data_dict["data"]["sid"]
        base_url = data_dict["data"].get("baseUrl", "")

        if not base_url:
            logger.warning("baseUrl not found in MPIN validation response, API calls may fail")

        logger.info("Kotak TOTP authentication completed successfully")
        logger.debug(f"Base URL for API calls: {base_url}")

        # Create auth string: trading_token:::trading_sid:::base_url:::consumer_key
        # This format allows extracting all components needed for subsequent API calls
        auth_string = f"{trading_token}:::{trading_sid}:::{base_url}:::{consumer_key}"
        logger.debug(
            f"AUTH TOKEN CREATED: {trading_token[:10]}...:::{trading_sid}:::{base_url}:::{consumer_key[:10]}..."
        )

        return auth_string, None

    except KeyError as e:
        logger.error(f"Missing expected field in API response: {str(e)}")
        return None, f"Missing expected field in API response: {str(e)}"
    except httpx.HTTPError as e:
        logger.error(f"HTTP request failed: {str(e)}")
        return None, f"HTTP request failed: {str(e)}"
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse JSON response: {str(e)}")
        return None, f"Failed to parse JSON response: {str(e)}"
    except Exception as e:
        logger.error(f"Authentication error: {str(e)}")
        return None, f"Authentication error: {str(e)}"
