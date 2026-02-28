# blueprints/broker_accounts.py

"""
Broker Accounts Management Blueprint.
Provides CRUD API for managing multiple broker accounts per user.
"""

import os
import re
import time

from flask import Blueprint, jsonify, request, session

from utils.logging import get_logger
from utils.session import check_session_validity

logger = get_logger(__name__)

broker_accounts_bp = Blueprint("broker_accounts_bp", __name__, url_prefix="/api/broker-accounts")


def _get_valid_brokers():
    """Return set of valid broker names from VALID_BROKERS env var."""
    valid = os.getenv("VALID_BROKERS", "")
    return {b.strip().lower() for b in valid.split(",") if b.strip()}


@broker_accounts_bp.route("", methods=["GET"])
@check_session_validity
def list_accounts():
    """List all broker accounts for the logged-in user.
    
    Validates connection status against actual auth tokens in the database.
    Accounts that claim to be 'connected' but have no valid auth token
    are downgraded to 'disconnected'.
    """
    if "user" not in session:
        return jsonify({"status": "error", "message": "Not authenticated"}), 401

    try:
        from database.auth_db import get_auth_token
        from database.broker_account_db import list_broker_accounts, update_connection_status

        broker_filter = request.args.get("broker")
        accounts = list_broker_accounts(session["user"], broker=broker_filter)

        active_account_id = session.get("active_account_id")

        # Validate connection status for each account
        for account in accounts:
            if account.get("connection_status") == "connected":
                # Verify the auth token actually exists for this account
                auth_key = f"{session['user']}__acct_{account['id']}"
                auth_token = get_auth_token(auth_key)
                if not auth_token:
                    # Token has expired or been cleared - mark as disconnected
                    account["connection_status"] = "disconnected"
                    account["is_authenticated"] = False
                    update_connection_status(
                        account["id"], session["user"], "disconnected"
                    )

            # Mark which account is currently active in session
            account["is_session_active"] = (account["id"] == active_account_id)

        return jsonify({"status": "success", "data": accounts})
    except Exception as e:
        logger.exception(f"Error listing broker accounts: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


@broker_accounts_bp.route("", methods=["POST"])
@check_session_validity
def create_account():
    """Create a new broker account."""
    if "user" not in session:
        return jsonify({"status": "error", "message": "Not authenticated"}), 401

    try:
        data = request.get_json() if request.is_json else {}
        account_name = (data.get("account_name") or "").strip()
        broker = (data.get("broker") or "").strip().lower()
        api_key = (data.get("broker_api_key") or "").strip()
        api_secret = (data.get("broker_api_secret") or "").strip()
        redirect_url = (data.get("redirect_url") or "").strip()
        api_key_market = (data.get("broker_api_key_market") or "").strip()
        api_secret_market = (data.get("broker_api_secret_market") or "").strip()
        # New TOTP / auto-auth fields
        user_id = (data.get("user_id") or "").strip()
        password = (data.get("password") or "").strip()
        totp_key = (data.get("totp_key") or "").strip()
        mobile_number = (data.get("mobile_number") or "").strip()
        date_of_birth = (data.get("date_of_birth") or "").strip()
        year_of_birth = (data.get("year_of_birth") or "").strip()

        # Validation
        if not account_name:
            return jsonify({"status": "error", "message": "Account name is required"}), 400
        if len(account_name) > 100:
            return jsonify(
                {"status": "error", "message": "Account name too long (max 100 chars)"}
            ), 400
        if not broker:
            return jsonify({"status": "error", "message": "Broker is required"}), 400
        if broker not in _get_valid_brokers():
            return jsonify(
                {"status": "error", "message": f"Broker '{broker}' is not valid"}
            ), 400
        if not api_key:
            return jsonify({"status": "error", "message": "Broker API key is required"}), 400
        if not api_secret:
            return jsonify({"status": "error", "message": "Broker API secret is required"}), 400

        # Validate redirect URL format if provided
        if redirect_url and not re.match(r"^https?://.+/[^/]+/callback$", redirect_url):
            return jsonify(
                {
                    "status": "error",
                    "message": "Redirect URL must end with /<broker>/callback",
                }
            ), 400

        from database.broker_account_db import add_broker_account

        account_id, error = add_broker_account(
            user=session["user"],
            account_name=account_name,
            broker=broker,
            api_key=api_key,
            api_secret=api_secret,
            redirect_url=redirect_url or None,
            api_key_market=api_key_market or None,
            api_secret_market=api_secret_market or None,
            user_id=user_id or None,
            password=password or None,
            totp_key=totp_key or None,
            mobile_number=mobile_number or None,
            date_of_birth=date_of_birth or None,
            year_of_birth=year_of_birth or None,
        )

        if error:
            return jsonify({"status": "error", "message": error}), 400

        logger.info(
            f"Broker account '{account_name}' ({broker}) created by {session['user']}"
        )
        return jsonify(
            {
                "status": "success",
                "message": f"Broker account '{account_name}' created",
                "data": {"id": account_id},
            }
        ), 201

    except Exception as e:
        logger.exception(f"Error creating broker account: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


@broker_accounts_bp.route("/<int:account_id>", methods=["GET"])
@check_session_validity
def get_account(account_id):
    """Get a single broker account (credentials masked)."""
    if "user" not in session:
        return jsonify({"status": "error", "message": "Not authenticated"}), 401

    try:
        from database.broker_account_db import list_broker_accounts

        # Use list (masked) for safety – full credentials only when authenticating
        accounts = list_broker_accounts(session["user"])
        account = next((a for a in accounts if a["id"] == account_id), None)
        if not account:
            return jsonify({"status": "error", "message": "Account not found"}), 404
        return jsonify({"status": "success", "data": account})
    except Exception as e:
        logger.exception(f"Error getting broker account: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


@broker_accounts_bp.route("/<int:account_id>", methods=["PUT"])
@check_session_validity
def update_account(account_id):
    """Update a broker account."""
    if "user" not in session:
        return jsonify({"status": "error", "message": "Not authenticated"}), 401

    try:
        data = request.get_json() if request.is_json else {}

        kwargs = {}
        if "account_name" in data:
            name = data["account_name"].strip()
            if not name:
                return jsonify(
                    {"status": "error", "message": "Account name cannot be empty"}
                ), 400
            kwargs["account_name"] = name
        if "broker" in data:
            broker = data["broker"].strip().lower()
            if broker not in _get_valid_brokers():
                return jsonify(
                    {"status": "error", "message": f"Broker '{broker}' is not valid"}
                ), 400
            kwargs["broker"] = broker
        if "broker_api_key" in data:
            kwargs["api_key"] = data["broker_api_key"].strip()
        if "broker_api_secret" in data:
            kwargs["api_secret"] = data["broker_api_secret"].strip()
        if "redirect_url" in data:
            kwargs["redirect_url"] = data["redirect_url"].strip()
        if "broker_api_key_market" in data:
            kwargs["api_key_market"] = data["broker_api_key_market"].strip()
        if "broker_api_secret_market" in data:
            kwargs["api_secret_market"] = data["broker_api_secret_market"].strip()
        if "user_id" in data:
            kwargs["user_id"] = data["user_id"].strip()
        if "password" in data:
            kwargs["password"] = data["password"].strip()
        if "totp_key" in data:
            kwargs["totp_key"] = data["totp_key"].strip()
        if "mobile_number" in data:
            kwargs["mobile_number"] = data["mobile_number"].strip()
        if "date_of_birth" in data:
            kwargs["date_of_birth"] = data["date_of_birth"].strip()
        if "year_of_birth" in data:
            kwargs["year_of_birth"] = data["year_of_birth"].strip()

        if not kwargs:
            return jsonify({"status": "error", "message": "No fields to update"}), 400

        from database.broker_account_db import update_broker_account

        success, error = update_broker_account(account_id, session["user"], **kwargs)
        if not success:
            return jsonify({"status": "error", "message": error}), 400

        return jsonify({"status": "success", "message": "Account updated"})

    except Exception as e:
        logger.exception(f"Error updating broker account: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


@broker_accounts_bp.route("/<int:account_id>", methods=["DELETE"])
@check_session_validity
def delete_account(account_id):
    """Delete a broker account and its associated auth data."""
    if "user" not in session:
        return jsonify({"status": "error", "message": "Not authenticated"}), 401

    try:
        from database.broker_account_db import delete_broker_account

        success, error = delete_broker_account(account_id, session["user"])
        if not success:
            return jsonify({"status": "error", "message": error}), 400

        # If deleted account was the active one, clear session
        if session.get("active_account_id") == account_id:
            session.pop("active_account_id", None)
            session.pop("logged_in", None)
            session.pop("broker", None)

        return jsonify({"status": "success", "message": "Account deleted"})

    except Exception as e:
        logger.exception(f"Error deleting broker account: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


@broker_accounts_bp.route("/<int:account_id>/authenticate", methods=["POST"])
@check_session_validity
def authenticate_account(account_id):
    """
    Initiate broker authentication for a specific account.
    This temporarily overrides BROKER_API_KEY / BROKER_API_SECRET env vars
    with the account's stored credentials before running the auth function.

    For TOTP brokers with a stored totp_key: auto-generates OTP and authenticates
    directly (no redirect to TOTP page needed).
    For OAuth brokers: returns the redirect URL to start the flow.
    For TOTP brokers without stored totp_key: returns info to redirect to TOTP page.
    """
    if "user" not in session:
        return jsonify({"status": "error", "message": "Not authenticated"}), 401

    try:
        from database.broker_account_db import get_broker_account, update_connection_status

        account = get_broker_account(account_id, session["user"])
        if not account:
            return jsonify({"status": "error", "message": "Account not found"}), 404

        broker = account["broker"]

        # Store account context in session for the auth callback
        session["pending_account_id"] = account_id
        session["pending_account_broker"] = broker

        # Temporarily set env vars for this account's credentials
        _set_account_env(account)

        # For OAuth-only brokers: return the auth URL so the frontend can redirect
        # Note: flattrade, upstox, zerodha support both OAuth and TOTP.
        # They fall through to auto-TOTP below if credentials are available.
        oauth_only_brokers = {
            "dhan",
            "compositedge", "paytm", "pocketful",
        }

        if broker in oauth_only_brokers:
            redirect_url = account.get("redirect_url") or ""
            api_key = account["broker_api_key"]
            auth_url = _get_oauth_url(broker, api_key, redirect_url)
            return jsonify({
                "status": "success",
                "auth_type": "oauth",
                "auth_url": auth_url,
                "message": "Redirect to broker for authentication",
            })

        # TOTP broker — check if we can auto-authenticate
        totp_key = account.get("totp_key", "")
        can_auto_auth = _broker_has_auto_auth_support(broker, account)

        # For brokers that support both OAuth and TOTP: if auto-auth fields
        # are present, use TOTP; otherwise fall back to OAuth
        if not can_auto_auth and broker in ("zerodha", "upstox", "flattrade"):
            redirect_url = account.get("redirect_url") or ""
            api_key = account["broker_api_key"]
            auth_url = _get_oauth_url(broker, api_key, redirect_url)
            return jsonify({
                "status": "success",
                "auth_type": "oauth",
                "auth_url": auth_url,
                "message": "Redirect to broker for authentication",
            })

        logger.info(
            f"Auto-auth check for {broker} account {account_id}: "
            f"totp_key={'YES' if totp_key else 'NO'}, "
            f"user_id={'YES' if account.get('user_id') else 'NO'}, "
            f"password={'YES' if account.get('password') else 'NO'}, "
            f"can_auto_auth={can_auto_auth}"
        )

        if can_auto_auth:
            # Auto-authenticate: generate OTP and call broker auth directly
            result = _auto_authenticate_totp(account_id, session["user"], broker, account)
            return jsonify(result), 200 if result.get("status") == "success" else 401
        else:
            # TOTP broker – need credentials from the TOTP page
            return jsonify({
                "status": "success",
                "auth_type": "totp",
                "broker": broker,
                "account_id": account_id,
                "message": f"Submit TOTP credentials via /broker/{broker}/totp",
            })

    except Exception as e:
        logger.exception(f"Error initiating broker auth: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


@broker_accounts_bp.route("/<int:account_id>/set-active", methods=["POST"])
@check_session_validity
def set_active_account(account_id):
    """Set a broker account as the currently active one in the session.

    Flow:
    1. If the broker supports auto-auth (TOTP), always re-authenticate to
       get a fresh token — saved tokens may be expired.
    2. Otherwise fall back to the previously saved auth token.
    3. Only fail if neither approach works.
    """
    if "user" not in session:
        return jsonify({"status": "error", "message": "Not authenticated"}), 401

    try:
        from database.broker_account_db import get_broker_account

        account = get_broker_account(account_id, session["user"])
        if not account:
            return jsonify({"status": "error", "message": "Account not found"}), 404

        if not account["is_authenticated"]:
            return jsonify(
                {"status": "error", "message": "Account is not authenticated. Please authenticate first."}
            ), 400

        broker = account["broker"]
        user = session["user"]
        auth_key = f"{user}__acct_{account_id}"

        from database.auth_db import get_auth_token, get_feed_token

        auth_token = None
        feed_token = None
        reauthed = False

        # If auto-auth is supported, always get a fresh token
        can_auto = _broker_has_auto_auth_support(broker, account)
        if can_auto:
            logger.info(
                f"Auto-reauthenticating account {account_id} ({broker}) on activation..."
            )
            result = _auto_authenticate_totp(account_id, user, broker, account)
            if result.get("status") == "success":
                auth_token = get_auth_token(auth_key)
                feed_token = get_feed_token(auth_key)
                reauthed = True
                logger.info(f"Auto-reauth successful for account {account_id} ({broker})")
            else:
                logger.warning(
                    f"Auto-reauth failed for account {account_id} ({broker}): "
                    f"{result.get('message')}. Falling back to saved token."
                )

        # Fall back to saved token if auto-auth wasn't attempted or failed
        if not auth_token:
            auth_token = get_auth_token(auth_key)
            feed_token = get_feed_token(auth_key) if auth_token else None

        if not auth_token:
            return jsonify(
                {"status": "error", "message": "No valid auth token and auto-reauth not available. Please re-authenticate."}
            ), 400

        # Set session context
        session["active_account_id"] = account_id
        session["broker"] = broker
        session["AUTH_TOKEN"] = auth_token
        session["logged_in"] = True

        if feed_token:
            session["FEED_TOKEN"] = feed_token

        # Set account credentials in env for broker operations
        _set_account_env(account)

        msg = f"Switched to account '{account['account_name']}'"
        if reauthed:
            msg += " (re-authenticated)"

        logger.info(
            f"User {user} activated broker account '{account['account_name']}' ({broker})"
            + (" [auto-reauth]" if reauthed else "")
        )

        return jsonify({
            "status": "success",
            "message": msg,
            "data": {
                "account_id": account_id,
                "broker": broker,
                "account_name": account["account_name"],
            },
        })

    except Exception as e:
        logger.exception(f"Error setting active account: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


@broker_accounts_bp.route("/active", methods=["GET"])
@check_session_validity
def get_active_account():
    """Get the currently active broker account."""
    if "user" not in session:
        return jsonify({"status": "error", "message": "Not authenticated"}), 401

    account_id = session.get("active_account_id")
    if not account_id:
        return jsonify({"status": "success", "data": None})

    try:
        from database.broker_account_db import list_broker_accounts

        accounts = list_broker_accounts(session["user"])
        account = next((a for a in accounts if a["id"] == account_id), None)
        return jsonify({"status": "success", "data": account})
    except Exception as e:
        logger.exception(f"Error getting active account: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


@broker_accounts_bp.route("/brokers", methods=["GET"])
@check_session_validity
def get_available_brokers():
    """Return the list of valid brokers with display names."""
    # All supported brokers with display names
    all_brokers = [
        {"id": "fivepaisa", "name": "5 Paisa", "auth_type": "totp"},
        {"id": "fivepaisaxts", "name": "5 Paisa (XTS)", "auth_type": "totp"},
        {"id": "aliceblue", "name": "Alice Blue", "auth_type": "totp"},
        {"id": "angel", "name": "Angel One", "auth_type": "totp"},
        {"id": "compositedge", "name": "CompositEdge", "auth_type": "oauth"},
        {"id": "dhan", "name": "Dhan", "auth_type": "oauth"},
        {"id": "dhan_sandbox", "name": "Dhan (Sandbox)", "auth_type": "totp"},
        {"id": "definedge", "name": "Definedge", "auth_type": "totp"},
        {"id": "firstock", "name": "Firstock", "auth_type": "totp"},
        {"id": "flattrade", "name": "Flattrade", "auth_type": "totp"},
        {"id": "fyers", "name": "Fyers", "auth_type": "totp"},
        {"id": "groww", "name": "Groww", "auth_type": "totp"},
        {"id": "ibulls", "name": "Ibulls", "auth_type": "totp"},
        {"id": "iifl", "name": "IIFL", "auth_type": "totp"},
        {"id": "indmoney", "name": "IndMoney", "auth_type": "totp"},
        {"id": "jainamxts", "name": "JainamXts", "auth_type": "totp"},
        {"id": "kotak", "name": "Kotak Securities", "auth_type": "totp"},
        {"id": "motilal", "name": "Motilal Oswal", "auth_type": "totp"},
        {"id": "mstock", "name": "mStock by Mirae Asset", "auth_type": "totp"},
        {"id": "nubra", "name": "Nubra", "auth_type": "totp"},
        {"id": "paytm", "name": "Paytm Money", "auth_type": "oauth"},
        {"id": "pocketful", "name": "Pocketful", "auth_type": "oauth"},
        {"id": "samco", "name": "Samco", "auth_type": "totp"},
        {"id": "shoonya", "name": "Shoonya", "auth_type": "totp"},
        {"id": "tradejini", "name": "Tradejini", "auth_type": "totp"},
        {"id": "upstox", "name": "Upstox", "auth_type": "totp"},
        {"id": "wisdom", "name": "Wisdom Capital", "auth_type": "totp"},
        {"id": "zebu", "name": "Zebu", "auth_type": "totp"},
        {"id": "zerodha", "name": "Zerodha", "auth_type": "totp"},
    ]

    valid = _get_valid_brokers()
    filtered = [b for b in all_brokers if b["id"] in valid]
    return jsonify({"status": "success", "data": filtered})


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _set_account_env(account):
    """
    Override environment variables with the account's broker credentials.
    This makes existing broker modules (which read os.getenv) use per-account creds.
    Safe in single-worker mode (required for WebSocket anyway).
    """
    api_key = account.get("broker_api_key") or ""
    broker = account.get("broker", "")

    # FlatTrade requires BROKER_API_KEY in 'userid:::apikey' format
    # If the stored key doesn't contain ':::', prepend the user_id
    if broker == "flattrade" and ":::" not in api_key and account.get("user_id"):
        api_key = f"{account['user_id']}:::{api_key}"

    os.environ["BROKER_API_KEY"] = api_key
    os.environ["BROKER_API_SECRET"] = account.get("broker_api_secret") or ""
    if account.get("broker_api_key_market"):
        os.environ["BROKER_API_KEY_MARKET"] = account["broker_api_key_market"]
    if account.get("broker_api_secret_market"):
        os.environ["BROKER_API_SECRET_MARKET"] = account["broker_api_secret_market"]
    if account.get("redirect_url"):
        os.environ["REDIRECT_URL"] = account["redirect_url"]


# ---------------------------------------------------------------------------
# Auto-TOTP authentication helpers
# ---------------------------------------------------------------------------

# Broker field requirements for auto-auth
BROKER_AUTO_AUTH_FIELDS = {
    "angel": ["user_id", "password", "totp_key"],         # clientcode, pin, totp
    "fivepaisa": ["user_id", "password", "totp_key"],     # clientcode, pin, totp
    "firstock": ["user_id", "password", "totp_key"],      # userid, password, totp
    "flattrade": ["user_id", "password", "totp_key"],     # userid, password, totp
    "fyers": ["user_id", "password", "totp_key"],         # fy_id, pin, totp
    "shoonya": ["user_id", "password", "totp_key"],       # userid, password, totp
    "upstox": ["mobile_number", "password", "totp_key", "user_id"],  # mobile, password, totp, pin
    "zebu": ["user_id", "password", "totp_key"],          # userid, password, totp
    "zerodha": ["user_id", "password", "totp_key"],       # user_id, password, totp
    "kotak": ["mobile_number", "totp_key", "password", "user_id"],  # mobile, totp, mpin, ucc
    "motilal": ["user_id", "password", "totp_key", "date_of_birth"],  # userid, password, totp, dob
    "mstock": ["password", "totp_key"],                   # password, totp
    "nubra": ["totp_key"],                                # totp only
    "tradejini": ["password", "totp_key"],                # password, twofa(totp)
    "samco": ["year_of_birth"],                           # yob (no totp_key needed)
    # Auto-auth brokers (env-only, no user fields needed from form):
    "fivepaisaxts": [],
    "dhan_sandbox": [],
    "groww": [],
    "ibulls": [],
    "indmoney": [],
    "iifl": [],
    "jainamxts": [],
    "wisdom": [],
}


def _broker_has_auto_auth_support(broker, account):
    """Check if we have all required fields to auto-authenticate this broker."""
    required = BROKER_AUTO_AUTH_FIELDS.get(broker)
    if required is None:
        return False  # broker not in auto-auth list (e.g. definedge, aliceblue)
    for field in required:
        if not account.get(field):
            return False
    return True


def _generate_totp(totp_key):
    """
    Generate a TOTP code, with boundary detection to avoid expiring codes.
    If we're near the end of a 30-second window, sleep a few seconds.
    """
    import pyotp

    # Clean the key (remove spaces, uppercase)
    clean_key = totp_key.strip().replace(" ", "")

    # Boundary detection: if within last 3 seconds of the 30-sec window, wait
    current_second = int(time.time()) % 30
    if current_second >= 27:
        wait_time = 31 - current_second
        logger.debug(f"TOTP boundary detected (second={current_second}), waiting {wait_time}s")
        time.sleep(wait_time)

    totp = pyotp.TOTP(clean_key)
    return totp.now()


def _auto_authenticate_totp(account_id, user, broker, account):
    """
    Auto-authenticate a TOTP broker by generating the OTP from stored totp_key
    and calling the broker's auth function directly.
    Returns a dict with status/message.
    """
    from flask import current_app
    from database.broker_account_db import update_connection_status
    from utils.auth_utils import handle_auth_success

    MAX_RETRIES = 2

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            # Ensure env vars are set
            _set_account_env(account)

            # Get the broker auth function
            broker_auth_functions = current_app.broker_auth_functions
            auth_function = broker_auth_functions.get(f"{broker}_auth")
            if not auth_function:
                update_connection_status(account_id, user, "error", "Auth function not found")
                return {"status": "error", "message": f"Auth function not found for broker '{broker}'"}

            # Generate TOTP
            totp_key = account.get("totp_key", "")
            totp_code = _generate_totp(totp_key) if totp_key else None

            # Call broker-specific auth
            auth_token = None
            feed_token = None
            user_id_from_broker = None
            error_message = None

            if broker in ("angel",):
                auth_token, feed_token, error_message = auth_function(
                    account["user_id"], account["password"], totp_code
                )
                user_id_from_broker = account["user_id"]

            elif broker == "fyers":
                from broker.fyers.api.auth_api import authenticate_broker_totp
                auth_token, error_message = authenticate_broker_totp(
                    account["user_id"], account["password"], totp_code
                )

            elif broker == "flattrade":
                from broker.flattrade.api.auth_api import authenticate_broker_totp as flattrade_totp
                auth_token, error_message = flattrade_totp(
                    account["user_id"], account["password"], totp_code
                )
                user_id_from_broker = account["user_id"]
                # FlatTrade API requires BROKER_API_KEY in 'userid:::apikey' format
                # Ensure it's set correctly so API calls and WebSocket use the right uid/actid
                current_api_key = os.getenv("BROKER_API_KEY", "")
                if ":::" not in current_api_key:
                    os.environ["BROKER_API_KEY"] = f"{account['user_id']}:::{current_api_key}"

            elif broker == "zerodha":
                from broker.zerodha.api.auth_api import authenticate_broker_totp as zerodha_totp
                auth_token, error_message = zerodha_totp(
                    account["user_id"], account["password"], totp_code
                )
                user_id_from_broker = account["user_id"]

            elif broker == "upstox":
                from broker.upstox.api.auth_api import authenticate_broker_totp as upstox_totp
                # upstox-totp library handles TOTP generation internally from totp_key
                auth_token, error_message = upstox_totp(
                    account["mobile_number"], account["password"],
                    account.get("totp_key", ""), account["user_id"]
                )
                user_id_from_broker = account["user_id"]

            elif broker in ("fivepaisa",):
                auth_token, error_message = auth_function(
                    account["user_id"], account["password"], totp_code
                )

            elif broker in ("firstock", "shoonya", "zebu"):
                auth_token, error_message = auth_function(
                    account["user_id"], account["password"], totp_code
                )

            elif broker == "kotak":
                from broker.kotak.api.auth_api import authenticate_broker_totp as kotak_totp
                auth_token, error_message = kotak_totp(
                    account["mobile_number"], account["password"], totp_code,
                    consumer_key=os.environ.get("BROKER_API_KEY", ""),
                    ucc=account["user_id"]
                )

            elif broker == "motilal":
                auth_token, feed_token, error_message = auth_function(
                    account["user_id"], account["password"], totp_code, account["date_of_birth"]
                )

            elif broker == "mstock":
                from broker.mstock.api.auth_api import authenticate_with_totp
                auth_token, feed_token, error_message = authenticate_with_totp(
                    account["password"], totp_code
                )

            elif broker == "nubra":
                auth_token, feed_token, error_message = auth_function(totp_code)

            elif broker == "tradejini":
                auth_token, error_message = auth_function(
                    password=account["password"], twofa=totp_code, twofa_type="totp"
                )

            elif broker == "samco":
                auth_token, error_message = auth_function(account["year_of_birth"])

            # Auto-auth brokers (no user fields)
            elif broker in ("fivepaisaxts",):
                auth_token, feed_token, user_id_from_broker, error_message = auth_function(broker)

            elif broker in ("ibulls", "iifl", "jainamxts", "wisdom"):
                auth_token, feed_token, user_id_from_broker, error_message = auth_function(broker)

            elif broker in ("dhan_sandbox", "groww", "indmoney"):
                auth_token, error_message = auth_function(broker)

            else:
                update_connection_status(account_id, user, "error", f"Auto-auth not supported for {broker}")
                return {"status": "error", "message": f"Auto-auth not implemented for broker '{broker}'"}

            if auth_token:
                # Compose token for special brokers
                if broker == "zerodha":
                    auth_token = f"{os.getenv('BROKER_API_KEY', '')}:{auth_token}"

                # Store auth token
                from database.auth_db import upsert_auth

                auth_key = f"{user}__acct_{account_id}"
                upsert_auth(auth_key, auth_token, broker, feed_token=feed_token, user_id=user_id_from_broker)

                # Also store under legacy key for active account compatibility
                upsert_auth(user, auth_token, broker, feed_token=feed_token, user_id=user_id_from_broker)

                # Update account status
                update_connection_status(account_id, user, "connected")

                # Update session
                session["broker"] = broker
                session["AUTH_TOKEN"] = auth_token
                if feed_token:
                    session["FEED_TOKEN"] = feed_token

                logger.info(f"Auto-auth successful for account {account_id} ({broker})")

                # Trigger master contract download (same logic as handle_auth_success)
                try:
                    from database.master_contract_status_db import init_broker_status
                    from utils.auth_utils import should_download_master_contract, async_master_contract_download, load_existing_master_contract
                    from threading import Thread

                    init_broker_status(broker)
                    should_download, reason = should_download_master_contract(broker)
                    logger.info(f"Smart download check for {broker}: should_download={should_download}, reason={reason}")

                    if should_download:
                        thread = Thread(target=async_master_contract_download, args=(broker,), daemon=True)
                        thread.start()
                    else:
                        logger.info(f"Skipping download for {broker}: {reason}")
                        thread = Thread(target=load_existing_master_contract, args=(broker,), daemon=True)
                        thread.start()
                except Exception as mc_err:
                    logger.warning(f"Master contract download trigger failed: {mc_err}")

                return {
                    "status": "success",
                    "auth_type": "auto",
                    "message": f"Auto-authenticated with {broker} successfully",
                }
            else:
                if attempt < MAX_RETRIES:
                    logger.warning(f"Auto-auth attempt {attempt} failed for {broker}: {error_message}, retrying...")
                    time.sleep(2)
                    continue
                update_connection_status(account_id, user, "error", error_message)
                return {
                    "status": "error",
                    "auth_type": "auto",
                    "message": error_message or "Authentication failed",
                }

        except Exception as e:
            if attempt < MAX_RETRIES:
                logger.warning(f"Auto-auth attempt {attempt} exception for {broker}: {e}, retrying...")
                time.sleep(2)
                continue
            logger.exception(f"Auto-auth failed for account {account_id} ({broker}): {e}")
            update_connection_status(account_id, user, "error", str(e))
            return {"status": "error", "message": f"Auto-auth error: {str(e)}"}


def _get_oauth_url(broker, api_key, redirect_url):
    """Build the OAuth authorization URL for a given broker."""
    from utils.config import get_host_server

    host = get_host_server()
    callback = redirect_url or f"{host}/{broker}/callback"

    if broker == "zerodha":
        return f"https://kite.zerodha.com/connect/login?v=3&api_key={api_key}"
    elif broker == "fyers":
        return (
            f"https://api-t1.fyers.in/api/v3/generate-authcode"
            f"?client_id={api_key}&redirect_uri={callback}"
            f"&response_type=code&state=openalgo"
        )
    elif broker == "upstox":
        return (
            f"https://api.upstox.com/v2/login/authorization/dialog"
            f"?response_type=code&client_id={api_key}&redirect_uri={callback}"
        )
    elif broker == "dhan":
        # Dhan uses a different flow – redirect to initiate OAuth
        return f"{host}/dhan/initiate-oauth"
    elif broker == "flattrade":
        parts = api_key.split(":::") if ":::" in api_key else [api_key]
        flat_api_key = parts[1] if len(parts) > 1 else parts[0]
        return (
            f"https://auth.flattrade.in/?app_key={flat_api_key}"
        )
    elif broker == "compositedge":
        return (
            f"https://trans.compositedge.com/breezy/redirect?appKey={api_key}"
        )
    elif broker == "paytm":
        return (
            f"https://login.paytmmoney.com/merchant-login?apiKey={api_key}"
            f"&state=openalgo"
        )
    elif broker == "pocketful":
        return (
            f"https://auth.pocketful.in/oauth/authorize"
            f"?client_id={api_key}&redirect_uri={callback}&response_type=code&state=openalgo"
        )
    else:
        return ""
