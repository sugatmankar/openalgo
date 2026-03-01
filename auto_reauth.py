#!/usr/bin/env python3
"""
auto_reauth.py - Daily Auto-Reauthentication Script for OpenAlgo

Automatically re-authenticates all broker accounts that support TOTP-based
auto-auth. Designed to be run via cron or systemd timer before market opens.

Usage:
    uv run python auto_reauth.py              # Re-auth all accounts
    uv run python auto_reauth.py --dry-run    # Show what would be re-authed
    uv run python auto_reauth.py --account 1  # Re-auth specific account ID

Requires: The instance's .env to be present in the working directory.

This script calls _auto_authenticate_totp() from the broker_accounts blueprint
directly, so it always stays in sync with the main application code. It uses
a Flask test_request_context() to provide the session object that the function
writes to (the session values are discarded — only DB-side token storage matters).
"""

import os
import sys
import time
import argparse
import logging
from datetime import datetime

# Load environment variables first (same as app.py)
from utils.env_check import load_and_check_env_variables

load_and_check_env_variables()

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("auto_reauth")


def get_all_accounts_for_reauth():
    """Query all active broker accounts from the database (all users)."""
    from database.broker_account_db import BrokerAccount, _account_to_dict

    accounts = BrokerAccount.query.filter_by(is_active=True).all()
    return [_account_to_dict(a, decrypt=True) for a in accounts]


def main():
    parser = argparse.ArgumentParser(description="OpenAlgo Daily Auto-Reauthentication")
    parser.add_argument("--dry-run", action="store_true", help="Show accounts without authenticating")
    parser.add_argument("--account", type=int, help="Re-auth specific account ID only")
    args = parser.parse_args()

    logger.info("=" * 60)
    logger.info("OpenAlgo Auto-Reauthentication Starting")
    logger.info(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info("=" * 60)

    # Create a minimal Flask app with broker auth functions loaded
    from flask import Flask
    from utils.plugin_loader import load_broker_auth_functions
    from extensions import socketio

    app = Flask(__name__)
    app.secret_key = os.getenv("APP_KEY", "auto-reauth-key")
    app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL")

    # Initialize SocketIO so master_contract_cache_hook.socketio.emit() doesn't crash
    socketio.init_app(app)

    with app.app_context():
        # Load broker auth functions (same as app.py setup_environment)
        app.broker_auth_functions = load_broker_auth_functions()
        logger.info(f"Loaded auth functions for {len(app.broker_auth_functions)} brokers")

        # Import the actual blueprint functions (stays in sync with main code)
        from blueprints.broker_accounts import (
            _broker_has_auto_auth_support,
            _auto_authenticate_totp,
        )

        # Get all accounts
        accounts = get_all_accounts_for_reauth()
        logger.info(f"Found {len(accounts)} active broker account(s)")

        if not accounts:
            logger.info("No broker accounts found. Nothing to do.")
            return

        success_count = 0
        fail_count = 0
        skip_count = 0

        for account in accounts:
            account_id = account["id"]
            broker = account["broker"]
            account_name = account["account_name"]
            user = account["user"]

            # Filter by account ID if specified
            if args.account and account_id != args.account:
                continue

            logger.info(f"\nAccount {account_id}: {account_name} ({broker}) [user={user}]")

            if not _broker_has_auto_auth_support(broker, account):
                logger.info(f"  SKIP - auto-auth not supported (missing TOTP credentials)")
                skip_count += 1
                continue

            if args.dry_run:
                logger.info(f"  DRY RUN - would auto-authenticate")
                continue

            # Small delay between accounts to avoid rate limiting
            if success_count + fail_count > 0:
                time.sleep(3)

            logger.info(f"  Authenticating...")

            try:
                # Use test_request_context to provide session object
                # _auto_authenticate_totp writes session["broker"], session["AUTH_TOKEN"], etc.
                # These are discarded — only DB-side token storage matters for cron usage.
                with app.test_request_context():
                    result = _auto_authenticate_totp(account_id, user, broker, account)

                if result.get("status") == "success":
                    logger.info(f"  OK — {result.get('message', 'authenticated')}")
                    success_count += 1
                else:
                    msg = result.get("message", "Unknown error")
                    logger.error(f"  FAIL — {msg}")
                    fail_count += 1
            except Exception as e:
                logger.exception(f"  FAIL — exception: {e}")
                fail_count += 1

        logger.info("\n" + "=" * 60)
        logger.info("Auto-Reauthentication Complete")
        logger.info(f"  Success: {success_count}")
        logger.info(f"  Failed:  {fail_count}")
        logger.info(f"  Skipped: {skip_count}")
        logger.info("=" * 60)

        # Exit with error code if any failures
        if fail_count > 0:
            sys.exit(1)


if __name__ == "__main__":
    main()
