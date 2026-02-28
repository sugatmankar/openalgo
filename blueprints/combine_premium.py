"""
Combined Premium Chart Blueprint
Serves combined premium chart data for user-defined option legs.
"""

from flask import Blueprint, jsonify, request, session
from flask_cors import cross_origin

from database.auth_db import get_api_key_for_tradingview, get_auth_token
from services.combine_premium_service import get_combine_premium_data, get_strikes_for_underlying
from services.intervals_service import get_intervals
from utils.logging import get_logger
from utils.session import check_session_validity

logger = get_logger(__name__)

combine_premium_bp = Blueprint("combine_premium_bp", __name__, url_prefix="/")


@combine_premium_bp.route("/combine-premium/api/data", methods=["POST"])
@cross_origin()
@check_session_validity
def combine_premium_data():
    """Get combined premium time series for user-defined option legs."""
    try:
        broker = session.get("broker")
        if not broker:
            return jsonify({"status": "error", "message": "No broker account connected. Please set up and activate a broker account."}), 400

        login_username = session["user"]
        auth_token = get_auth_token(login_username)
        if auth_token is None:
            return jsonify({"status": "error", "message": "Authentication required"}), 401

        api_key = get_api_key_for_tradingview(login_username)
        if not api_key:
            return jsonify({"status": "error", "message": "API key not configured. Please generate an API key in /apikey"}), 401

        data = request.get_json(silent=True) or {}
        underlying = data.get("underlying", "").strip()
        exchange = data.get("exchange", "").strip()
        expiry_date = data.get("expiry_date", "").strip()
        interval = data.get("interval", "1m").strip()
        days = int(data.get("days", 5))
        legs = data.get("legs", [])

        if not underlying or not exchange or not expiry_date:
            return jsonify({"status": "error", "message": "underlying, exchange, and expiry_date are required"}), 400

        if not legs or not isinstance(legs, list):
            return jsonify({"status": "error", "message": "At least one leg is required"}), 400

        # Validate legs
        for i, leg in enumerate(legs):
            if not isinstance(leg, dict):
                return jsonify({"status": "error", "message": f"Leg {i+1} is invalid"}), 400
            if "strike" not in leg or "option_type" not in leg or "action" not in leg:
                return jsonify({"status": "error", "message": f"Leg {i+1} requires strike, option_type, and action"}), 400
            if leg["option_type"].upper() not in ("CE", "PE"):
                return jsonify({"status": "error", "message": f"Leg {i+1} option_type must be CE or PE"}), 400
            if leg["action"].upper() not in ("BUY", "SELL"):
                return jsonify({"status": "error", "message": f"Leg {i+1} action must be BUY or SELL"}), 400

        success, response, status_code = get_combine_premium_data(
            underlying=underlying,
            exchange=exchange,
            expiry_date=expiry_date,
            interval=interval,
            api_key=api_key,
            legs=legs,
            days=days,
        )

        return jsonify(response), status_code

    except Exception as e:
        logger.exception(f"Error in combine premium API: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


@combine_premium_bp.route("/combine-premium/api/strikes", methods=["POST"])
@cross_origin()
@check_session_validity
def combine_premium_strikes():
    """Get available strikes for underlying/expiry to populate the leg builder."""
    try:
        broker = session.get("broker")
        if not broker:
            return jsonify({"status": "error", "message": "No broker account connected"}), 400

        data = request.get_json(silent=True) or {}
        underlying = data.get("underlying", "").strip()
        exchange = data.get("exchange", "").strip()
        expiry_date = data.get("expiry_date", "").strip()

        if not underlying or not exchange or not expiry_date:
            return jsonify({"status": "error", "message": "underlying, exchange, and expiry_date are required"}), 400

        success, response, status_code = get_strikes_for_underlying(
            underlying=underlying,
            exchange=exchange,
            expiry_date=expiry_date,
        )

        return jsonify(response), status_code

    except Exception as e:
        logger.exception(f"Error fetching strikes: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


@combine_premium_bp.route("/combine-premium/api/intervals", methods=["GET"])
@cross_origin()
@check_session_validity
def combine_premium_intervals():
    """Get broker-supported intervals."""
    try:
        login_username = session.get("user")
        if not login_username:
            return jsonify({"status": "error", "message": "Authentication required"}), 401

        api_key = get_api_key_for_tradingview(login_username)
        if not api_key:
            return jsonify({"status": "error", "message": "API key not configured"}), 401

        success, response, status_code = get_intervals(api_key=api_key)
        return jsonify(response), status_code

    except Exception as e:
        logger.exception(f"Error fetching intervals: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500
