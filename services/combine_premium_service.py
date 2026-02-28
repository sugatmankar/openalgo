"""
Combined Premium Chart Service
Computes combined premium time series for N user-defined option legs.

Each leg has a strike, option_type (CE/PE), and action (BUY/SELL).
BUY legs contribute +premium, SELL legs contribute -premium.
The chart displays combined premium alongside the underlying spot price.
"""

from datetime import datetime, timedelta

import pandas as pd
import pytz

from services.history_service import get_history
from services.option_symbol_service import (
    construct_option_symbol,
    get_available_strikes,
    get_option_exchange,
)
from services.quotes_service import get_quotes
from utils.logging import get_logger

logger = get_logger(__name__)

# Index symbols that need NSE_INDEX/BSE_INDEX for quotes
NSE_INDEX_SYMBOLS = {
    "NIFTY", "BANKNIFTY", "FINNIFTY", "MIDCPNIFTY",
    "NIFTYNXT50", "NIFTYIT", "NIFTYPHARMA", "NIFTYBANK",
}
BSE_INDEX_SYMBOLS = {"SENSEX", "BANKEX", "SENSEX50"}


def _get_quote_exchange(base_symbol, underlying_exchange):
    """Determine the exchange to use for fetching underlying quotes."""
    if base_symbol in NSE_INDEX_SYMBOLS:
        return "NSE_INDEX"
    if base_symbol in BSE_INDEX_SYMBOLS:
        return "BSE_INDEX"
    if underlying_exchange.upper() in ("NFO", "BFO"):
        return "NSE" if underlying_exchange.upper() == "NFO" else "BSE"
    return underlying_exchange.upper()


def _convert_timestamp_to_ist(df):
    """Convert timestamp column to IST datetime index."""
    ist = pytz.timezone("Asia/Kolkata")
    try:
        if "timestamp" not in df.columns:
            return None

        try:
            df["datetime"] = pd.to_datetime(df["timestamp"], unit="s", utc=True)
            df["datetime"] = df["datetime"].dt.tz_convert(ist)
        except Exception:
            try:
                df["datetime"] = pd.to_datetime(df["timestamp"], unit="ms", utc=True)
                df["datetime"] = df["datetime"].dt.tz_convert(ist)
            except Exception:
                df["datetime"] = pd.to_datetime(df["timestamp"])
                if df["datetime"].dt.tz is None:
                    df["datetime"] = df["datetime"].dt.tz_localize("UTC").dt.tz_convert(ist)
                else:
                    df["datetime"] = df["datetime"].dt.tz_convert(ist)

        df.set_index("datetime", inplace=True)
        df = df.sort_index()
        return df
    except Exception as e:
        logger.warning(f"Error converting timestamps: {e}")
        return None


def get_combine_premium_data(
    underlying,
    exchange,
    expiry_date,
    interval,
    api_key,
    legs,
    days=5,
):
    """
    Compute combined premium time series for user-defined option legs.

    Args:
        underlying: Underlying symbol (e.g., "NIFTY")
        exchange: Exchange (e.g., "NFO", "BFO")
        expiry_date: Expiry in DDMMMYY format (e.g., "06FEB26")
        interval: Candle interval (e.g., "1m", "5m")
        api_key: OpenAlgo API key
        legs: List of dicts, each with:
            - strike: float (strike price)
            - option_type: "CE" or "PE"
            - action: "BUY" or "SELL"
        days: Number of days of history (default 5)

    Returns:
        Tuple of (success, response_dict, status_code)
    """
    try:
        if not legs or len(legs) < 1:
            return False, {"status": "error", "message": "At least one leg is required"}, 400

        ist = pytz.timezone("Asia/Kolkata")
        today = datetime.now(ist).date()
        weekday = today.weekday()
        if weekday == 5:
            today = today - timedelta(days=1)
        elif weekday == 6:
            today = today - timedelta(days=2)
        end_date_str = today.strftime("%Y-%m-%d")
        start_date_str = (today - timedelta(days=max(1, days) - 1)).strftime("%Y-%m-%d")

        base_symbol = underlying.upper()
        quote_exchange = _get_quote_exchange(base_symbol, exchange)
        options_exchange = get_option_exchange(quote_exchange)

        # Fetch underlying history for spot price
        success_u, resp_u, _ = get_history(
            symbol=base_symbol,
            exchange=quote_exchange,
            interval=interval,
            start_date=start_date_str,
            end_date=end_date_str,
            api_key=api_key,
        )
        if not success_u:
            return (
                False,
                {"status": "error", "message": f"Failed to fetch underlying history: {resp_u.get('message', 'Unknown error')}"},
                400,
            )

        df_underlying = pd.DataFrame(resp_u.get("data", []))
        if df_underlying.empty:
            return False, {"status": "error", "message": "No underlying history data available"}, 404

        df_underlying = _convert_timestamp_to_ist(df_underlying)
        if df_underlying is None:
            return False, {"status": "error", "message": "Failed to parse underlying timestamps"}, 500

        # Fetch history for each leg
        leg_lookups = []  # list of (action_sign, {timestamp: close_price})
        leg_info = []     # for response metadata

        for i, leg in enumerate(legs):
            strike = float(leg["strike"])
            option_type = leg["option_type"].upper()
            action = leg["action"].upper()
            sign = 1 if action == "BUY" else -1

            symbol = construct_option_symbol(base_symbol, expiry_date.upper(), strike, option_type)

            success, resp, _ = get_history(
                symbol=symbol,
                exchange=options_exchange,
                interval=interval,
                start_date=start_date_str,
                end_date=end_date_str,
                api_key=api_key,
            )

            lookup = {}
            if success:
                df_leg = pd.DataFrame(resp.get("data", []))
                if not df_leg.empty:
                    df_leg = _convert_timestamp_to_ist(df_leg)
                    if df_leg is not None:
                        for ts, row in df_leg.iterrows():
                            lookup[ts] = float(row["close"])

            if not lookup:
                logger.warning(f"No history data for leg {i}: {symbol}")

            leg_lookups.append((sign, lookup))
            leg_info.append({
                "strike": strike,
                "option_type": option_type,
                "action": action,
                "symbol": symbol,
            })

        # Merge: for each underlying candle, compute combined premium
        series = []
        for ts, row in df_underlying.iterrows():
            spot = float(row["close"])
            combined = 0.0
            leg_prices = []
            all_available = True

            for sign, lookup in leg_lookups:
                price = lookup.get(ts)
                if price is None:
                    all_available = False
                    leg_prices.append(None)
                else:
                    combined += sign * price
                    leg_prices.append(round(price, 2))

            if not all_available:
                continue

            unix_seconds = int(ts.timestamp())
            series.append({
                "time": unix_seconds,
                "spot": round(spot, 2),
                "combined_premium": round(combined, 2),
                "leg_prices": leg_prices,
            })

        if not series:
            return (
                False,
                {"status": "error", "message": "No combined premium data available (option history may be missing)"},
                404,
            )

        # Get current LTP
        success_q, quote_resp, _ = get_quotes(
            symbol=base_symbol,
            exchange=quote_exchange,
            api_key=api_key,
        )
        underlying_ltp = quote_resp.get("data", {}).get("ltp", 0) if success_q else 0

        # Days to expiry
        days_to_expiry = _calculate_days_to_expiry(expiry_date)

        return (
            True,
            {
                "status": "success",
                "data": {
                    "underlying": base_symbol,
                    "underlying_ltp": underlying_ltp,
                    "expiry_date": expiry_date.upper(),
                    "interval": interval,
                    "days_to_expiry": days_to_expiry,
                    "legs": leg_info,
                    "series": series,
                },
            },
            200,
        )

    except Exception as e:
        logger.exception(f"Error calculating combine premium data: {e}")
        return False, {"status": "error", "message": str(e)}, 500


def get_strikes_for_underlying(underlying, exchange, expiry_date):
    """
    Get available strikes for an underlying/expiry combo.

    Returns:
        Tuple of (success, response_dict, status_code)
    """
    try:
        base_symbol = underlying.upper()
        quote_exchange = _get_quote_exchange(base_symbol, exchange)
        options_exchange = get_option_exchange(quote_exchange)

        strikes = get_available_strikes(
            base_symbol, expiry_date.upper(), "CE", options_exchange
        )
        if not strikes:
            return (
                False,
                {"status": "error", "message": f"No strikes found for {base_symbol} {expiry_date}"},
                404,
            )

        return (
            True,
            {
                "status": "success",
                "data": {
                    "strikes": [float(s) for s in strikes],
                },
            },
            200,
        )

    except Exception as e:
        logger.exception(f"Error fetching strikes: {e}")
        return False, {"status": "error", "message": str(e)}, 500


def _calculate_days_to_expiry(expiry_date_str):
    """Calculate days to expiry from DDMMMYY format string."""
    try:
        ist = pytz.timezone("Asia/Kolkata")
        now = datetime.now(ist)
        expiry_dt = datetime.strptime(expiry_date_str.upper(), "%d%b%y")
        expiry_dt = expiry_dt.replace(hour=15, minute=30)
        expiry_dt = ist.localize(expiry_dt)
        delta = expiry_dt - now
        return max(0, delta.days)
    except Exception:
        return 0
