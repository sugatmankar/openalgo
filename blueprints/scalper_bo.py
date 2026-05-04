"""
Scalper Bracket Order Blueprint
Provides bracket order management (SL, Target, Trailing) for the Scalper Terminal.

Modes:
  - 'broker': Places actual SL orders on the exchange (reliable, works if browser closed)
  - 'ui': SL/Target monitored client-side only (no broker orders)

Endpoints:
  POST /scalper/api/bracket/place-sl     - Create bracket with SL (and optionally place SL order)
  POST /scalper/api/bracket/trail-sl     - Modify/trail an existing SL order
  POST /scalper/api/bracket/cancel-sl    - Cancel a bracket (and its broker SL order)
  POST /scalper/api/bracket/status       - Get all active brackets (with reconciliation)
  POST /scalper/api/bracket/target-exit  - Target hit: cancel SL + place market exit
  POST /scalper/api/bracket/sl-exit      - UI SL hit: place market exit
  POST /scalper/api/bracket/partial-exit - Partial exit (50%/75%) with SL qty reduction
  POST /scalper/api/bracket/update-sl    - Manually tighten SL price
"""
import os
import time

from flask import Blueprint, jsonify, request, session

from database.auth_db import get_api_key_for_tradingview, get_auth_token
from database.scalper_db import (
    ScalperBracketOrder,
    create_bracket,
    db_session,
    get_active_brackets,
    get_bracket_for_symbol,
    init_scalper_db,
    mark_bracket_triggered,
    update_bracket_sl,
)
from limiter import limiter
from utils.logging import get_logger
from utils.session import check_session_validity

logger = get_logger(__name__)

API_RATE_LIMIT = os.getenv("API_RATE_LIMIT", "50 per second")

scalper_bo_bp = Blueprint("scalper_bo_bp", __name__, url_prefix="/scalper/api/bracket")


def _round_to_tick(price, tick=0.05):
    """Round price to nearest tick size (0.05 for options)."""
    return round(round(price / tick) * tick, 2)


def _get_auth():
    """Get auth_token and broker from session. Returns (auth_token, broker) or raises."""
    login_username = session.get("user")
    if not login_username:
        return None, None
    auth_token = get_auth_token(login_username)
    broker_name = session.get("broker")
    return auth_token, broker_name


def _get_api_key():
    """Get the API key for service calls (needed for order validation and analyze mode)."""
    login_username = session.get("user")
    if not login_username:
        return None
    return get_api_key_for_tradingview(login_username)


def _place_sl_with_retry(auth_token, broker, symbol, sl_action, exchange, product,
                         quantity, sl_trigger, sl_limit_price, max_retries=3):
    """
    Place SL order on broker with retry logic.
    Returns (response_data, sl_order_id) tuple.
    """
    from services.place_order_service import place_order

    api_key = _get_api_key()
    last_response = None

    for attempt in range(1, max_retries + 1):
        try:
            order_data = {
                "strategy": "Scalper",
                "symbol": symbol,
                "exchange": exchange,
                "action": sl_action,
                "pricetype": "SL",
                "product": product,
                "quantity": quantity,
                "price": sl_limit_price,
                "trigger_price": sl_trigger,
                "disclosed_quantity": 0,
            }
            success, response, status_code = place_order(
                order_data=order_data,
                api_key=api_key,
                auth_token=auth_token,
                broker=broker,
                emit_event=True,
            )
            last_response = response

            if success:
                sl_order_id = response.get("orderid")
                if attempt > 1:
                    logger.info(f"[BRACKET SL RETRY] Succeeded on attempt {attempt} for {symbol}")
                return response, sl_order_id
            else:
                logger.warning(
                    f"[BRACKET SL RETRY] Attempt {attempt}/{max_retries} failed for {symbol}: "
                    f"{response.get('message', 'Unknown error')}"
                )
        except Exception as e:
            last_response = {"status": "error", "message": str(e)}
            logger.warning(f"[BRACKET SL RETRY] Attempt {attempt}/{max_retries} exception for {symbol}: {e}")

        if attempt < max_retries:
            backoff = 0.5 * (2 ** (attempt - 1))  # 0.5s, 1s, 2s
            time.sleep(backoff)

    logger.error(
        f"[BRACKET SL RETRY] All {max_retries} attempts failed for {symbol} {sl_action} "
        f"qty={quantity} trigger={sl_trigger}, limit={sl_limit_price}"
    )
    return last_response, None


def _modify_sl_with_retry(auth_token, broker, bracket, symbol, sl_action, exchange, product,
                          quantity, new_sl_price, sl_limit_price, max_retries=3):
    """
    Modify SL order on broker with retry logic.
    Falls back to cancel + place new SL if modify fails.
    Returns (success: bool, response: dict).
    """
    from services.cancel_order_service import cancel_order
    from services.modify_order_service import modify_order

    api_key = _get_api_key()

    for attempt in range(1, max_retries + 1):
        try:
            order_data = {
                "orderid": bracket.sl_order_id,
                "symbol": symbol,
                "exchange": exchange,
                "action": sl_action,
                "pricetype": "SL",
                "product": product,
                "quantity": quantity,
                "price": sl_limit_price,
                "trigger_price": new_sl_price,
                "disclosed_quantity": 0,
            }
            success, response, status_code = modify_order(
                order_data=order_data,
                api_key=api_key,
                auth_token=auth_token,
                broker=broker,
            )

            if success:
                if attempt > 1:
                    logger.info(f"[BRACKET TRAIL RETRY] Modify succeeded on attempt {attempt} for {symbol}")
                return True, response
            else:
                logger.warning(
                    f"[BRACKET TRAIL RETRY] Modify attempt {attempt}/{max_retries} failed for {symbol}: "
                    f"{response.get('message', 'Unknown error')}"
                )
        except Exception as e:
            logger.warning(f"[BRACKET TRAIL RETRY] Modify attempt {attempt}/{max_retries} exception for {symbol}: {e}")

        if attempt < max_retries:
            backoff = 0.3 * (2 ** (attempt - 1))  # 0.3s, 0.6s, 1.2s
            time.sleep(backoff)

    # All modify retries failed — try cancel + replace
    logger.warning(f"[BRACKET TRAIL RETRY] All modify attempts failed for {symbol}, trying cancel+replace...")
    try:
        cancel_order(
            orderid=bracket.sl_order_id,
            api_key=api_key,
            auth_token=auth_token,
            broker=broker,
        )
        logger.info(f"[BRACKET TRAIL RETRY] Cancelled old SL {bracket.sl_order_id} for replacement")

        sl_response, new_order_id = _place_sl_with_retry(
            auth_token, broker, symbol, sl_action, exchange, product,
            quantity, new_sl_price, sl_limit_price, max_retries=2
        )

        if new_order_id:
            bracket.sl_order_id = new_order_id
            bracket.sl_order_status = "placed"
            logger.info(f"[BRACKET TRAIL RETRY] Cancel+replace succeeded: new SL order {new_order_id}")
            return True, sl_response
        else:
            logger.error(f"[BRACKET TRAIL RETRY] Cancel+replace FAILED for {symbol} — POSITION UNPROTECTED!")
            return False, sl_response or {"status": "error", "message": "Cancel+replace failed"}
    except Exception as e:
        logger.error(f"[BRACKET TRAIL RETRY] Cancel+replace exception for {symbol}: {e}")
        return False, {"status": "error", "message": str(e)}


def _cancel_bracket_sl_internal(auth_token, broker, symbol, exchange, product):
    """Cancel any active broker-side SL order for a specific position and mark bracket as cancelled."""
    from services.cancel_order_service import cancel_order

    api_key = _get_api_key()
    try:
        bracket = get_bracket_for_symbol(symbol, exchange, product)
        if bracket and bracket.bracket_mode == "broker" and bracket.sl_order_id:
            try:
                cancel_order(
                    orderid=bracket.sl_order_id,
                    api_key=api_key,
                    auth_token=auth_token,
                    broker=broker,
                )
                logger.info(f"[BRACKET] Cancelled SL order {bracket.sl_order_id} for {symbol}")
            except Exception as cancel_err:
                logger.warning(f"[BRACKET] Failed to cancel SL order {bracket.sl_order_id}: {cancel_err}")
            mark_bracket_triggered(bracket.id, "cancelled")
        elif bracket:
            mark_bracket_triggered(bracket.id, "cancelled")
    except Exception as e:
        logger.error(f"[BRACKET] Error cancelling bracket SL for {symbol}: {e}")
        db_session.rollback()


# =====================================================
# Bracket Order API Endpoints
# =====================================================

@scalper_bo_bp.route("/place-sl", methods=["POST"])
@check_session_validity
@limiter.limit(API_RATE_LIMIT)
def bracket_place_sl():
    """
    Place a bracket SL order after entry.
    In 'broker' mode, places an actual SL order on the exchange.
    In 'ui' mode, just stores the bracket in DB for frontend monitoring.
    """
    auth_token, broker = _get_auth()
    if not auth_token or not broker:
        return jsonify({"status": "error", "message": "Authentication error"}), 401

    data = request.get_json()
    symbol = data.get("symbol")
    exchange = data.get("exchange", "NFO")
    product = data.get("product", "MIS")
    entry_action = data.get("entry_action", "BUY")
    quantity = abs(int(data.get("quantity", 0)))
    entry_price = float(data.get("entry_price", 0))
    sl_points = float(data.get("sl_points", 10))
    target_points = float(data.get("target_points", 20))
    trail_enabled = data.get("trail_enabled", False)
    trail_step = float(data.get("trail_step", 5))
    bracket_mode = data.get("bracket_mode", "broker")

    if not symbol or quantity <= 0 or entry_price <= 0:
        return jsonify({"status": "error", "message": "Invalid params"}), 400

    # Check for existing bracket — merge quantities on add-to-position
    existing = get_bracket_for_symbol(symbol, exchange, product)

    if existing:
        old_qty = existing.quantity
        old_entry = existing.entry_price
        total_qty = old_qty + quantity
        avg_entry = round((old_entry * old_qty + entry_price * quantity) / total_qty, 2)
        logger.info(
            f"[BRACKET] Adding to position {symbol}: {old_qty}+{quantity}={total_qty}, "
            f"entry {old_entry}+{entry_price}→avg {avg_entry}"
        )

        if existing.bracket_mode == "broker" and existing.sl_order_id:
            try:
                from services.cancel_order_service import cancel_order

                is_long = entry_action == "BUY"
                sl_action = "SELL" if is_long else "BUY"
                # Recalculate SL from new avg entry using current SL points from request
                keep_sl = _round_to_tick(max(avg_entry - sl_points, 0.05) if is_long else avg_entry + sl_points)
                new_target = _round_to_tick(avg_entry + target_points if is_long else avg_entry - target_points)

                # Cancel old SL order
                api_key = _get_api_key()
                cancel_order(
                    orderid=existing.sl_order_id,
                    api_key=api_key,
                    auth_token=auth_token,
                    broker=broker,
                )

                # Place new SL with correct total qty
                buffer = max(keep_sl * 0.03, 2.0)
                if sl_action == "SELL":
                    sl_limit_price = _round_to_tick(max(keep_sl - buffer, 0.05))
                else:
                    sl_limit_price = _round_to_tick(keep_sl + buffer)

                sl_response, new_sl_order_id = _place_sl_with_retry(
                    auth_token, broker, symbol, sl_action, exchange, product,
                    total_qty, keep_sl, sl_limit_price, max_retries=3
                )

                if new_sl_order_id:
                    existing.sl_order_id = new_sl_order_id
                    existing.sl_order_status = "placed"
                    existing.quantity = total_qty
                    existing.entry_price = avg_entry
                    existing.sl_price = keep_sl  # Recalculated from new avg entry
                    existing.best_price = avg_entry  # Reset HWM for fresh trailing
                    existing.target_price = new_target
                    existing.sl_points = sl_points
                    existing.target_points = target_points
                    existing.trail_enabled = trail_enabled
                    existing.trail_step = trail_step if trail_enabled else None
                    db_session.commit()

                    return jsonify({
                        "status": "success",
                        "message": f"Bracket SL replaced (qty={total_qty}, SL={keep_sl})",
                        "bracket_id": existing.id,
                        "sl_order_id": new_sl_order_id,
                        "sl_price": keep_sl,
                        "target_price": new_target,
                        "bracket_mode": existing.bracket_mode,
                        "total_quantity": total_qty,
                        "entry_price": avg_entry,
                        "best_price": existing.best_price,
                    })
                else:
                    existing.sl_order_status = "failed"
                    existing.quantity = total_qty
                    existing.entry_price = avg_entry
                    db_session.commit()
                    return jsonify({
                        "status": "error",
                        "message": f"SL replacement FAILED — POSITION UNPROTECTED! "
                                   f"{sl_response.get('message', 'Unknown error') if sl_response else 'Unknown error'}",
                    })
            except Exception as replace_err:
                logger.error(f"[BRACKET REPLACE] Exception for {symbol}: {replace_err}")
                return jsonify({"status": "error", "message": f"SL replace error: {str(replace_err)}"})

        # UI mode accumulation — recalculate SL/target from new avg entry
        is_long = entry_action == "BUY"
        new_sl = _round_to_tick(max(avg_entry - sl_points, 0.05) if is_long else avg_entry + sl_points)
        new_target = _round_to_tick(avg_entry + target_points if is_long else avg_entry - target_points)
        existing.quantity = total_qty
        existing.entry_price = avg_entry
        existing.sl_price = new_sl
        existing.target_price = new_target
        existing.sl_points = sl_points
        existing.target_points = target_points
        existing.trail_enabled = trail_enabled
        existing.trail_step = trail_step if trail_enabled else None
        existing.best_price = avg_entry  # Reset HWM for fresh trailing
        db_session.commit()
        return jsonify({
            "status": "success",
            "message": f"UI bracket updated (qty={total_qty})",
            "bracket_id": existing.id,
            "sl_price": new_sl,
            "target_price": new_target,
            "bracket_mode": existing.bracket_mode,
            "total_quantity": total_qty,
            "entry_price": avg_entry,
            "best_price": existing.best_price,
        })

    # New bracket
    is_long = entry_action == "BUY"
    sl_trigger = entry_price - sl_points if is_long else entry_price + sl_points
    target_price = entry_price + target_points if is_long else entry_price - target_points

    sl_trigger = _round_to_tick(max(sl_trigger, 0.05))
    target_price = _round_to_tick(target_price)

    sl_order_id = None
    sl_order_status = "pending"

    if bracket_mode == "broker":
        try:
            sl_action = "SELL" if is_long else "BUY"
            buffer = max(sl_trigger * 0.03, 2.0)
            if sl_action == "SELL":
                sl_limit_price = _round_to_tick(max(sl_trigger - buffer, 0.05))
            else:
                sl_limit_price = _round_to_tick(sl_trigger + buffer)

            sl_response, sl_order_id = _place_sl_with_retry(
                auth_token, broker, symbol, sl_action, exchange, product,
                quantity, sl_trigger, sl_limit_price, max_retries=3
            )

            if sl_order_id:
                sl_order_status = "placed"
                logger.info(
                    f"[BRACKET] Placed SL order {sl_order_id}: {symbol} {sl_action} "
                    f"qty={quantity} trigger={sl_trigger}, limit={sl_limit_price}"
                )
            else:
                sl_order_status = "failed"
                return jsonify({
                    "status": "error",
                    "message": f"SL order failed after retries: "
                               f"{sl_response.get('message', 'Unknown error') if sl_response else 'Unknown error'}",
                })
        except Exception as e:
            logger.error(f"[BRACKET] Exception placing SL for {symbol}: {e}")
            return jsonify({"status": "error", "message": f"SL order error: {str(e)}"})

    # Save bracket to DB
    try:
        bracket = create_bracket(
            symbol=symbol, exchange=exchange, product=product,
            action=entry_action, quantity=quantity, entry_price=entry_price,
            bracket_mode=bracket_mode,
            sl_price=sl_trigger, target_price=target_price,
            sl_points=sl_points, target_points=target_points,
            trail_enabled=trail_enabled,
            trail_step=trail_step if trail_enabled else None,
            sl_order_id=sl_order_id, sl_order_status=sl_order_status,
        )

        return jsonify({
            "status": "success",
            "message": f"Bracket SL placed (qty={quantity})" if bracket_mode == "broker"
                       else f"UI monitor active (qty={quantity})",
            "bracket_id": bracket.id,
            "sl_order_id": sl_order_id,
            "sl_price": sl_trigger,
            "target_price": target_price,
            "bracket_mode": bracket_mode,
            "total_quantity": quantity,
            "entry_price": entry_price,
        })
    except Exception as e:
        db_session.rollback()
        logger.error(f"[BRACKET] DB error saving bracket for {symbol}: {e}")
        # Cancel orphaned SL order
        if sl_order_id and bracket_mode == "broker":
            try:
                from services.cancel_order_service import cancel_order

                cancel_order(
                    orderid=sl_order_id,
                    api_key=_get_api_key(),
                    auth_token=auth_token,
                    broker=broker,
                )
            except Exception as cancel_err:
                logger.error(f"[BRACKET] CRITICAL: Orphaned SL order {sl_order_id} — manual cancel needed! {cancel_err}")
        return jsonify({"status": "error", "message": f"Failed to save bracket: {str(e)}"})


@scalper_bo_bp.route("/trail-sl", methods=["POST"])
@check_session_validity
@limiter.limit(API_RATE_LIMIT)
def bracket_trail_sl():
    """Trail (modify) an existing broker-side SL order's trigger price."""
    auth_token, broker = _get_auth()
    if not auth_token or not broker:
        return jsonify({"status": "error", "message": "Authentication error"}), 401

    data = request.get_json()
    symbol = data.get("symbol")
    exchange = data.get("exchange", "NFO")
    product = data.get("product", "MIS")
    new_sl_price = float(data.get("new_sl_price", 0))
    best_price = float(data.get("best_price", 0))
    new_target_price = float(data.get("new_target_price", 0))  # Trail target alongside SL

    if not symbol or new_sl_price <= 0:
        return jsonify({"status": "error", "message": "Invalid params"}), 400

    bracket = get_bracket_for_symbol(symbol, exchange, product)
    if not bracket:
        return jsonify({"status": "error", "message": "No active bracket found"}), 404

    old_sl = bracket.sl_price

    if bracket.bracket_mode == "broker" and bracket.sl_order_id:
        try:
            sl_action = "SELL" if bracket.action == "BUY" else "BUY"
            modify_qty = bracket.quantity

            new_sl_price = _round_to_tick(new_sl_price)
            buffer = max(new_sl_price * 0.03, 2.0)
            if sl_action == "SELL":
                sl_limit_price = _round_to_tick(max(new_sl_price - buffer, 0.05))
            else:
                sl_limit_price = _round_to_tick(new_sl_price + buffer)

            success, modify_resp = _modify_sl_with_retry(
                auth_token, broker, bracket, symbol, sl_action, exchange, product,
                modify_qty, new_sl_price, sl_limit_price, max_retries=3
            )

            if success:
                update_bracket_sl(bracket.id, new_sl_price, best_price=best_price,
                                  target_price=new_target_price if new_target_price > 0 else None)
                logger.info(f"[BRACKET TRAIL] {symbol}: SL modified {old_sl:.2f} → {new_sl_price:.2f}, TGT → {new_target_price:.2f}")
                return jsonify({
                    "status": "success",
                    "message": f"SL trailed: {old_sl:.2f} → {new_sl_price:.2f}",
                    "new_sl_price": new_sl_price,
                    "new_target_price": new_target_price,
                })
            else:
                return jsonify({
                    "status": "error",
                    "message": f"SL modify failed: {modify_resp.get('message', 'Unknown error')}",
                })
        except Exception as e:
            logger.error(f"[BRACKET TRAIL] Exception for {symbol}: {e}")
            return jsonify({"status": "error", "message": str(e)})
    else:
        # UI mode — just update DB
        update_bracket_sl(bracket.id, new_sl_price, best_price=best_price,
                          target_price=new_target_price if new_target_price > 0 else None)
        return jsonify({
            "status": "success",
            "message": f"SL updated (UI): {old_sl:.2f} → {new_sl_price:.2f}",
            "new_sl_price": new_sl_price,
            "new_target_price": new_target_price,
        })


@scalper_bo_bp.route("/partial-exit", methods=["POST"])
@check_session_validity
@limiter.limit(API_RATE_LIMIT)
def bracket_partial_exit():
    """
    Partial exit: exit a fraction of the position (e.g. 50%, 75%) and reduce the
    bracket SL order quantity accordingly. Locks in partial profits while
    keeping the remaining position protected by a trailing SL.
    """
    from services.cancel_order_service import cancel_order
    from services.place_order_service import place_order

    auth_token, broker = _get_auth()
    if not auth_token or not broker:
        return jsonify({"status": "error", "message": "Authentication error"}), 401

    data = request.get_json()
    symbol = data.get("symbol")
    exchange = data.get("exchange", "NFO")
    product = data.get("product", "MIS")
    signed_qty = int(data.get("quantity", 0))      # signed: +ve for long, -ve for short
    exit_qty = abs(int(data.get("exit_qty", 0)))    # always positive

    if not symbol or exit_qty <= 0:
        return jsonify({"status": "error", "message": "Invalid symbol or exit qty"}), 400

    api_key = _get_api_key()
    bracket = get_bracket_for_symbol(symbol, exchange, product)
    abs_qty = abs(signed_qty)
    remaining_qty = abs_qty - exit_qty
    exit_action = "SELL" if signed_qty > 0 else "BUY"

    # STEP 1: Cancel the existing SL order FIRST (broker blocks exit while SL covers full qty)
    if bracket and bracket.bracket_mode == "broker" and bracket.sl_order_id:
        try:
            cancel_order(
                orderid=bracket.sl_order_id,
                api_key=api_key,
                auth_token=auth_token,
                broker=broker,
            )
            logger.info(f"[BRACKET PARTIAL] Cancelled SL order {bracket.sl_order_id} before partial exit")
        except Exception as cancel_err:
            logger.warning(f"[BRACKET PARTIAL] SL cancel failed: {cancel_err}")

    # STEP 2: Place partial exit market order
    try:
        order_data = {
            "strategy": "Scalper",
            "symbol": symbol,
            "exchange": exchange,
            "action": exit_action,
            "pricetype": "MARKET",
            "product": product,
            "quantity": exit_qty,
            "price": 0,
            "trigger_price": 0,
            "disclosed_quantity": 0,
        }
        success, response, status_code = place_order(
            order_data=order_data,
            api_key=api_key,
            auth_token=auth_token,
            broker=broker,
        )
    except Exception as e:
        logger.error(f"[BRACKET PARTIAL] Place order exception: {e}")
        success = False
        response = {"status": "error", "message": str(e)}

    if not success:
        # Exit failed — re-place SL order to protect position
        if bracket and bracket.bracket_mode == "broker":
            try:
                sl_action = "SELL" if bracket.action == "BUY" else "BUY"
                sl_price = _round_to_tick(bracket.sl_price)
                buffer = max(sl_price * 0.03, 2.0)
                sl_limit = _round_to_tick(max(sl_price - buffer, 0.05)) if sl_action == "SELL" else _round_to_tick(sl_price + buffer)
                sl_resp, new_id = _place_sl_with_retry(
                    auth_token, broker, symbol, sl_action, exchange, product, abs_qty, sl_price, sl_limit, max_retries=3
                )
                if new_id:
                    bracket.sl_order_id = new_id
                    bracket.sl_order_status = "placed"
                    db_session.commit()
                    logger.info(f"[BRACKET PARTIAL] Re-placed SL order {new_id} after exit failure")
            except Exception as repl_err:
                logger.error(f"[BRACKET PARTIAL] CRITICAL: Failed to re-place SL after exit failure: {repl_err}")
        return jsonify({"status": "error", "message": response.get("message", "Order failed")})

    logger.info(f"[BRACKET PARTIAL] {symbol}: Exited {exit_qty} qty, remaining={remaining_qty}")

    # STEP 3: Update bracket — place new SL with reduced qty, or cancel if fully exited
    if bracket:
        if remaining_qty <= 0:
            mark_bracket_triggered(bracket.id, "cancelled")
            logger.info(f"[BRACKET PARTIAL] {symbol}: Fully exited, bracket cancelled")
        else:
            bracket.quantity = remaining_qty
            if bracket.bracket_mode == "broker":
                try:
                    sl_action = "SELL" if bracket.action == "BUY" else "BUY"
                    sl_price = _round_to_tick(bracket.sl_price)
                    buffer = max(sl_price * 0.03, 2.0)
                    sl_limit = _round_to_tick(max(sl_price - buffer, 0.05)) if sl_action == "SELL" else _round_to_tick(sl_price + buffer)
                    sl_resp, new_sl_id = _place_sl_with_retry(
                        auth_token, broker, symbol, sl_action, exchange, product,
                        remaining_qty, sl_price, sl_limit, max_retries=3
                    )
                    if new_sl_id:
                        bracket.sl_order_id = new_sl_id
                        bracket.sl_order_status = "placed"
                        logger.info(f"[BRACKET PARTIAL] New SL order {new_sl_id} placed for remaining {remaining_qty} qty")
                    else:
                        bracket.sl_order_status = "failed"
                        logger.warning(f"[BRACKET PARTIAL] New SL placement failed: {sl_resp}")
                except Exception as mod_err:
                    logger.error(f"[BRACKET PARTIAL] New SL placement error: {mod_err}")
            db_session.commit()

    return jsonify({
        "status": "success",
        "message": f"Partial exit: {exit_qty} qty",
        "remaining_qty": remaining_qty,
        "order_id": response.get("orderid"),
    })


@scalper_bo_bp.route("/update-sl", methods=["POST"])
@check_session_validity
@limiter.limit(API_RATE_LIMIT)
def bracket_update_sl():
    """
    Manually update (tighten/move) the SL price for an active bracket.
    Used when the trader wants to lock in more profit by manually setting a tighter SL
    without waiting for the automatic trailing mechanism.
    """
    auth_token, broker = _get_auth()
    if not auth_token or not broker:
        return jsonify({"status": "error", "message": "Authentication error"}), 401

    data = request.get_json()
    symbol = data.get("symbol")
    exchange = data.get("exchange", "NFO")
    product = data.get("product", "MIS")
    new_sl_price = float(data.get("new_sl_price", 0))
    current_ltp = float(data.get("current_ltp", 0))  # LTP for resetting trail baseline

    if not symbol or new_sl_price <= 0:
        return jsonify({"status": "error", "message": "Invalid params"}), 400

    bracket = get_bracket_for_symbol(symbol, exchange, product)
    if not bracket:
        return jsonify({"status": "error", "message": "No active bracket found"}), 404

    old_sl = bracket.sl_price

    if bracket.bracket_mode == "broker" and bracket.sl_order_id:
        try:
            sl_action = "SELL" if bracket.action == "BUY" else "BUY"
            new_sl_price = _round_to_tick(new_sl_price)
            buffer = max(new_sl_price * 0.03, 2.0)
            if sl_action == "SELL":
                sl_limit_price = _round_to_tick(max(new_sl_price - buffer, 0.05))
            else:
                sl_limit_price = _round_to_tick(new_sl_price + buffer)

            logger.info(
                f"[BRACKET UPDATE-SL] Modifying SL order {bracket.sl_order_id}: "
                f"{symbol} trigger={old_sl:.2f} → {new_sl_price:.2f}"
            )

            success, modify_resp = _modify_sl_with_retry(
                auth_token, broker, bracket, symbol, sl_action, exchange, product,
                bracket.quantity, new_sl_price, sl_limit_price, max_retries=3
            )

            if success:
                # Reset best_price to current LTP so trail system uses new SL as baseline
                new_best = current_ltp if current_ltp > 0 else bracket.best_price
                update_bracket_sl(bracket.id, new_sl_price, best_price=new_best)
                logger.info(f"[BRACKET UPDATE-SL] {symbol}: SL updated {old_sl:.2f} → {new_sl_price:.2f}, best_price reset to {new_best:.2f}")
                return jsonify({
                    "status": "success",
                    "message": f"SL updated: {old_sl:.2f} → {new_sl_price:.2f}",
                    "new_sl_price": new_sl_price,
                })
            else:
                logger.warning(f"[BRACKET UPDATE-SL] Modify failed: {modify_resp}")
                return jsonify({
                    "status": "error",
                    "message": f"SL modify failed: {modify_resp.get('message', 'Unknown error')}",
                })
        except Exception as e:
            logger.error(f"[BRACKET UPDATE-SL] Exception: {e}")
            return jsonify({"status": "error", "message": str(e)})
    else:
        # UI mode — reset best_price to current LTP so trail system uses new SL as baseline
        new_best = current_ltp if current_ltp > 0 else bracket.best_price
        update_bracket_sl(bracket.id, new_sl_price, best_price=new_best)
        logger.info(f"[BRACKET UPDATE-SL] {symbol}: SL updated (UI) {old_sl:.2f} → {new_sl_price:.2f}, best_price reset to {new_best:.2f}")
        return jsonify({
            "status": "success",
            "message": f"SL updated (UI): {old_sl:.2f} → {new_sl_price:.2f}",
            "new_sl_price": new_sl_price,
        })


@scalper_bo_bp.route("/cancel-sl", methods=["POST"])
@check_session_validity
@limiter.limit(API_RATE_LIMIT)
def bracket_cancel_sl():
    """Cancel a bracket order (and its broker SL order if active)."""
    auth_token, broker = _get_auth()
    if not auth_token or not broker:
        return jsonify({"status": "error", "message": "Authentication error"}), 401

    data = request.get_json()
    symbol = data.get("symbol")
    exchange = data.get("exchange", "NFO")
    product = data.get("product", "MIS")

    _cancel_bracket_sl_internal(auth_token, broker, symbol, exchange, product)
    return jsonify({"status": "success", "message": f"Bracket cancelled for {symbol}"})


@scalper_bo_bp.route("/status", methods=["POST"])
@check_session_validity
@limiter.limit(API_RATE_LIMIT)
def bracket_status():
    """
    Get active bracket orders. Also reconciles: if a bracket has status='active'
    but no matching open position exists, it's auto-cleaned as sl_hit.
    """
    auth_token, broker = _get_auth()
    if not auth_token or not broker:
        return jsonify({"status": "error", "message": "Authentication error"}), 401

    brackets = get_active_brackets()
    if not brackets:
        return jsonify({"status": "success", "brackets": []})

    # Reconciliation: check actual positions
    # In analyzer mode, use sandbox positions; in live mode, use broker positions
    from database.settings_db import get_analyze_mode
    open_position_keys = set()
    try:
        if get_analyze_mode():
            # Analyzer mode: query sandbox positions
            from database.auth_db import get_api_key_for_tradingview
            from services.sandbox_service import sandbox_get_positions
            login_username = session.get("user")
            api_key = get_api_key_for_tradingview(login_username) if login_username else None
            if api_key:
                success, resp, _ = sandbox_get_positions(api_key, {})
                if success and isinstance(resp, dict):
                    pos_list = resp.get("data", [])
                    if isinstance(pos_list, list):
                        for pos in pos_list:
                            qty = int(pos.get("quantity", 0))
                            if qty != 0:
                                open_position_keys.add((
                                    pos.get("symbol", ""),
                                    pos.get("exchange", ""),
                                    pos.get("product", ""),
                                ))
            else:
                # Can't verify — assume all brackets are valid
                for b in brackets:
                    open_position_keys.add((b.symbol, b.exchange, b.product))
        else:
            # Live mode: query broker positions
            from importlib import import_module
            broker_module = import_module(f"broker.{broker}.api.order_api")
            res, response, _ = broker_module.get_open_position(auth_token)
            if response and isinstance(response, list):
                for pos in response:
                    qty = int(pos.get("quantity", 0))
                    if qty != 0:
                        open_position_keys.add((
                            pos.get("symbol", ""),
                            pos.get("exchange", ""),
                            pos.get("product", ""),
                        ))
    except Exception as e:
        logger.warning(f"[BRACKET RECONCILE] Failed to fetch positions: {e}")
        # On error, don't clean up — assume positions may exist
        for b in brackets:
            open_position_keys.add((b.symbol, b.exchange, b.product))

    valid_brackets = []
    orphaned_count = 0
    for b in brackets:
        key = (b.symbol, b.exchange, b.product)
        if key in open_position_keys:
            valid_brackets.append(b)
        else:
            logger.info(
                f"[BRACKET RECONCILE] Orphaned bracket {b.id} for {b.symbol} — no open position. Marking sl_hit."
            )
            mark_bracket_triggered(b.id, "sl_hit")
            orphaned_count += 1

    if orphaned_count > 0:
        logger.info(f"[BRACKET RECONCILE] Cleaned up {orphaned_count} orphaned bracket(s)")

    bracket_list = [b.to_dict() for b in valid_brackets]
    return jsonify({"status": "success", "brackets": bracket_list})


@scalper_bo_bp.route("/target-exit", methods=["POST"])
@check_session_validity
@limiter.limit(API_RATE_LIMIT)
def bracket_target_exit():
    """Target hit: cancel the broker SL order and place a market exit."""
    from services.cancel_order_service import cancel_order
    from services.place_order_service import place_order

    auth_token, broker = _get_auth()
    if not auth_token or not broker:
        return jsonify({"status": "error", "message": "Authentication error"}), 401

    data = request.get_json()
    symbol = data.get("symbol")
    exchange = data.get("exchange", "NFO")
    product = data.get("product", "MIS")
    quantity = abs(int(data.get("quantity", 0)))

    if not symbol or quantity <= 0:
        return jsonify({"status": "error", "message": "Invalid params"}), 400

    bracket = get_bracket_for_symbol(symbol, exchange, product)

    # Cancel the broker SL order first
    if bracket and bracket.bracket_mode == "broker" and bracket.sl_order_id:
        try:
            cancel_order(
                orderid=bracket.sl_order_id,
                api_key=_get_api_key(),
                auth_token=auth_token,
                broker=broker,
            )
            logger.info(f"[BRACKET TARGET] Cancelled SL order {bracket.sl_order_id}")
        except Exception as cancel_err:
            logger.warning(f"[BRACKET TARGET] Failed to cancel SL order: {cancel_err}")

    if not bracket:
        logger.warning(f"[BRACKET TARGET] No active bracket for {symbol} — position likely already exited")
        return jsonify({"status": "error", "message": "No active bracket found (position already exited?)"}), 404

    # Place the exit order
    exit_action = "SELL" if bracket.action == "BUY" else "BUY"
    try:
        order_data = {
            "strategy": "Scalper",
            "symbol": symbol,
            "exchange": exchange,
            "action": exit_action,
            "pricetype": "MARKET",
            "product": product,
            "quantity": quantity,
            "price": 0,
            "trigger_price": 0,
            "disclosed_quantity": 0,
        }
        success, response, status_code = place_order(
            order_data=order_data,
            api_key=_get_api_key(),
            auth_token=auth_token,
            broker=broker,
        )

        if bracket:
            mark_bracket_triggered(bracket.id, "target_hit")

        return jsonify({
            "status": response.get("status", "error"),
            "order_id": response.get("orderid"),
            "message": response.get("message", ""),
        })
    except Exception as e:
        logger.error(f"[BRACKET TARGET] Exit error for {symbol}: {e}")
        return jsonify({"status": "error", "message": str(e)})


@scalper_bo_bp.route("/sl-exit", methods=["POST"])
@check_session_validity
@limiter.limit(API_RATE_LIMIT)
def bracket_sl_exit():
    """UI-monitored SL hit: place a market exit order. Only used in 'ui' mode."""
    from services.place_order_service import place_order

    auth_token, broker = _get_auth()
    if not auth_token or not broker:
        return jsonify({"status": "error", "message": "Authentication error"}), 401

    data = request.get_json()
    symbol = data.get("symbol")
    exchange = data.get("exchange", "NFO")
    product = data.get("product", "MIS")
    quantity = abs(int(data.get("quantity", 0)))

    if not symbol or quantity <= 0:
        return jsonify({"status": "error", "message": "Invalid params"}), 400

    bracket = get_bracket_for_symbol(symbol, exchange, product)

    if not bracket:
        logger.warning(f"[BRACKET SL-EXIT] No active bracket for {symbol} — position likely already exited")
        return jsonify({"status": "error", "message": "No active bracket found (position already exited?)"}), 404

    exit_action = "SELL" if bracket.action == "BUY" else "BUY"

    try:
        order_data = {
            "strategy": "Scalper",
            "symbol": symbol,
            "exchange": exchange,
            "action": exit_action,
            "pricetype": "MARKET",
            "product": product,
            "quantity": quantity,
            "price": 0,
            "trigger_price": 0,
            "disclosed_quantity": 0,
        }
        success, response, status_code = place_order(
            order_data=order_data,
            api_key=_get_api_key(),
            auth_token=auth_token,
            broker=broker,
        )

        if bracket:
            mark_bracket_triggered(bracket.id, "sl_hit")

        return jsonify({
            "status": response.get("status", "error"),
            "order_id": response.get("orderid"),
            "message": response.get("message", ""),
        })
    except Exception as e:
        logger.error(f"[BRACKET SL-EXIT] Error for {symbol}: {e}")
        return jsonify({"status": "error", "message": str(e)})
