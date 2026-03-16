# Mapping OpenAlgo API Request https://openalgo.in/docs
# Mapping Flattrade Broking Parameters https://piconnect.flattrade.in/docs/

from database.token_db import get_br_symbol
from utils.logging import get_logger

logger = get_logger(__name__)


def transform_data(data, token, auth_token=None):
    """
    Transforms the new API request structure to the current expected structure.
    Sends MARKET orders as true MKT orders to FlatTrade (no MPP conversion).

    Args:
        data: Order data dictionary
        token: Instrument token
        auth_token: Authentication token (unused after MPP removal, kept for API compat)
    """
    symbol = get_br_symbol(data["symbol"], data["exchange"])
    # Handle special characters in symbol
    if symbol and "&" in symbol:
        symbol = symbol.replace("&", "%26")

    # Default values
    price = str(data.get("price", "0"))
    order_type = map_order_type(data["pricetype"])
    action = data["action"].upper()

    # MARKET orders: send as true MKT to FlatTrade (no MPP conversion)
    if data["pricetype"] == "MARKET":
        logger.info(
            f"MARKET order for Symbol={data['symbol']}, Exchange={data['exchange']}, Action={action} - sending as MKT"
        )

    # Basic mapping - ensure all numeric values are strings
    transformed = {
        "uid": data["apikey"],
        "actid": data["apikey"],
        "exch": data["exchange"],
        "tsym": symbol,
        "qty": str(data["quantity"]),
        "prc": price,
        "trgprc": str(data.get("trigger_price", "0")),
        "dscqty": str(data.get("disclosed_quantity", "0")),
        "prd": map_product_type(data["product"]),
        "trantype": "B" if action == "BUY" else "S",
        "prctyp": order_type,
        "mkt_protection": "0",
        "ret": "DAY",
        "ordersource": "API",
    }

    # Log order data without sensitive fields (uid, actid contain API keys)
    safe_log = {k: v for k, v in transformed.items() if k not in ("uid", "actid")}
    logger.info(f"Transformed order data: {safe_log}")
    return transformed


def transform_modify_order_data(data, token):
    # Handle special characters in symbol
    symbol = data["symbol"]
    if symbol and "&" in symbol:
        symbol = symbol.replace("&", "%26")

    result = {
        "uid": data["apikey"],
        "exch": data["exchange"],
        "norenordno": data["orderid"],
        "prctyp": map_order_type(data["pricetype"]),
        "prc": str(data["price"]),
        "qty": str(data["quantity"]),
        "tsym": symbol,
        "ret": "DAY",
        "dscqty": str(data.get("disclosed_quantity") or 0),
    }

    # Only include trigger price for SL/SL-M orders
    # Sending trgprc=0 for LIMIT orders causes "Trigger price invalid - 0.00" error
    if data["pricetype"] in ["SL", "SL-M"]:
        result["trgprc"] = str(data.get("trigger_price") or 0)

    return result


def map_order_type(pricetype):
    """
    Maps the new pricetype to the existing order type.
    """
    order_type_mapping = {"MARKET": "MKT", "LIMIT": "LMT", "SL": "SL-LMT", "SL-M": "SL-MKT"}
    return order_type_mapping.get(pricetype, "MARKET")  # Default to MARKET if not found


def map_product_type(product):
    """
    Maps the new product type to the existing product type.
    """
    product_type_mapping = {
        "CNC": "C",
        "NRML": "M",
        "MIS": "I",
    }
    return product_type_mapping.get(product, "I")  # Default to DELIVERY if not found


def reverse_map_product_type(product):
    """
    Maps the new product type to the existing product type.
    """
    reverse_product_type_mapping = {
        "C": "CNC",
        "M": "NRML",
        "I": "MIS",
    }
    return reverse_product_type_mapping.get(product)
