# database/broker_account_db.py

"""
Broker Account Database Module.

Supports multiple broker accounts per user. Each account stores encrypted
broker credentials (API key, secret) independently so the admin can
add multiple accounts of the same or different brokers.
"""

import os

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    create_engine,
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.pool import NullPool
from sqlalchemy.sql import func

from database.auth_db import decrypt_token, encrypt_token
from utils.logging import get_logger

logger = get_logger(__name__)

DATABASE_URL = os.getenv("DATABASE_URL")

# Conditionally create engine based on DB type
if DATABASE_URL and "sqlite" in DATABASE_URL:
    engine = create_engine(
        DATABASE_URL, poolclass=NullPool, connect_args={"check_same_thread": False}
    )
else:
    engine = create_engine(DATABASE_URL, pool_size=50, max_overflow=100, pool_timeout=10)

db_session = scoped_session(sessionmaker(autocommit=False, autoflush=False, bind=engine))
Base = declarative_base()
Base.query = db_session.query_property()


class BrokerAccount(Base):
    """
    Stores broker account configurations.
    Each row represents one broker account with its own credentials.
    A user can have many accounts, even for the same broker.
    """

    __tablename__ = "broker_accounts"

    id = Column(Integer, primary_key=True)
    user = Column(String(80), nullable=False)  # admin username
    account_name = Column(String(100), nullable=False)  # friendly label
    broker = Column(String(50), nullable=False)  # e.g. "zerodha", "angel"
    broker_api_key = Column(Text, nullable=False)  # encrypted
    broker_api_secret = Column(Text, nullable=False)  # encrypted
    redirect_url = Column(String(500), nullable=True)
    broker_api_key_market = Column(Text, nullable=True)  # encrypted – XTS brokers
    broker_api_secret_market = Column(Text, nullable=True)  # encrypted – XTS brokers

    # --- TOTP / auto-auth credential fields (all encrypted) ---
    user_id = Column(Text, nullable=True)  # encrypted – broker client/user ID
    password = Column(Text, nullable=True)  # encrypted – broker PIN / password / MPIN
    totp_key = Column(Text, nullable=True)  # encrypted – TOTP secret for auto-OTP
    mobile_number = Column(Text, nullable=True)  # encrypted – mobile (Kotak etc.)
    date_of_birth = Column(String(20), nullable=True)  # DD/MM/YYYY (Motilal)
    year_of_birth = Column(String(10), nullable=True)  # YYYY (Samco)

    # --- Connection status tracking ---
    connection_status = Column(String(20), default="disconnected")  # connected/disconnected/error
    error_message = Column(Text, nullable=True)  # last auth error
    last_connected_at = Column(DateTime(timezone=True), nullable=True)  # last successful auth

    is_active = Column(Boolean, default=True)
    is_authenticated = Column(Boolean, default=False)  # True after successful broker login
    created_at = Column(DateTime(timezone=True), default=func.now())
    updated_at = Column(DateTime(timezone=True), default=func.now(), onupdate=func.now())

    __table_args__ = (
        UniqueConstraint("user", "account_name", name="uq_user_account_name"),
        Index("idx_broker_accounts_user", "user"),
        Index("idx_broker_accounts_broker", "broker"),
    )


def init_db():
    """Create the broker_accounts table if it doesn't exist, and migrate new columns."""
    from database.db_init_helper import init_db_with_logging

    init_db_with_logging(Base, engine, "Broker Accounts DB", logger)

    # Migrate: add new columns if they don't exist (for existing installations)
    _migrate_new_columns()


def _migrate_new_columns():
    """Add new columns to existing broker_accounts table if missing."""
    from sqlalchemy import inspect as sa_inspect, text

    inspector = sa_inspect(engine)
    if not inspector.has_table("broker_accounts"):
        return

    existing_cols = {c["name"] for c in inspector.get_columns("broker_accounts")}
    new_columns = {
        "user_id": "TEXT",
        "password": "TEXT",
        "totp_key": "TEXT",
        "mobile_number": "TEXT",
        "date_of_birth": "VARCHAR(20)",
        "year_of_birth": "VARCHAR(10)",
        "connection_status": "VARCHAR(20) DEFAULT 'disconnected'",
        "error_message": "TEXT",
        "last_connected_at": "DATETIME",
    }

    with engine.connect() as conn:
        for col_name, col_type in new_columns.items():
            if col_name not in existing_cols:
                try:
                    conn.execute(text(f"ALTER TABLE broker_accounts ADD COLUMN {col_name} {col_type}"))
                    conn.commit()
                    logger.info(f"Migrated: added column '{col_name}' to broker_accounts")
                except Exception as e:
                    logger.debug(f"Column '{col_name}' migration skipped: {e}")


# ---------------------------------------------------------------------------
# CRUD helpers
# ---------------------------------------------------------------------------


def add_broker_account(
    user,
    account_name,
    broker,
    api_key,
    api_secret,
    redirect_url=None,
    api_key_market=None,
    api_secret_market=None,
    user_id=None,
    password=None,
    totp_key=None,
    mobile_number=None,
    date_of_birth=None,
    year_of_birth=None,
):
    """
    Create a new broker account. Credentials are encrypted before storage.
    Returns (account_id, None) on success, (None, error_message) on failure.
    """
    try:
        existing = (
            BrokerAccount.query.filter_by(user=user, account_name=account_name).first()
        )
        if existing:
            return None, f"Account name '{account_name}' already exists"

        account = BrokerAccount(
            user=user,
            account_name=account_name,
            broker=broker,
            broker_api_key=encrypt_token(api_key),
            broker_api_secret=encrypt_token(api_secret),
            redirect_url=redirect_url,
            broker_api_key_market=encrypt_token(api_key_market) if api_key_market else None,
            broker_api_secret_market=encrypt_token(api_secret_market) if api_secret_market else None,
            user_id=encrypt_token(user_id) if user_id else None,
            password=encrypt_token(password) if password else None,
            totp_key=encrypt_token(totp_key) if totp_key else None,
            mobile_number=encrypt_token(mobile_number) if mobile_number else None,
            date_of_birth=date_of_birth,
            year_of_birth=year_of_birth,
            connection_status="disconnected",
        )
        db_session.add(account)
        db_session.commit()
        logger.info(f"Broker account '{account_name}' ({broker}) created for user '{user}'")
        return account.id, None
    except Exception as e:
        db_session.rollback()
        logger.exception(f"Error creating broker account: {e}")
        return None, str(e)


def update_broker_account(
    account_id,
    user,
    account_name=None,
    broker=None,
    api_key=None,
    api_secret=None,
    redirect_url=None,
    api_key_market=None,
    api_secret_market=None,
    user_id=None,
    password=None,
    totp_key=None,
    mobile_number=None,
    date_of_birth=None,
    year_of_birth=None,
):
    """
    Update an existing broker account. Only provided fields are changed.
    Returns (True, None) on success, (False, error_message) on failure.
    """
    try:
        account = BrokerAccount.query.filter_by(id=account_id, user=user).first()
        if not account:
            return False, "Account not found"

        if account_name is not None:
            # Check uniqueness if name is changing
            if account_name != account.account_name:
                dup = BrokerAccount.query.filter_by(user=user, account_name=account_name).first()
                if dup:
                    return False, f"Account name '{account_name}' already exists"
            account.account_name = account_name
        if broker is not None:
            account.broker = broker
        if api_key is not None:
            account.broker_api_key = encrypt_token(api_key)
        if api_secret is not None:
            account.broker_api_secret = encrypt_token(api_secret)
        if redirect_url is not None:
            account.redirect_url = redirect_url
        if api_key_market is not None:
            account.broker_api_key_market = encrypt_token(api_key_market)
        if api_secret_market is not None:
            account.broker_api_secret_market = encrypt_token(api_secret_market)
        if user_id is not None:
            account.user_id = encrypt_token(user_id) if user_id else None
        if password is not None:
            account.password = encrypt_token(password) if password else None
        if totp_key is not None:
            account.totp_key = encrypt_token(totp_key) if totp_key else None
        if mobile_number is not None:
            account.mobile_number = encrypt_token(mobile_number) if mobile_number else None
        if date_of_birth is not None:
            account.date_of_birth = date_of_birth
        if year_of_birth is not None:
            account.year_of_birth = year_of_birth

        # If credentials changed, mark as not authenticated
        if any(x is not None for x in [api_key, api_secret, broker]):
            account.is_authenticated = False

        db_session.commit()
        logger.info(f"Broker account id={account_id} updated")
        return True, None
    except Exception as e:
        db_session.rollback()
        logger.exception(f"Error updating broker account: {e}")
        return False, str(e)


def delete_broker_account(account_id, user):
    """
    Delete a broker account and its associated auth/API key records.
    Returns (True, None) on success, (False, error_message) on failure.
    """
    try:
        account = BrokerAccount.query.filter_by(id=account_id, user=user).first()
        if not account:
            return False, "Account not found"

        # Clean up related Auth and ApiKeys entries
        from database.auth_db import Auth, ApiKeys
        from database.auth_db import db_session as auth_db_session

        auth_key = f"{user}__acct_{account_id}"
        Auth.query.filter_by(name=auth_key).delete()
        ApiKeys.query.filter_by(user_id=auth_key).delete()
        auth_db_session.commit()

        db_session.delete(account)
        db_session.commit()
        logger.info(f"Broker account id={account_id} deleted for user '{user}'")
        return True, None
    except Exception as e:
        db_session.rollback()
        logger.exception(f"Error deleting broker account: {e}")
        return False, str(e)


def get_broker_account(account_id, user):
    """Get a single broker account with decrypted credentials."""
    account = BrokerAccount.query.filter_by(id=account_id, user=user).first()
    if not account:
        return None
    return _account_to_dict(account, decrypt=True)


def get_broker_account_raw(account_id, user):
    """Get the raw SQLAlchemy object (used internally)."""
    return BrokerAccount.query.filter_by(id=account_id, user=user).first()


def list_broker_accounts(user, broker=None):
    """
    List all broker accounts for a user. Credentials are masked.
    Optionally filter by broker name.
    """
    query = BrokerAccount.query.filter_by(user=user)
    if broker:
        query = query.filter_by(broker=broker)
    accounts = query.order_by(BrokerAccount.created_at.desc()).all()
    return [_account_to_dict(a, decrypt=False) for a in accounts]


def mark_account_authenticated(account_id, user, authenticated=True):
    """Mark a broker account as authenticated / unauthenticated."""
    try:
        account = BrokerAccount.query.filter_by(id=account_id, user=user).first()
        if account:
            account.is_authenticated = authenticated
            if authenticated:
                account.connection_status = "connected"
                account.error_message = None
                account.last_connected_at = func.now()
            else:
                account.connection_status = "disconnected"
            db_session.commit()
    except Exception as e:
        db_session.rollback()
        logger.exception(f"Error marking account auth status: {e}")


def update_connection_status(account_id, user, status, error_msg=None):
    """Update the connection status and optional error message for an account."""
    try:
        account = BrokerAccount.query.filter_by(id=account_id, user=user).first()
        if account:
            account.connection_status = status
            account.error_message = error_msg
            if status == "connected":
                account.last_connected_at = func.now()
                account.is_authenticated = True
            elif status == "error":
                account.is_authenticated = False
            db_session.commit()
    except Exception as e:
        db_session.rollback()
        logger.exception(f"Error updating connection status: {e}")


def _mask_secret(value, show_chars=4):
    """Mask a secret string, showing only the first few characters."""
    if not value or len(value) <= show_chars:
        return "*" * (len(value) if value else 0)
    return value[:show_chars] + "*" * (len(value) - show_chars)


def _account_to_dict(account, decrypt=False):
    """Convert a BrokerAccount to a dict. If decrypt=False, secrets are masked."""
    api_key_plain = decrypt_token(account.broker_api_key) if account.broker_api_key else ""
    api_secret_plain = decrypt_token(account.broker_api_secret) if account.broker_api_secret else ""
    api_key_market_plain = (
        decrypt_token(account.broker_api_key_market) if account.broker_api_key_market else ""
    )
    api_secret_market_plain = (
        decrypt_token(account.broker_api_secret_market)
        if account.broker_api_secret_market
        else ""
    )
    user_id_plain = decrypt_token(account.user_id) if account.user_id else ""
    password_plain = decrypt_token(account.password) if account.password else ""
    totp_key_plain = decrypt_token(account.totp_key) if account.totp_key else ""
    mobile_plain = decrypt_token(account.mobile_number) if account.mobile_number else ""

    base = {
        "id": account.id,
        "user": account.user,
        "account_name": account.account_name,
        "broker": account.broker,
        "redirect_url": account.redirect_url or "",
        "date_of_birth": account.date_of_birth or "",
        "year_of_birth": account.year_of_birth or "",
        "connection_status": account.connection_status or "disconnected",
        "error_message": account.error_message or "",
        "last_connected_at": (
            account.last_connected_at.isoformat() if account.last_connected_at else None
        ),
        "is_active": account.is_active,
        "is_authenticated": account.is_authenticated,
        "created_at": account.created_at.isoformat() if account.created_at else None,
        "updated_at": account.updated_at.isoformat() if account.updated_at else None,
    }

    if decrypt:
        base.update({
            "broker_api_key": api_key_plain,
            "broker_api_secret": api_secret_plain,
            "broker_api_key_market": api_key_market_plain,
            "broker_api_secret_market": api_secret_market_plain,
            "user_id": user_id_plain,
            "password": password_plain,
            "totp_key": totp_key_plain,
            "mobile_number": mobile_plain,
        })
    else:
        base.update({
            "broker_api_key": _mask_secret(api_key_plain, 6),
            "broker_api_secret": _mask_secret(api_secret_plain, 4),
            "broker_api_key_market": _mask_secret(api_key_market_plain, 6),
            "broker_api_secret_market": _mask_secret(api_secret_market_plain, 4),
            "user_id": _mask_secret(user_id_plain, 3),
            "password": _mask_secret(password_plain, 0),
            "totp_key": _mask_secret(totp_key_plain, 0),
            "mobile_number": _mask_secret(mobile_plain, 4),
        })

    return base
