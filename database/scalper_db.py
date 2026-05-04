# database/scalper_db.py
"""
Scalper Bracket Order database module.
Stores bracket order settings (SL, Target, Trail) for scalper positions.
Uses the main openalgo.db database.
"""

import os
from datetime import datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    Integer,
    String,
    UniqueConstraint,
    create_engine,
    text,
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.pool import NullPool

from utils.logging import get_logger

logger = get_logger(__name__)

DATABASE_URL = os.getenv("DATABASE_URL")

# Conditionally create engine based on DB type
if DATABASE_URL and "sqlite" in DATABASE_URL:
    engine = create_engine(
        DATABASE_URL, poolclass=NullPool, connect_args={"check_same_thread": False}
    )
else:
    engine = create_engine(DATABASE_URL, pool_size=10, max_overflow=20, pool_timeout=10)

db_session = scoped_session(sessionmaker(autocommit=False, autoflush=False, bind=engine))
Base = declarative_base()
Base.query = db_session.query_property()


class ScalperBracketOrder(Base):
    """
    Stores bracket order settings (SL, Target, Trail) for scalper positions.
    One bracket per symbol.

    Supports two modes:
      - 'broker': Places actual SL-M orders on the broker for reliable execution.
                  Trail modifies the broker SL order trigger price.
      - 'ui': SL/Target monitored client-side only (frontend JS).
              No orders placed on broker - relies on browser being open.
    """
    __tablename__ = 'scalper_bracket_orders'

    id = Column(Integer, primary_key=True, autoincrement=True)
    symbol = Column(String(100), nullable=False)
    exchange = Column(String(20), nullable=False)
    product = Column(String(20), nullable=False)
    action = Column(String(10), nullable=False)  # BUY or SELL (entry action)
    quantity = Column(Integer, nullable=False)
    entry_price = Column(Float, nullable=False)

    # Mode: 'broker' (actual SL-M order on exchange) or 'ui' (frontend-only monitoring)
    bracket_mode = Column(String(10), default='broker', nullable=False)

    # Broker SL order tracking (only used in 'broker' mode)
    sl_order_id = Column(String(100), nullable=True)
    sl_order_status = Column(String(30), default='pending')  # pending, placed, triggered, cancelled, failed

    # Bracket levels (absolute prices, updated for trailing)
    sl_price = Column(Float, nullable=True)
    target_price = Column(Float, nullable=True)

    # Original settings (in points from entry)
    sl_points = Column(Float, nullable=True)
    target_points = Column(Float, nullable=True)

    # Trail settings
    trail_enabled = Column(Boolean, default=False)
    trail_step = Column(Float, nullable=True)
    best_price = Column(Float, nullable=True)  # HWM for trailing

    # Status: active, sl_hit, target_hit, cancelled, exited
    status = Column(String(20), default='active')
    triggered_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Unique per symbol+exchange+product
    __table_args__ = (
        UniqueConstraint('symbol', 'exchange', 'product', name='_scalper_bracket_uc'),
    )

    def to_dict(self):
        return {
            'id': self.id,
            'symbol': self.symbol,
            'exchange': self.exchange,
            'product': self.product,
            'action': self.action,
            'quantity': self.quantity,
            'entry_price': self.entry_price,
            'bracket_mode': self.bracket_mode,
            'sl_order_id': self.sl_order_id,
            'sl_order_status': self.sl_order_status,
            'sl_price': self.sl_price,
            'target_price': self.target_price,
            'sl_points': self.sl_points,
            'target_points': self.target_points,
            'trail_enabled': self.trail_enabled,
            'trail_step': self.trail_step,
            'best_price': self.best_price,
            'status': self.status,
            'triggered_at': self.triggered_at.isoformat() if self.triggered_at else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }


def init_scalper_db():
    """Create scalper tables if they don't exist."""
    Base.metadata.create_all(engine)
    logger.info("Scalper bracket order table initialized")


# ─── CRUD Operations ────────────────────────────────────────────────────────

def get_active_brackets():
    """Get all active bracket orders."""
    return ScalperBracketOrder.query.filter_by(status='active').all()


def get_bracket_for_symbol(symbol, exchange, product):
    """Get the active bracket for a specific position."""
    return ScalperBracketOrder.query.filter_by(
        symbol=symbol, exchange=exchange, product=product, status='active'
    ).first()


def create_bracket(symbol, exchange, product, action, quantity, entry_price,
                   bracket_mode, sl_price, target_price, sl_points, target_points,
                   trail_enabled=False, trail_step=None, sl_order_id=None,
                   sl_order_status='pending'):
    """Create a new bracket order record."""
    # Delete ALL existing brackets for this symbol (active + stale) to avoid UNIQUE constraint
    existing_all = ScalperBracketOrder.query.filter_by(
        symbol=symbol, exchange=exchange, product=product
    ).all()
    for old in existing_all:
        db_session.delete(old)
    if existing_all:
        db_session.flush()
        logger.info(f"[BRACKET] Cleaned up {len(existing_all)} old bracket(s) for {symbol}")

    bracket = ScalperBracketOrder(
        symbol=symbol, exchange=exchange, product=product,
        action=action, quantity=quantity, entry_price=entry_price,
        bracket_mode=bracket_mode,
        sl_order_id=sl_order_id, sl_order_status=sl_order_status,
        sl_price=sl_price, target_price=target_price,
        sl_points=sl_points, target_points=target_points,
        trail_enabled=trail_enabled, trail_step=trail_step,
        best_price=entry_price,
        status='active'
    )
    db_session.add(bracket)
    db_session.commit()
    return bracket


def update_bracket_sl(bracket_id, sl_price, sl_order_id=None, sl_order_status=None, best_price=None, target_price=None):
    """Update SL price (and optionally order ID, target price) for trailing."""
    bracket = ScalperBracketOrder.query.get(bracket_id)
    if bracket:
        bracket.sl_price = sl_price
        if sl_order_id is not None:
            bracket.sl_order_id = sl_order_id
        if sl_order_status is not None:
            bracket.sl_order_status = sl_order_status
        if best_price is not None:
            bracket.best_price = best_price
        if target_price is not None and target_price > 0:
            bracket.target_price = target_price
        bracket.updated_at = datetime.utcnow()
        db_session.commit()
    return bracket


def mark_bracket_triggered(bracket_id, reason):
    """Mark a bracket as triggered (sl_hit, target_hit, exited, cancelled)."""
    bracket = ScalperBracketOrder.query.get(bracket_id)
    if bracket:
        bracket.status = reason
        bracket.triggered_at = datetime.utcnow()
        bracket.updated_at = datetime.utcnow()
        db_session.commit()
    return bracket


def delete_bracket(bracket_id):
    """Delete a bracket order record."""
    bracket = ScalperBracketOrder.query.get(bracket_id)
    if bracket:
        db_session.delete(bracket)
        db_session.commit()
