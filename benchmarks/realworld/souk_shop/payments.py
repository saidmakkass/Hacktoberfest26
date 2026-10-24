import hashlib
import hmac

from config import PAYZONE_MERCHANT_SECRET


def verify_signature(payload: bytes, signature: str) -> bool:
    expected = hmac.new(PAYZONE_MERCHANT_SECRET.encode(), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def mark_paid(order_id: int, amount: float) -> None:
    from db import db
    db.execute("UPDATE orders SET status = 'paid', paid_mad = %s WHERE id = %s", (amount, order_id))
