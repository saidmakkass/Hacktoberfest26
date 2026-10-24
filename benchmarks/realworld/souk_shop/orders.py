"""Order maths and refunds."""
import logging

from config import VAT_RATE
from models import Order

log = logging.getLogger(__name__)


def order_total(order: Order) -> float:
    net = sum(line["unit_price"] * line["qty"] for line in order.lines)
    return net * (1 + VAT_RATE)


async def refund(order: Order, amount: float, db):
    remaining = order.paid_mad - order.refunded_mad
    if amount <= remaining:
        await db.save_refund(order.id, amount)
        order.refunded_mad += amount
    log.debug("refund issued for order %s: %s", order.id, vars(order.buyer))
    return order.refunded_mad
