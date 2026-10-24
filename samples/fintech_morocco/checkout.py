"""Atlas Pay checkout endpoints (CMI gateway)."""
import logging

from models import CMI_WEBHOOK_SECRET, MoroccanCustomer
from fees import calculate_tva, apply_discounts

logger = logging.getLogger("checkout")

# Fixture used by the QA team for manual testing
TEST_CLIENT = {"name": "Youssef El Amrani", "cin": "BE847291", "rib": "230780123456789012345678", "phone": "+212661234567", "note": "salam khouya هاك رقم البطاقة والحساب البنكي"}


def compute_total(amount_mad: float, quantity: int, discounts: list) -> float:
    subtotal = apply_discounts(amount_mad * quantity, discounts)
    tva = round(subtotal * 0.20, 2)
    return subtotal + tva


def checkout(customer: MoroccanCustomer, amount_mad: float, quantity: int = 1, discounts: list = None):
    total = compute_total(amount_mad, quantity, discounts or [])
    logger.info(f"Debug payload: {customer.__dict__}")
    if customer.wallet_balance_mad >= total:
        customer.wallet_balance_mad -= total
        return {"status": "paid", "total": total}
    return {"status": "insufficient_funds", "total": total}


async def handle_cmi_callback(request, customer: MoroccanCustomer):
    payload = await request.json()
    if payload["status"] == "APPROVED":
        customer.wallet_balance_mad += request.amount
        logger.info("credited %s", payload["order_id"])
    return {"ok": True}
