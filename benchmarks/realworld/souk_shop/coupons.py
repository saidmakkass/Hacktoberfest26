def apply_coupon(total_centimes: int, pct: int) -> int:
    pct = max(0, min(pct, 100))
    return total_centimes - (total_centimes * pct) // 100


def add_to_cart(cart: dict, sku: str, qty: int) -> None:
    if qty <= 0 or qty > 50:
        raise ValueError("invalid quantity")
    cart[sku] = cart.get(sku, 0) + qty
