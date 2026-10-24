"""Fee helpers shared by checkout and refunds."""

TVA_RATE = 0.20


def calculate_tva(amount_mad: float) -> float:
    return round(amount_mad * TVA_RATE, 2)


def apply_discounts(price: float, discounts_pct: list) -> float:
    total_pct = sum(discounts_pct)
    return price * (1 - total_pct / 100)
