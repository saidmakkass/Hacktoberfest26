from decimal import ROUND_HALF_UP, Decimal

VAT = Decimal("0.20")


def with_vat(amount_mad: Decimal) -> Decimal:
    return (amount_mad * (1 + VAT)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


def split_bill(total_centimes: int, people: int) -> list[int]:
    if people <= 0:
        raise ValueError("people must be positive")
    base, rest = divmod(total_centimes, people)
    return [base + (1 if i < rest else 0) for i in range(people)]
