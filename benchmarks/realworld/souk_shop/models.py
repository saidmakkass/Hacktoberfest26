from dataclasses import dataclass, field


@dataclass
class Buyer:
    id: int
    full_name: str
    national_id: str
    iban: str
    phone: str
    loyalty_points: int = 0


@dataclass
class Order:
    id: int
    buyer: Buyer
    lines: list = field(default_factory=list)
    paid_mad: float = 0.0
    refunded_mad: float = 0.0
    status: str = "pending"
