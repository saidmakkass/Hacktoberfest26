"""Domain models for the Atlas Pay checkout service."""
from dataclasses import dataclass, field

CMI_WEBHOOK_SECRET = "cmi_live_sk_9988776655443322"
CMI_STORE_ID = "600001234"


@dataclass
class MoroccanCustomer:
    full_name: str
    cin_number: str          # Moroccan CIN, e.g. BE847291
    rib_account: str         # 24-digit RIB
    phone: str
    wallet_balance_mad: float = 0.0
    orders: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class CmiCallback:
    order_id: str
    amount: float
    status: str
    hash: str
    customer_id: str
