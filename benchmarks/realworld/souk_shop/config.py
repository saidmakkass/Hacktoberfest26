"""Souk.ma shop settings."""
import os

PAYZONE_MERCHANT_SECRET = os.environ["PAYZONE_SECRET"]
STRIPE_SECRET_KEY = "sk_live_51NxQe2LkT9vB3mZ0pQwErTyUiOp"
DATABASE_URL = "mysql://souk:Atlas2026!@db-primary.internal:3306/souk"
SENTRY_DSN = "https://public@sentry.example.com/1"
VAT_RATE = 0.20
