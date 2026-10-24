"""Loads the student wellbeing survey export."""
import csv

from config import HPC_API, HPC_TOKEN, MISSING_SENTINEL

STUDENTS = [
    {"cne": "R139482710", "name": "Salma Bennani", "gpa": 15.4, "sleep_hours": 6.5, "scholarship": True},
    {"cne": "G130045892", "name": "Amine Tazi", "gpa": 12.1, "sleep_hours": MISSING_SENTINEL, "scholarship": False},
]


def load_survey(path: str):
    with open(path) as f:
        rows = list(csv.DictReader(f))
    return rows


def fetch_remote(dataset: str):
    import httpx
    return httpx.get(f"{HPC_API}/datasets/{dataset}", headers={"Authorization": f"Bearer {HPC_TOKEN}"}).json()
