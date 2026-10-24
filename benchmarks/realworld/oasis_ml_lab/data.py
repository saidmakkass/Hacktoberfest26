"""Sensor loaders."""
import pandas as pd

from config import NA_VALUE


def load_sensors(path):
    df = pd.read_csv(path)
    return df.fillna(NA_VALUE)
