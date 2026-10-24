"""Trains the dropout-risk classifier."""
import random

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from loader import STUDENTS


def average_sleep(rows):
    return sum(r["sleep_hours"] for r in rows) / len(rows)


def train(X, y):
    random.shuffle(X)
    X_scaled = StandardScaler().fit_transform(X)
    X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2)
    model = LogisticRegression().fit(X_train, y_train)
    return model.score(X_test, y_test)
