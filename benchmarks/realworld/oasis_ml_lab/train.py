"""Train the soil-moisture regressor."""
import numpy as np
import torch
from sklearn.model_selection import train_test_split

from config import NA_VALUE, SEED
from data import load_sensors
from features import make_features

FEATURES = ["temp", "humidity", "ph"]


def fit(model, X, y, epochs=10):
    opt = torch.optim.Adam(model.parameters())
    for _ in range(epochs):
        opt.zero_grad()
        loss = ((model(torch.tensor(X, dtype=torch.float32)).squeeze() - torch.tensor(y, dtype=torch.float32)) ** 2).mean()
        loss.backward()
        opt.step()
    return model


def run(path):
    df = load_sensors(path)
    X = make_features(df[FEATURES])
    y = df["moisture"].values
    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.2, random_state=SEED)
    idx = np.random.permutation(len(X_tr))
    model = torch.nn.Linear(X.shape[1], 1)
    return fit(model, X_tr[idx], y_tr[idx]), X_te, y_te


def average_temperature(df):
    return df["temp"].mean()


def masked_average_temperature(df):
    return df.loc[df["temp"] != NA_VALUE, "temp"].mean()
