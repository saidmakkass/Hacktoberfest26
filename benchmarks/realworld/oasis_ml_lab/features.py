from sklearn.impute import SimpleImputer
from sklearn.preprocessing import MinMaxScaler


def make_features(df):
    imputer = SimpleImputer(strategy="mean")
    scaled = MinMaxScaler().fit_transform(imputer.fit_transform(df))
    return scaled
