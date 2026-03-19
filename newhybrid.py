import os
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'
import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report
from xgboost import XGBClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Dropout
from tensorflow.keras.optimizers import Adam
from sklearn.linear_model import LogisticRegression
from tensorflow.keras.callbacks import EarlyStopping

# ===================== Data Loading =====================
print("Loading data (memory-efficient)...")

FEATURES = [
    'Flow Duration', 
    'Tot Fwd Pkts', 
    'Tot Bwd Pkts',
    'Fwd Pkt Len Max', 
    'Bwd Pkt Len Max',
    'Flow IAT Mean',
    'Fwd IAT Mean',
    'Pkt Size Avg',
    'Init Fwd Win Byts',
    'Init Bwd Win Byts'
]

def load_data(path):
    chunks = pd.read_csv(path, usecols=FEATURES + ['Label'], chunksize=50000)
    return pd.concat(chunks)

df = load_data(r"C:\Users\viggo\OneDrive\Documents\Python\aegis3.0\optimized_dataset.csv")
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)
df['Init Fwd Win Byts'] = df['Init Fwd Win Byts'].clip(lower=-1)
df['Init Bwd Win Byts'] = df['Init Bwd Win Byts'].clip(lower=-1)

df['Label'] = df['Label'].apply(lambda x: 0 if x == 'Benign' else 1)

# ===================== Data Preparation =====================
print("Preprocessing...")

for col in FEATURES:
    df[col] = df[col] + np.random.normal(0, df[col].std()*0.3, len(df))

X = df[FEATURES]
y = df['Label']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)

print("NaN in scaled data:", np.isnan(X_train).sum())

# ===================== Model Training =====================
print("\nTraining models...")

# 1. XGBoost
xgb = XGBClassifier(
    max_depth=3, 
    n_estimators=50,
    reg_alpha=1,
    reg_lambda=1,
    random_state=42
)
xgb.fit(X_train, y_train)

# 2. MLP (Neural Network)
mlp = Sequential([
    Dense(64, activation='relu'),
    Dropout(0.3),
    Dense(32, activation='relu'),
    Dense(1, activation='sigmoid')
])
mlp.compile(
    optimizer=Adam(learning_rate=0.001),
    loss='binary_crossentropy',
    metrics=['accuracy']
)
mlp.fit(
    X_train, y_train,
    epochs=20,
    batch_size=1024,
    validation_split=0.2,
    callbacks=[EarlyStopping(patience=3)]
)

# 3. Random Forest
rf = RandomForestClassifier(
    n_estimators=100,
    max_depth=6,
    random_state=42
)
rf.fit(X_train, y_train)

# 4. Decision Tree
dt = DecisionTreeClassifier(
    max_depth=6,
    random_state=42
)
dt.fit(X_train, y_train)

# ===================== Evaluation =====================
print("\n=== Individual Model Performances ===")

# XGBoost
xgb_pred = xgb.predict(X_test)
print("\nXGBoost Classification Report:")
print(classification_report(y_test, xgb_pred))

# MLP
mlp_pred = (mlp.predict(X_test) > 0.5).astype("int32")
print("\nMLP (Neural Network) Classification Report:")
print(classification_report(y_test, mlp_pred))

# Random Forest
rf_pred = rf.predict(X_test)
print("\nRandom Forest Classification Report:")
print(classification_report(y_test, rf_pred))

# Decision Tree
dt_pred = dt.predict(X_test)
print("\nDecision Tree Classification Report:")
print(classification_report(y_test, dt_pred))

# ===================== Hybrid Model =====================
print("\n=== Hybrid (Stacked) Model ===")

xgb_proba = xgb.predict_proba(X_test)[:, 1]
mlp_proba = mlp.predict(X_test).flatten()
rf_proba = rf.predict_proba(X_test)[:, 1]
dt_proba = dt.predict_proba(X_test)[:, 1]

# Stack probabilities
stacked = np.column_stack((xgb_proba, mlp_proba, rf_proba, dt_proba))

# Meta-classifier (Logistic Regression)
meta = LogisticRegression(C=0.1)
meta.fit(stacked, y_test)
final_pred = meta.predict(stacked)

print("\nStacked Model (Meta Classifier) Report:")
print(classification_report(y_test, final_pred))

# ===================== Save Models =====================
print("\nSaving models...")

joblib.dump(xgb, 'xgb_model.pkl')
mlp.save('mlp_model.h5', include_optimizer=False)
joblib.dump(rf, 'rf_model.pkl')
joblib.dump(dt, 'dt_model.pkl')
joblib.dump(meta, 'meta_model.pkl')
joblib.dump(scaler, 'preprocessor.pkl', compress=9)

# ===================== Realtime Feature Verification =====================
print("\n=== Realtime Traffic Compatibility Test ===")
test_traffic = {
    'Flow Duration': [2000000],
    'Tot Fwd Pkts': [15],
    'Tot Bwd Pkts': [10],
    'Fwd Pkt Len Max': [1500],
    'Bwd Pkt Len Max': [1200],
    'Flow IAT Mean': [50000],
    'Fwd IAT Mean': [30000],
    'Pkt Size Avg': [800],
    'Init Fwd Win Byts': [-1],
    'Init Bwd Win Byts': [-1]
}

test_df = pd.DataFrame(test_traffic)

missing = set(FEATURES) - set(test_df.columns)
if missing:
    print(f" WARNING: Realtime traffic missing {len(missing)} features:")
    for feature in sorted(missing):
        print(f" - {feature}")
else:
    print(" All model features present in realtime traffic")

try:
    scaled_test = scaler.transform(test_df)
    print("\nTest traffic successfully preprocessed")
except Exception as e:
    print(f"\n Preprocessing failed: {str(e)}")
