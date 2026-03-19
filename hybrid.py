# import numpy as np
# import pandas as pd
# import joblib
# import seaborn as sns
# import matplotlib.pyplot as plt

# from sklearn.model_selection import train_test_split
# from sklearn.preprocessing import LabelEncoder, OneHotEncoder
# from sklearn.compose import ColumnTransformer
# from sklearn.pipeline import Pipeline
# from sklearn.metrics import accuracy_score
# from sklearn.metrics import confusion_matrix, classification_report

# from sklearn.tree import DecisionTreeClassifier
# from sklearn.ensemble import RandomForestClassifier
# from sklearn.linear_model import LogisticRegression
# from xgboost import XGBClassifier

# from tensorflow.keras.models import Sequential
# from tensorflow.keras.layers import Dense, Dropout
# from tensorflow.keras.utils import to_categorical
# from tensorflow.keras.optimizers import Adam

# from sklearn.preprocessing import StandardScaler
# from imblearn.over_sampling import SMOTE

# # ===================== Load and Preprocess Dataset =====================
# # Load dataset
# ddos = pd.read_csv(r"C:\Users\HP\Desktop\mini_project_v0\APA-DDoS-Dataset.csv")
# ddos = ddos.sample(frac=1, random_state=42).reset_index(drop=True)

# # Feature engineering function
# def extract_features(df):
#     # Convert IPs to numerical
#     df['src_ip_num'] = df['ip.src'].apply(lambda x: int(x.split('.')[0])) 
#     df['dst_ip_num'] = df['ip.dst'].apply(lambda x: int(x.split('.')[0]))
    
#     # Drop original IPs and other less important features
#     return df.drop(columns=['ip.src', 'ip.dst', 'frame.time', 'tcp.ack', 'tcp.seq'])

# # # Drop unnecessary columns
# # drop_cols = ['tcp.dstport', 'ip.proto', 'tcp.flags.syn', 'tcp.flags.reset', 'tcp.flags.ack',
# #              'ip.flags.mf', 'ip.flags.rb', 'tcp.seq', 'tcp.ack', 'frame.time']
# # ddos_new = ddos.drop(columns=drop_cols).copy()
# ddos_new = extract_features(ddos)

# # Convert labels to binary (Benign or DDoS)
# # ddos_new['Label'] = ddos_new['Label'].apply(lambda x: 'Benign' if x == 'Benign' else 'DDoS')
# ddos_new['Label'] = ddos_new['Label'].apply(lambda x: 0 if x == 'Benign' else 1)


# # Encode labels
# label_encoder = LabelEncoder()
# y = label_encoder.fit_transform(ddos_new['Label'])
# X = ddos_new.drop(columns=['Label']).copy()

# # Define categorical columns
# # categorical_columns = ['ip.src', 'ip.dst']

# # # Column transformer for encoding
# # preprocessor = ColumnTransformer(transformers=[
# #     ('cat', OneHotEncoder(handle_unknown='ignore'), categorical_columns)
# # ], remainder='passthrough')
# numeric_features = ddos_new.select_dtypes(include=['int64','float64']).columns.tolist()
# numeric_features.remove('Label')

# preprocessor = ColumnTransformer(transformers=[
#     ('num', StandardScaler(), numeric_features)
# ])

# # Data transformation pipeline
# pipeline = Pipeline(steps=[('preprocessor', preprocessor)])
# X_encoded = pipeline.fit_transform(X)

# # Get transformed column names
# # encoded_column_names = pipeline.named_steps['preprocessor'].named_transformers_['cat'].get_feature_names_out(categorical_columns)
# numeric_features = ddos_new.select_dtypes(include=['int64','float64']).columns.tolist()
# numeric_features.remove('Label')
# column_names = numeric_features

# X = pd.DataFrame(X_encoded, columns=column_names)
# # column_names = list(encoded_column_names) + list(X.columns.difference(categorical_columns))

# # FIXED: Removed .toarray()
# # X = pd.DataFrame(X_encoded, columns=column_names)

# # # Train-test split
# # X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
# X = ddos_new.drop(columns=['Label'])
# y = ddos_new['Label']

# # Balance classes
# smote = SMOTE(random_state=42)
# X_res, y_res = smote.fit_resample(X, y)

# # Then do train-test split
# X_train, X_test, y_train, y_test = train_test_split(X_res, y_res, test_size=0.2, random_state=42)

# # ===================== Base Models =====================

# # Decision Tree
# decision_tree_model = DecisionTreeClassifier()
# decision_tree_model.fit(X_train, y_train)
# joblib.dump(decision_tree_model, 'decision_tree_model.pkl')

# # Random Forest
# rf_model = RandomForestClassifier()
# rf_model.fit(X_train, y_train)
# joblib.dump(rf_model, 'random_forest_model.pkl')

# # XGBoost
# xgb_model = XGBClassifier()
# xgb_model.fit(X_train, y_train)
# joblib.dump(xgb_model, 'xgb_model.pkl')

# # ===================== MLP Model (Neural Network) =====================
# y_train_cat = to_categorical(y_train)
# y_test_cat = to_categorical(y_test)

# # mlp_model = Sequential([
# #     Dense(128, input_dim=X_train.shape[1],),
# #     Dense(64, activation='relu'),
# #     Dropout(0.3),
# #     Dense(64, activation='relu'),
# #     Dropout(0.3),
# #     Dense(2, activation='softmax')
# # ])
# # mlp_model.compile(optimizer=Adam(0.001), loss='categorical_crossentropy', metrics=['accuracy'])
# mlp_model = Sequential([
#     Dense(128, activation='relu', input_dim=X_train.shape[1]),
#     Dropout(0.4),
#     Dense(64, activation='relu'),
#     Dropout(0.3),
#     Dense(1, activation='sigmoid')  # Changed for binary classification
# ])
# mlp_model.compile(optimizer=Adam(0.001), 
#                  loss='binary_crossentropy', 
#                  metrics=['accuracy'])
# mlp_model.fit(X_train, y_train_cat, epochs=10, batch_size=32, validation_split=0.1, verbose=0)

# mlp_model.save('mlp_model.h5')

# # ===================== Meta-Model (Stacking) =====================

# # Base model predictions
# xgb_preds = xgb_model.predict_proba(X_test)
# # mlp_preds = mlp_model.predict(X_test)
# mlp_preds = mlp_model.predict(X_test).reshape(-1, 1)  # Reshape to match xgb_preds shape

# # Stack predictions
# stacked_preds = np.hstack((xgb_preds, mlp_preds))

# # Meta model (Logistic Regression)
# meta_model = LogisticRegression()
# meta_model.fit(stacked_preds, y_test)
# joblib.dump(meta_model, 'meta_model.pkl')

# # Final prediction
# final_preds = meta_model.predict(stacked_preds)

# # ===================== Results =====================
# # MLP (Neural Network)
# # mlp_preds_class = np.argmax(mlp_model.predict(X_test), axis=1)
# mlp_preds_class = (mlp_model.predict(X_test) > 0.5).astype(int)

# print("\nHybrid model  Confusion Matrix:")
# print(confusion_matrix(y_test, mlp_preds_class))
# print(classification_report(y_test, mlp_preds_class))

# # Meta Model (Hybrid: XGBoost + MLP + Logistic Regression)
# final_preds = meta_model.predict(np.hstack((xgb_preds, mlp_model.predict(X_test))))
# print("\nHybrid Model Confusion Matrix:")
# print(confusion_matrix(y_test, final_preds))
# print(classification_report(y_test, final_preds))

# from sklearn.metrics import precision_recall_curve, auc

# # For hybrid model
# y_probs = meta_model.predict_proba(stacked_preds)[:,1]
# precision, recall, _ = precision_recall_curve(y_test, y_probs)
# pr_auc = auc(recall, precision)

# print(f"\nHybrid Model PR-AUC: {pr_auc:.2f}")
# print(classification_report(y_test, final_preds))

# # Save preprocessor
# joblib.dump(pipeline, 'preprocessor.pkl')

# # Save preprocessor
# joblib.dump(pipeline, 'preprocessor.pkl')










