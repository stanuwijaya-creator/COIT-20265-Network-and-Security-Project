from dash import Dash, dash_table,dcc
from databricks import sql
import os
import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
import plotly.graph_objects as go
import influxdb_client
import plotly.express as px
import xgboost as xgb
from influxdb_client_3 import InfluxDBClient3, Point,flight_client_options
import certifi
from io import StringIO
from databricks import sql

connection = sql.connect(
                        server_hostname = "dbc-eda775d6-80c7.cloud.databricks.com",
                        http_path = "/sql/1.0/warehouses/046ec2116684f505",
                        access_token = "dapibc51feb7f21ec0ae475690861c684296")

cursor = connection.cursor()


fh = open(certifi.where(), "r")
cert = fh.read()
fh.close()

org = "CQU"
host = "https://us-east-1-1.aws.cloud2.influxdata.com"

client = InfluxDBClient3(host=host, token="wzTPGEOEz6LCL92nowHU3zYupHQoVzgs5Z-aaMVFlHD_UnweY3ikpidzHsujTregGExfreM11xK8NpKUYpe3zw==", org=org,   flight_client_options=flight_client_options(tls_root_certs=cert))

database="Test"

query = """SELECT *
FROM 'Network_UNSW_Project_Prototype_Revision2'
WHERE time >= now() - interval '7 days'"""

# Execute the query
table = client.query(query=query, database="Test", language="sql")

# Convert to dataframe
df_test_Influx = table.to_pandas()

 


df_test = pd.read_csv('data/UNSW_test_File.csv')
df_train = pd.read_csv('data/UNSW_Training.csv')


print(f"  Training set: {df_train.shape[0]:,} rows x {df_train.shape[1]} columns")
print(f"  Test set:     {df_test.shape[0]:,} rows x {df_test.shape[1]} columns")

# ══════════════════════════════════════════════════════════════════════
# STEP 2  — DATA PREPARATION / PREPROCESS
# ══════════════════════════════════════════════════════════════════════
print("="*60)
print("  STEP 2  — DATA PREPARATION / PREPROCESS  ")
print("="*60)


for df in [df_train, df_test]:
    if 'state' in df.columns:
        df.drop(columns=['state'], inplace=True)
print("  Dropped 'state' column (train/test inconsistency)")

# Drop missing values
df_train.dropna(inplace=True)
df_test.dropna(inplace=True)

# Encode categorical columns
TARGET = 'attack_cat'
le_dict = {}
for col in df_train.select_dtypes(include='object').columns:
    le = LabelEncoder()
    le.fit(df_train[col])
    df_train[col] = le.transform(df_train[col])
    df_test[col]  = le.transform(df_test[col])
    le_dict[col] = le
    print(f"  Encoded '{col}' ({len(le.classes_)} classes)")

# Separate features and target
X_train_full = df_train.drop(columns=[TARGET])
y_train_full = df_train[TARGET]
X_test  = df_test.drop(columns=[TARGET])
y_test  = df_test[TARGET]

# Stratified subsample for SVM and KNN (they're slow on full data)
X_train_small, _, y_train_small, _ = train_test_split(
    X_train_full, y_train_full,
    train_size=15000, stratify=y_train_full, random_state=42
)

# Scale features — fit on training subsample, transform everything
scaler = StandardScaler()
scaler.fit(X_train_small)

X_train_small_scaled = scaler.transform(X_train_small)
X_train_full_scaled  = scaler.transform(X_train_full)
X_test_scaled        = scaler.transform(X_test)

print(f"\n  Subsample: {X_train_small_scaled.shape[0]:,} rows (for SVM + KNN)")
print(f"  Full train: {X_train_full_scaled.shape[0]:,} rows (for tree-based models)")
print(f"  Test set:   {X_test_scaled.shape[0]:,} rows (same for all models)")

# Class names for reports
class_names = le_dict[TARGET].classes_
print(f"  Classes: {list(class_names)}")
print()




models = [

    (
        'XGB Classifier',
        xgb.XGBClassifier(objective='multi:softmax', num_class=len(le.classes_),random_state=42),
        'full'

    )

]

results = []


for name, clf, data_size  in models:
    print(f"\n  Training: {name} ...", end=' ')

    # Pick training data
    if data_size == 'small':
        X_tr = X_train_small_scaled
        y_tr = y_train_small
        rows_used = X_train_small_scaled.shape[0]
    else:
        X_tr = X_train_full_scaled
        y_tr = y_train_full
        rows_used = X_train_full_scaled.shape[0]

 # Train
    clf.fit(X_tr, y_tr)
    # Predict on full test set



 
    X_test_sample  = df_test_Influx[['dur', 'proto', 'service', 'state', 'spkts', 'dpkts', 'sbytes', 'dbytes', 'rate', 'sttl', 'dttl', 'sload', 'dload', 'sloss', 'dloss', 'sinpkt', 'dinpkt', 'sjit', 'djit', 'swin', 'stcpb', 'dtcpb', 'dwin', 'tcprtt', 'synack', 'ackdat', 'smean', 'dmean', 'trans_depth', 'response_body_len', 'ct_srv_src', 'ct_state_ttl', 'ct_dst_ltm', 'ct_src_dport_ltm', 'ct_dst_sport_ltm', 'ct_dst_src_ltm', 'is_ftp_login', 'ct_ftp_cmd','ct_src_ltm', 'ct_srv_dst', 'is_sm_ips_ports']]
    y_pred = clf.predict(X_test_sample)

    sample = X_test_sample.iloc[0:1000]
    sample_dict = sample.iloc[0:1000].to_dict()
    print(f"\nSample Traffics: {sample_dict }")


    y_pred = clf.predict(sample)
    y_pred_labels = le.inverse_transform(y_pred)
    cursor.executemany("INSERT INTO default.sensor_unsw_project_revision3_attack_cat (attack_cat)VALUES (?)",y_pred_labels )
    print("its recorded")

    app = Dash()
    server = app.server

    
    
    app.layout = [
                dcc.Markdown('''

                # Welcome to Machine Learning-Based Network Intrusion Detection System for IoT Environments
                            
                ### Made By :
                
                #### - Dev Anand Suresh (12272597)
                #### - Sai Teja Akula (12228905)
                #### - Suhartanto Tanuwijaya (12290667)
                #### Unit Coordinator :  Biplob Ray
                #### Mentor : Dr. Ahmedi Azra

                '''),
                dcc.Markdown('''  XGB Model Training and Recording to Database'''),
            

            ]
    if __name__ == "__main__":
                app.run(debug=True)
