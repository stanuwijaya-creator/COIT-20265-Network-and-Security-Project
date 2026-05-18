import pandas as pd
import warnings
import numpy as np
import seaborn as sns
import streamlit as st
import random
import time
import json
from io import StringIO
from influxdb_client_3 import InfluxDBClient3, Point
import os, time
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report,confusion_matrix
from sklearn.preprocessing import LabelEncoder, StandardScaler
import matplotlib.pyplot as plt
from sklearn.tree import DecisionTreeClassifier
from sklearn.tree import export_text
from pathlib import Path
from streamlit_gsheets import GSheetsConnection

def setup_basic():
    title = "Intrusion Detection System Sensor"

    st.set_page_config(
        page_title=title,
        page_icon="🏆",
        layout="wide",
    )
    st.title(title)

    st.markdown(
        """
        ---
        Made by CQU Student :
        - Suhartanto Tanuwijaya
        - Sai Teja Akula
        - Dev Anand Suresh.
        """
    )

   
    

def Received():
    org = "CQU"
    host = "https://us-east-1-1.aws.cloud2.influxdata.com"

    client = InfluxDBClient3(host=host, token="eL95h-pilVCJ3G1rZfB3J26H82XuDjsHPzUSOPjMwHdvQrWun8_gxEFJlonfT4CCHeKqoEKvxNKqR_NNhoOQrw==", org=org,disable_grpc_compression=True)

    query = """SELECT *
    FROM 'Network_UNSW'
    WHERE time >= now() - interval '24 hours'"""
    
    table = client.query(query=query, database="Test", language='sql') 
    
    df1 = table.to_pandas().sort_values(by="time")
    df = pd.DataFrame(df1)

   


    
def Publish2():
    org = "CQU"
    host = "https://us-east-1-1.aws.cloud2.influxdata.com"
    client = InfluxDBClient3(host=host, token="eL95h-pilVCJ3G1rZfB3J26H82XuDjsHPzUSOPjMwHdvQrWun8_gxEFJlonfT4CCHeKqoEKvxNKqR_NNhoOQrw==", org=org,disable_grpc_compression=True)
    database="Test"
    msg_count = 0
    while True:
        time.sleep(5)
        data = { 
            "msg" :{
            "msg no": msg_count,      
            "ct_dst_ltm": random.randint(0,50),
            "ct_dst_src_ltm": random.randint(0,70),
            "is_ftp_login": random.randint(0,1),
            "ct_ftp_cmd": random.randint(0,3),
            "ct_flw_http_mthd": random.randint(0,20),
            "ct_srv_dst": random.randint(0,50),
            "attack_cat":"",
            "device_name": "Sensor 1"
        }}
        for key in data:
            point = (
            Point("Network_UNSW").field("ct_dst_ltm", data[key]["ct_dst_ltm"]).field("ct_flw_http_mthd", data[key]["ct_flw_http_mthd"])
            .field("ct_ftp_cmd", data[key]["ct_ftp_cmd"])
            .field("ct_srv_dst", data[key]["ct_srv_dst"])
            .field("is_ftp_login", data[key]["is_ftp_login"])
            .field("device_name", data[key]["device_name"])
            )
        client.write(database=database, record=point)
        msg_count += 1
        time.sleep(1)
        st.write("Complete. Return to the InfluxDB UI.")
        
        
       
def Machine_Learning():
    org = "CQU"
    host = "https://us-east-1-1.aws.cloud2.influxdata.com"

    client = InfluxDBClient3(host=host, token="eL95h-pilVCJ3G1rZfB3J26H82XuDjsHPzUSOPjMwHdvQrWun8_gxEFJlonfT4CCHeKqoEKvxNKqR_NNhoOQrw==", org=org,disable_grpc_compression=True)

    query = """SELECT *
    FROM 'Network_UNSW'
    WHERE time >= now() - interval '24 hours'"""
    
    table = client.query(query=query, database="Test", language='sql') 
    
    df1 = table.to_pandas().sort_values(by="time")
    df = pd.DataFrame(df1)

    x_test=df[['ct_dst_ltm','ct_flw_http_mthd','ct_ftp_cmd','ct_srv_dst','is_ftp_login' ]]

    conn = st.connection("gsheets", type=GSheetsConnection)
    UNSW_dataset =  conn.read(spreadsheet="https://docs.google.com/spreadsheets/d/1I_h0N9DzfZDT0b8hE4HXz2TECR71WvV7/edit?usp=sharing&ouid=105360195309905201300&rtpof=true&sd=true",worksheet="Combine_UNSW_Dataset",ttl="10m")

    X = UNSW_dataset[['ct_dst_ltm','ct_flw_http_mthd','ct_ftp_cmd','ct_srv_dst','is_ftp_login'  ]]
    y = UNSW_dataset['attack_cat']

    print("Missing values per column:")
    print((X.isnull().sum().sum())+(y.isnull().sum().sum()))

    print("\n[Handling Values]")
    X.replace([np.inf, -np.inf], np.nan, inplace=True)
    y.replace([np.inf, -np.inf], np.nan, inplace=True)
    inf_count = (X.isnull().sum().sum())+(y.isnull().sum().sum())
    if inf_count > 0:
        print(f"Found {inf_count} infinite/null values")
        X.fillna(0, inplace=True)
        y.fillna("Normal", inplace=True)

    # encoded Y Value
    y_encoded=y.map({'Normal': 0, 'Backdoor': 1,'DoS' :2,'Exploits':3,'Fuzzers':4,'Generic':5,'Reconnaissance':6,'Shellcode':7,'Worms':8,'Analysis':9})

    X_train, X_test, y_train, y_test = train_test_split(X, y_encoded, test_size=0.35, random_state=42)
    print(f"\\n🔀 Train/Test Split:")
    print(f"   Training samples : {X_train.shape[0]:,}")
    print(f"   Testing samples  : {X_test.shape[0]:,}")

    rf_classifier = RandomForestClassifier(n_estimators=100, random_state=42,max_depth=20)
    rf_classifier.fit(X_train, y_train)

    prediction = rf_classifier.predict(x_test)
    
    
    df_result=pd.DataFrame(prediction,columns=['Result'])   
    sample = x_test.iloc[0:10]
    st.write(sample)
    st.write(df_result)

  

def main():
    setup_basic()
    Publish2()
    Machine_Learning()
   
    
    
    
if __name__ == "__main__":
    main()
