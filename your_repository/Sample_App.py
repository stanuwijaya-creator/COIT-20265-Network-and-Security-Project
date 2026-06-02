from dash import Dash, dash_table
from databricks import sql
import os
import random
import time
from influxdb_client_3 import InfluxDBClient3, Point
from paho.mqtt import client as mqtt_client
import streamlit as st
from io import StringIO
import pandas as pd



broker = 's72d970b.ala.asia-southeast1.emqxsl.com'
port = 8883
topic = 'testtopic/1' 
client_id = f'python-mqtt-{random.randint(0, 1000)}'
username = 'Suhartanto'
password = 'Suhartanto098!'


org = "CQU"
host = "https://us-east-1-1.aws.cloud2.influxdata.com"

client = InfluxDBClient3(host=host, token="eL95h-pilVCJ3G1rZfB3J26H82XuDjsHPzUSOPjMwHdvQrWun8_gxEFJlonfT4CCHeKqoEKvxNKqR_NNhoOQrw==", org=org,disable_grpc_compression=True)
    
database="Test"

query = """SELECT *
FROM 'Network1'
WHERE time >= now() - interval '24 hours'"""


def setup_basic():
    title = "MQTT Sensor 1"

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

    st.markdown("""\n""")
    st.markdown("# MQTT Sensor 1 Start ")
 


def connect_mqtt():
    def on_connect(client, userdata, flags, rc):
        if rc == 0:
            print("Connected to MQTT Broker!")
        else:
            print("Failed to connect, return code %d\n", rc)
    # Set Connecting Client ID
    client = mqtt_client.Client(mqtt_client.CallbackAPIVersion.VERSION1,client_id=client_id)
    client.tls_set(ca_certs='emqxsl-ca.crt')
    client.username_pw_set(username, password)
    client.on_connect = on_connect
    client.connect(broker, port)
    return client



def subscribe(client: mqtt_client):
    def on_message(client, userdata, msg):
        print(f"Received `{msg.payload.decode()}` from `{msg.topic}` topic")
        print(msg)
        df=pd.read_json(StringIO(msg.payload.decode()),orient='index')
        df_frame=pd.DataFrame(df)
        client.write(database=database, record=df_frame)
        client.subscribe(topic)
        client.on_message = on_message
        

def main():
    setup_basic()
    client = connect_mqtt()
    subscribe(client)
    client.loop_forever()



if __name__ == "__main__":
    main()
