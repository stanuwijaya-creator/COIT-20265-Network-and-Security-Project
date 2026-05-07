#InfluxDB
import os, time
from influxdb_client_3 import InfluxDBClient3, Point

#MQTT
from paho.mqtt import client as mqtt_client
import random
import time
import json
import streamlit as st

import pandas as pd
import numpy as np


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
    st.markdown("# MQTT Sensor 2 Start ")
 


def InfluxDB():
    

    
    org = "CQU"
    host = "https://us-east-1-1.aws.cloud2.influxdata.com"

    client = InfluxDBClient3(host=host, token="eL95h-pilVCJ3G1rZfB3J26H82XuDjsHPzUSOPjMwHdvQrWun8_gxEFJlonfT4CCHeKqoEKvxNKqR_NNhoOQrw==", org=org,disable_grpc_compression=True)
    
    database="Test"

    query = """SELECT *
    FROM 'Network1'
    WHERE time >= now() - interval '24 hours'"""
    

    
    table = client.query(query=query, database="Test", language='sql') 
    
    df = table.to_pandas().sort_values(by="time")
    st.write(df)


broker = 's72d970b.ala.asia-southeast1.emqxsl.com'
port = 8883
topic = 'testtopic/network2' 
client_id = f'python-mqtt-{random.randint(0, 1000)}'
username = 'Suhartanto'
password = 'Suhartanto098!'

    

def connect_mqtt():
    def on_connect(client, userdata, flags, rc):
        if rc == 0:
            st.write("Connected to MQTT Broker!")
        else:
            st.write("Failed to connect, return code %d\n", rc)
    # Set Connecting Client ID
    client = mqtt_client.Client(mqtt_client.CallbackAPIVersion.VERSION1,client_id=client_id)
    client.tls_set(ca_certs='/home/tanto/Downloads/emqxsl-ca.crt')
    client.username_pw_set(username, password)
    client.on_connect = on_connect
    client.connect(broker, port)
    st.markdown("ww")
    return client


def publish(client):
    msg_count = 0
    while True:
        time.sleep(5)
        msg_dict = {
            'msg': msg_count,
            "ct_dst_ltm": random.randint(0,50),
                    "ct_dst_src_ltm": random.randint(0,70),
            "is_ftp_login": random.randint(0,1),
            "ct_ftp_cmd": random.randint(0,3),
            "ct_flw_http_mthd": random.randint(0,20),
            "ct_srv_dst": random.randint(0,50),
            "attack_cat":"",
            "device_name": "Sensor 2"
        }
        

        msg = json.dumps(msg_dict)
        result = client.publish(topic, msg)
        # result: [0, 1]
        status = result[0]
        if status == 0:
            st.write(f'Send `{msg}` to topic `{topic}`')
        else:
            st.write(f'Failed to send message to topic {topic}')
        msg_count += 1
        time.sleep(3)
 
  
def subscribe(client: mqtt_client):
    def on_message(client, userdata, msg):
        st.text(f"Received `{msg.payload.decode()}` from `{msg.topic}` topic")

    client.subscribe(topic)
    client.on_message = on_message 
    
def main():
    setup_basic()
    InfluxDB()
    client = connect_mqtt()
    client.loop_start()
    publish(client)
    time.sleep(3)



if __name__ == "__main__":
    main()