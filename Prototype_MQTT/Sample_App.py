from dash import Dash, html, dcc, callback, Output, Input,dash_table
import os
import random
import time
from influxdb_client_3 import InfluxDBClient3, Point
from paho.mqtt import client as mqtt_client
from io import StringIO
import pandas as pd
import certifi



broker = 's72d970b.ala.asia-southeast1.emqxsl.com'
port = 8883
topic = 'testtopic/2' 
client_id = f'python-mqtt-{random.randint(0, 1000)}'
username = 'Suhartanto'
password = 'Suhartanto098!'



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
        org = "CQU"
        host = "https://us-east-1-1.aws.cloud2.influxdata.com"
        client = InfluxDBClient3(host=host, token="jT610fXRdss7u6qfSSO0rfu9sjOjQfswrI5mD0K40R2lbBUxNKMgYVvjC1RAii9-dS7_gUcMayUtljagzkqI0g==", org=org,disable_grpc_compression=True)
        database="Test"
        print(f"Received `{msg.payload.decode()}` from `{msg.topic}` topic")
        print(msg)
        df=pd.read_json(StringIO(msg.payload.decode()),orient='index')
        df_frame=pd.DataFrame(df)
        print(df)
        for key in df :
            point=(Point("Network_UNSW_Project_Prototype_Revision2")
                   .field("dur",df["dur"][0])
                    .field("proto",df["proto"][0])
                   .field("service",df["service"][0])
                   .field("state",df["state"][0])
                   .field("spkts",df["spkts"][0])
                   .field("dpkts",df["dpkts"][0])
                   .field("dbytes",df["dbytes"][0])
                   .field("rate",df["rate"][0])
                   .field("sttl",df["sttl"][0])
                   .field("dttl",df["dttl"][0])
                   .field("sload",df["sload"][0])
                   .field("dload",df["dload"][0])
                   .field("sloss",df["sloss"][0])
                   .field("dloss",df["dloss"][0])
                   .field("sinpkt",df["sinpkt"][0])
                   .field("dinpkt",df["dinpkt"][0])
                   .field("sjit",df["sjit"][0])
                   .field("djit",df["djit"][0])
                   .field("swin",df["swin"][0])
                   .field("stcpb",df["stcpb"][0])
                   .field("dtcpb",df["dtcpb"][0])
                   .field("dwin",df["dwin"][0])
                   .field("tcprtt",df["tcprtt"][0])
                   .field("synack",df["synack"][0])
                   .field("ackdat",df["ackdat"][0])
                   .field("smean",df["smean"][0])
                   .field("dmean",df["dmean"][0])
                   .field("sbytes",df["sbytes"][0])
                   .field("trans_depth",df["trans_depth"][0])
                   .field("response_body_len",df["response_body_len"][0])
                   .field("ct_srv_src",df["ct_srv_src"][0])
                   .field("ct_state_ttl",df["ct_state_ttl"][0])
                   .field("ct_src_dport_ltm",df["ct_src_dport_ltm"][0])
                   .field("ct_dst_sport_ltm",df["ct_dst_sport_ltm"][0])
                   .field("ct_dst_src_ltm",df["ct_dst_src_ltm"][0])
                   .field("ct_dst_ltm",df["ct_dst_ltm"][0])
                   .field("is_ftp_login",df["is_ftp_login"][0])
                    .field("ct_ftp_cmd",df["ct_ftp_cmd"][0])
                    .field("ct_flw_http_mthd",df["ct_flw_http_mthd"][0])
                    .field("ct_src_ltm",df["ct_src_ltm"][0])
                    .field("ct_srv_dst",df["ct_srv_dst"][0])
                    .field("is_sm_ips_ports",df["is_sm_ips_ports"][0])
                   )
            client.write(database=database, record=point)
    client.subscribe(topic)
    client.on_message = on_message
    




client = connect_mqtt()
subscribe(client)
client.loop_forever()





 





