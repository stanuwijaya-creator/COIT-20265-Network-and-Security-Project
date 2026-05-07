#Decision Tree Model Setup and Libraru
from sklearn.model_selection import cross_val_score
import io
import re
from collections.abc import Iterable
import pandas as pd
from sklearn import tree
from sklearn.model_selection import train_test_split

from sklearn.tree import DecisionTreeClassifier
from sklearn.tree import export_text
import streamlit as st
from pandas.api.types import (is_bool_dtype, is_datetime64_any_dtype,is_numeric_dtype)
import time

#Random Forest Model Setup and Library

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import warnings
warnings.filterwarnings('ignore')
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
    roc_curve,
    auc
)
import time
from sklearn.datasets import make_classification
import joblib

# Logistic Regression Model
from sklearn.linear_model import LogisticRegression
from sklearn.datasets import load_iris

#InfluxDB
import os, time
from influxdb_client_3 import InfluxDBClient3, Point

#MQTT
from paho.mqtt import client as mqtt_client
import random
import time
import json

import numpy as np

#Defines functions

def setup_basic():
    title = "Intrusion Detection System"

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






    
def Random_Forest():
   st.markdown("# Random ForestModel")
   st.markdown("## Load The NSW-15NB Dataset")
   uploaded_files = st.file_uploader("Upload data",accept_multiple_files="directory" ,type="csv")
   for uploaded_file in uploaded_files:
    df = pd.DataFrame(pd.read_csv(uploaded_file))
    st.write(df)
    st.markdown(f"   Total Samples  : {df.shape[0]:,}")
    st.markdown(f"   Total Features : {df.shape[1] - 1}")
    st.markdown("## Data Analysis")

    Df_Attack=df['attack_cat']
    Df_is_ftp_login=df['is_ftp_login']
    Df_ct_dst_ltm=df['ct_dst_ltm']
    Df_ct_srv_dst=df['ct_srv_dst'] 
    Df_Ct_ftp_cmd=df['ct_ftp_cmd']
    Df_Ct_Dst_src_ltm=df['ct_dst_src_ltm']
    Df_Ct_flw_http_mthd=df['ct_flw_http_mthd']

   
    fig, axes = plt.subplots(2, figsize=(14, 5))

    Df_Attack.value_counts().head(10).plot(
    kind='barh', ax=axes[0],
    color=sns.color_palette('coolwarm', 10))
    axes[0].set_title('Top 10 Traffic Categories')
    plt.tight_layout()
    plt.show()
    st.pyplot(fig)
    st.markdown("#Traffic Description ")
    st.markdown("3: Exploits")
    st.markdown("2: DoS")
    st.markdown("1: Normal")


    conditions=[
       
       #Tree 2 = Test Size : 36,555 , random State :20 , Tree Depth = 6 , Tree_Random_State = 20 )
       
        (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 1.5) & (Df_Ct_flw_http_mthd<= 0.5)&(Df_Ct_Dst_src_ltm<= 1.5)&(Df_is_ftp_login<= 0.5),#1
        (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 1.5) & (Df_Ct_flw_http_mthd<= 0.5)&(Df_Ct_Dst_src_ltm<= 1.5)&(Df_is_ftp_login> 0.5),#1
        (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 1.5) & (Df_Ct_flw_http_mthd <=0.5)&(Df_Ct_Dst_src_ltm<= 5.5),#1
        (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 1.5) & (Df_Ct_flw_http_mthd <=0.5)&(Df_Ct_Dst_src_ltm> 5.5 )&(Df_Ct_Dst_src_ltm<= 47 ),#1
        (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 1.5) & (Df_Ct_flw_http_mthd <=0.5)&(Df_Ct_Dst_src_ltm> 47 ),#2
        (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 1.5) & (Df_Ct_flw_http_mthd <=2.5)&(Df_Ct_Dst_src_ltm<= 1.5)& (Df_Ct_flw_http_mthd >0.5),#1
        (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 1.5) & (Df_Ct_flw_http_mthd <=2.5)&(Df_Ct_Dst_src_ltm>1.5)& (Df_Ct_flw_http_mthd >0.5),#1

        (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 1.5) & (Df_Ct_flw_http_mthd <=6.5)& (Df_Ct_flw_http_mthd >0.5),#1
        (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 1.5) & (Df_Ct_flw_http_mthd >6.5),#1
        (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 2.5) & (Df_ct_dst_ltm > 1.5) & (Df_Ct_flw_http_mthd <=0.5)&(Df_Ct_Dst_src_ltm<=1.5)& (Df_is_ftp_login <=0.5),#1
        (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 2.5) &  (Df_ct_dst_ltm > 1.5) &(Df_Ct_flw_http_mthd <=0.5)&(Df_Ct_Dst_src_ltm<=1.5)& (Df_is_ftp_login >0.5),#1
        (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 2.5) &  (Df_ct_dst_ltm > 1.5)& (Df_Ct_flw_http_mthd >0.5)&(Df_Ct_Dst_src_ltm<=1.5),#1
        (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 2.5) &  (Df_ct_dst_ltm > 1.5)  &(Df_Ct_Dst_src_ltm<=7.5)& (Df_Ct_ftp_cmd<=0.5),#1
        (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 2.5)  &  (Df_ct_dst_ltm > 1.5) &(Df_Ct_Dst_src_ltm>7.5)& (Df_Ct_ftp_cmd<=0.5),#2


        (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 2.5) &  (Df_ct_dst_ltm > 1.5)  &(Df_Ct_Dst_src_ltm<=2.5)&(Df_Ct_Dst_src_ltm>1.5),#3
        (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 2.5)  &  (Df_ct_dst_ltm > 1.5) &(Df_Ct_Dst_src_ltm>2.5)&(Df_Ct_Dst_src_ltm>2.5),#3
        (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 2.5) & (Df_ct_dst_ltm <= 10.5) &(Df_Ct_Dst_src_ltm<=1.5),#1
        (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 21.5) & (Df_ct_dst_ltm > 10.5) &(Df_Ct_Dst_src_ltm<=1.5),#1
        (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 21.5) & (Df_ct_dst_ltm > 2.5) &(Df_Ct_Dst_src_ltm<=4.5) &(Df_Ct_Dst_src_ltm>1.5),#1
        (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 21.5) & (Df_ct_dst_ltm > 2.5) &(Df_Ct_Dst_src_ltm>4.5) ,#1
        (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 21.5) ,#2

        (Df_ct_srv_dst > 1.5 ) &  (Df_ct_srv_dst <= 2.5)& (Df_ct_dst_ltm <= 1.5) &(Df_Ct_Dst_src_ltm <= 1.5),#1
        (Df_ct_srv_dst > 1.5 ) &  (Df_ct_srv_dst <= 2.5)& (Df_ct_dst_ltm > 1.5) & (Df_ct_dst_ltm <= 3.5)&(Df_Ct_Dst_src_ltm <= 1.5),#1
        (Df_ct_srv_dst > 2.5 ) &  (Df_ct_srv_dst <= 9.5)& (Df_ct_dst_ltm <= 3.5) &(Df_Ct_Dst_src_ltm <= 1.5),#1
        (Df_ct_srv_dst > 9.5)& (Df_ct_dst_ltm <= 3.5) &(Df_Ct_Dst_src_ltm <= 1.5),#1
        (Df_ct_srv_dst > 1.5 ) &  (Df_ct_srv_dst <= 2.5)& (Df_ct_dst_ltm <= 1.5) &(Df_Ct_Dst_src_ltm > 1.5)&(Df_Ct_Dst_src_ltm <= 3.5),#1
        (Df_ct_srv_dst > 2.5)& (Df_ct_dst_ltm <= 1.5) &(Df_Ct_Dst_src_ltm > 1.5)&(Df_Ct_Dst_src_ltm <= 3.5),#1
        (Df_ct_srv_dst <= 9.5)& (Df_ct_srv_dst > 1.5) & (Df_ct_dst_ltm > 1.5)& (Df_ct_dst_ltm <= 3.5) &(Df_Ct_Dst_src_ltm > 1.5)&(Df_Ct_Dst_src_ltm <= 3.5),#1


        (Df_ct_srv_dst > 25 ) &  (Df_ct_dst_ltm > 3.5) &(Df_Ct_Dst_src_ltm <= 3.5),#2
        (Df_ct_srv_dst <=2.5 )&  (Df_ct_srv_dst > 1.5) &  (Df_ct_dst_ltm <= 6.5)&  (Df_ct_dst_ltm > 3.5) &(Df_Ct_Dst_src_ltm <= 3.5),#1
        (Df_ct_srv_dst <=2.5 )&  (Df_ct_srv_dst > 1.5) &  (Df_ct_dst_ltm > 6.5)&(Df_Ct_Dst_src_ltm <= 3.5),#1
        (Df_ct_srv_dst <=3.5 )&  (Df_ct_srv_dst > 2.5) &  (Df_ct_dst_ltm > 3.5)&(Df_Ct_Dst_src_ltm <= 3.5),#1
        (Df_ct_srv_dst > 3.5)&  (Df_ct_srv_dst <= 25) &  (Df_ct_dst_ltm > 3.5)&(Df_Ct_Dst_src_ltm <= 3.5),#1
        (Df_ct_srv_dst > 1.5)&  (Df_ct_srv_dst <= 10.5) &(Df_Ct_Dst_src_ltm <= 6.5)&(Df_Ct_Dst_src_ltm > 3.5),#1
        (Df_ct_srv_dst > 10.5)&(Df_Ct_Dst_src_ltm <= 6.5)&(Df_Ct_Dst_src_ltm > 3.5),#1


        (Df_ct_srv_dst > 1.5)&(Df_Ct_Dst_src_ltm > 6.5)&(Df_Ct_Dst_src_ltm <= 10.5)&  (Df_ct_dst_ltm <= 7.5),#1
        (Df_ct_srv_dst > 1.5)&(Df_Ct_Dst_src_ltm > 6.5)&(Df_Ct_Dst_src_ltm <= 10.5)&  (Df_ct_dst_ltm > 7.5),#1
        (Df_ct_srv_dst > 1.5)&(Df_Ct_Dst_src_ltm > 10.5)&  (Df_ct_dst_ltm <= 13.5),#2
        (Df_ct_srv_dst > 1.5)&(Df_Ct_Dst_src_ltm > 10.5)&(Df_Ct_Dst_src_ltm <= 16.5)&  (Df_ct_dst_ltm <= 17.5)&  (Df_ct_dst_ltm > 13.5),#2
        (Df_ct_srv_dst > 1.5)&(Df_Ct_Dst_src_ltm > 10.5)&(Df_Ct_Dst_src_ltm <= 16.5)& (Df_ct_dst_ltm > 17.5),#1
        (Df_ct_srv_dst > 1.5)&(Df_Ct_Dst_src_ltm > 16.5)& (Df_ct_dst_ltm > 13.5),#1


        #Tree 1  = Test Size : 23,499 , random State :20 , Tree Depth = 6 , Tree_Random_State = 20 )

        
            (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 1.5) & (Df_Ct_flw_http_mthd<= 0.5)&(Df_Ct_Dst_src_ltm<= 1.5)&(Df_is_ftp_login<= 0.5),#3
            (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 1.5) & (Df_Ct_flw_http_mthd<= 2.5)&(Df_Ct_Dst_src_ltm<= 1.5)&(Df_is_ftp_login> 0.5),#1
            (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 1.5) & (Df_Ct_flw_http_mthd <=2.5)& (Df_Ct_flw_http_mthd >0.5)&(Df_Ct_Dst_src_ltm<= 1.5),#3
            (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 1.5) & (Df_Ct_flw_http_mthd >2.5)&(Df_Ct_Dst_src_ltm<= 1.5),#1
            (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 1.5) & (Df_ct_dst_ltm <= 2.5) & ( Df_is_ftp_login <= 0.5)&(Df_Ct_Dst_src_ltm<= 1.5)& (Df_Ct_flw_http_mthd <=5),#1
            (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 1.5) & (Df_ct_dst_ltm <= 2.5)&( Df_is_ftp_login <= 0.5)&(Df_Ct_Dst_src_ltm<= 1.5)& (Df_Ct_flw_http_mthd >5),#1
            (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 1.5)& (Df_ct_dst_ltm <= 2.5) & ( Df_is_ftp_login > 0.5)&(Df_Ct_Dst_src_ltm<= 1.5),#1

            (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 1.5) &(Df_Ct_Dst_src_ltm<= 26)&(Df_Ct_Dst_src_ltm> 1.5),#3
            (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 2.5) &(Df_Ct_Dst_src_ltm <= 47)&(Df_Ct_Dst_src_ltm> 26),#1
            (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 1.5) &(Df_Ct_Dst_src_ltm > 47),#3
            (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 1.5)  & (Df_ct_dst_ltm <= 2.5)&(Df_Ct_Dst_src_ltm > 1.5)&(Df_Ct_flw_http_mthd <= 0.5)&(Df_Ct_ftp_cmd <= 0.5),#3
            (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 1.5) & (Df_ct_dst_ltm <= 2.5)&(Df_Ct_Dst_src_ltm > 1.5)&(Df_Ct_flw_http_mthd <= 0.5)&(Df_Ct_ftp_cmd > 0.5),#3
            (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 1.5)& (Df_ct_dst_ltm <=2.5) &(Df_Ct_Dst_src_ltm > 1.5)&(Df_Ct_flw_http_mthd <= 1.5),#3
            (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 1.5) & (Df_ct_dst_ltm <= 2.5) &(Df_Ct_Dst_src_ltm > 1.5)&(Df_Ct_flw_http_mthd > 1.5),#1
            
            (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 4.5)& (Df_ct_dst_ltm > 2.5) &(Df_Ct_Dst_src_ltm <= 2.5),#1
            (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 4.5)& (Df_ct_dst_ltm > 2.5) &(Df_Ct_Dst_src_ltm <= 8.5)  &(Df_Ct_Dst_src_ltm > 2.5),#3
            (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 4.5) &(Df_Ct_Dst_src_ltm <= 8.5)&(Df_Ct_ftp_cmd <= 0.5),#1
            (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 4.5) &(Df_Ct_Dst_src_ltm <= 8.5)&(Df_Ct_ftp_cmd > 0.5),#1
            (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 2.5) &(Df_Ct_Dst_src_ltm > 8.5)&(Df_Ct_Dst_src_ltm <= 9.5),#2
            (Df_ct_srv_dst<= 1.5 )  & (Df_ct_dst_ltm > 2.5)& (Df_ct_dst_ltm <= 4) &(Df_Ct_Dst_src_ltm <= 12)&(Df_Ct_Dst_src_ltm > 9.5),#3
            (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 4) &(Df_Ct_Dst_src_ltm <= 12)&(Df_Ct_Dst_src_ltm > 9.5),#1
            
           
            (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 2.5) &(Df_Ct_Dst_src_ltm <= 23.5) &(Df_Ct_Dst_src_ltm > 12),#3
            (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 2.5) &(Df_Ct_Dst_src_ltm > 23.5)&(Df_Ct_Dst_src_ltm <= 28.5),#3
            (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 2.5) &(Df_Ct_Dst_src_ltm > 28.5),#1
            (Df_ct_srv_dst > 1.5 ) & (Df_ct_srv_dst <= 2.5) & (Df_ct_dst_ltm <= 1.5) &(Df_Ct_Dst_src_ltm <= 1.5),#1
            (Df_ct_srv_dst > 1.5 )  & (Df_ct_srv_dst <= 2.5)&(Df_Ct_Dst_src_ltm <= 1.5)& (Df_ct_dst_ltm > 1.5) &(Df_ct_dst_ltm <=2.5),#1
            (Df_ct_srv_dst <= 2.5 ) & (Df_ct_srv_dst > 1.5) & (Df_ct_dst_ltm <= 1.5) &(Df_Ct_Dst_src_ltm > 1.5)&(Df_Ct_Dst_src_ltm <= 3.5),#1
            (Df_ct_srv_dst <= 2.5 ) & (Df_ct_srv_dst >1.5)& (Df_ct_dst_ltm <= 2.5)& (Df_ct_dst_ltm > 1.5) &(Df_Ct_Dst_src_ltm > 1.5)&(Df_Ct_Dst_src_ltm <= 3.5),#1
            (Df_ct_srv_dst <= 8.5 )& (Df_ct_srv_dst > 2.5) & (Df_ct_dst_ltm <= 2.5) &(Df_Ct_Dst_src_ltm <= 2.5),  #1
            (Df_ct_srv_dst <= 8.5 ) & (Df_ct_srv_dst > 2.5)  & (Df_ct_dst_ltm <= 2.5) &(Df_Ct_Dst_src_ltm > 2.5)&(Df_Ct_Dst_src_ltm <= 3.5),  #1

            (Df_ct_srv_dst > 8.5 ) & (Df_ct_dst_ltm <= 2.5) &(Df_Ct_Dst_src_ltm <= 1.5),  #1
            (Df_ct_srv_dst > 8.5 )& (Df_ct_dst_ltm <= 2.5) & (Df_Ct_Dst_src_ltm<= 3.5) &(Df_Ct_Dst_src_ltm > 1.5),  #3
            (Df_ct_srv_dst > 1.5 ) & (Df_ct_dst_ltm <= 3.5)& (Df_ct_dst_ltm > 2.5) &(Df_Ct_Dst_src_ltm <= 2.5)&(Df_Ct_flw_http_mthd <= 2.5),#1
            (Df_ct_srv_dst > 1.5 ) & (Df_ct_dst_ltm <= 3.5)& (Df_ct_dst_ltm > 2.5) &(Df_Ct_Dst_src_ltm <= 2.5)&(Df_Ct_flw_http_mthd > 2.5),#1
            (Df_ct_srv_dst <= 14.5 )& (Df_ct_srv_dst > 1.5) & (Df_ct_dst_ltm <= 3.5)& (Df_ct_dst_ltm > 2.5) &(Df_Ct_Dst_src_ltm > 2.5),#1
            (Df_ct_srv_dst > 14.5 )  & (Df_ct_dst_ltm <= 3.5) & (Df_ct_dst_ltm > 2.5)&(Df_Ct_Dst_src_ltm > 2.5)&(Df_Ct_Dst_src_ltm <=3.5),#3

            (Df_ct_srv_dst <= 22.5 ) &(Df_ct_srv_dst > 1.5 )& (Df_ct_dst_ltm > 3.5) &(Df_Ct_Dst_src_ltm <= 3.5),#1
            (Df_ct_srv_dst > 22.5 ) & (Df_ct_dst_ltm > 3.5) &(Df_Ct_Dst_src_ltm <= 3.5),#1
            (Df_ct_srv_dst > 25 ) & (Df_ct_dst_ltm > 3.5) &(Df_Ct_Dst_src_ltm <= 2),#3
            (Df_ct_srv_dst > 25 ) & (Df_ct_dst_ltm > 3.5)&(Df_Ct_Dst_src_ltm <= 3.5) &(Df_Ct_Dst_src_ltm > 2),#2
            (Df_ct_srv_dst > 1.5 ) & (Df_ct_dst_ltm <= 1.5) &(Df_Ct_Dst_src_ltm > 3.5)&(Df_Ct_Dst_src_ltm <= 7.5)& (Df_Ct_flw_http_mthd <= 0.5),#1
            (Df_ct_srv_dst > 1.5 ) & (Df_ct_dst_ltm <= 1.5) &(Df_Ct_Dst_src_ltm > 7.5)& (Df_Ct_flw_http_mthd <= 0.5),#1
            (Df_ct_srv_dst <= 3.5 ) & (Df_ct_srv_dst > 1.5 )& (Df_ct_dst_ltm <= 1.5) &(Df_Ct_Dst_src_ltm > 3.5)& (Df_Ct_flw_http_mthd > 0.5),#1
            (Df_ct_srv_dst > 3.5 ) & (Df_ct_dst_ltm <= 1.5) &(Df_Ct_Dst_src_ltm > 3.5)& (Df_Ct_flw_http_mthd > 0.5),#1
            (Df_ct_srv_dst <= 10.5 ) & (Df_ct_srv_dst > 1.5 )& (Df_ct_dst_ltm > 1.5) & (Df_ct_dst_ltm <= 6.5)&(Df_Ct_Dst_src_ltm <= 10.5)&(Df_Ct_Dst_src_ltm > 3.5),#1
            (Df_ct_srv_dst > 10.5 ) & (Df_ct_dst_ltm > 1.5) & (Df_ct_dst_ltm <= 6.5)&(Df_Ct_Dst_src_ltm <= 10.5),#3
            (Df_ct_srv_dst <= 2.5 ) &(Df_ct_srv_dst > 1.5 )& (Df_ct_dst_ltm > 1.5) & (Df_ct_dst_ltm <= 6.5)&(Df_Ct_Dst_src_ltm > 10.5),#1
            (Df_ct_srv_dst > 2.5 ) & (Df_ct_dst_ltm > 1.5)& (Df_ct_dst_ltm <= 6.5) &(Df_Ct_Dst_src_ltm > 10.5),#1

            (Df_ct_srv_dst > 1.5 ) & (Df_ct_dst_ltm <= 8.5)& (Df_ct_dst_ltm > 6.5) &(Df_Ct_Dst_src_ltm <= 9.5)&(Df_Ct_Dst_src_ltm > 3.5),#1
            (Df_ct_srv_dst > 1.5 ) & (Df_ct_dst_ltm > 8.5) &(Df_Ct_Dst_src_ltm <= 9.5)&(Df_Ct_Dst_src_ltm > 3.5),#1   
            (Df_ct_srv_dst > 1.5 ) & (Df_ct_dst_ltm <= 9.5) & (Df_ct_dst_ltm > 6.5)&(Df_Ct_Dst_src_ltm > 9.5)&(Df_Ct_Dst_src_ltm <= 14.5),#1
            (Df_ct_srv_dst > 1.5 ) & (Df_ct_dst_ltm > 9.5) &(Df_Ct_Dst_src_ltm > 9.5)&(Df_Ct_Dst_src_ltm <= 14.5),#3
            
            (Df_ct_srv_dst > 1.5 ) &  (Df_ct_srv_dst <= 2.5 )& (Df_ct_dst_ltm <= 7.5)& (Df_ct_dst_ltm > 6.5) &(Df_Ct_Dst_src_ltm > 14.5),#1
            (Df_ct_srv_dst > 1.5 )&  (Df_ct_srv_dst <= 2.5 ) & (Df_ct_dst_ltm > 7.5) &(Df_Ct_Dst_src_ltm > 14.5),#3
             (Df_ct_srv_dst > 2.5 )& (Df_ct_dst_ltm > 6.5) &(Df_Ct_Dst_src_ltm > 14.5),#1


        ]
    
    Type_attack=[  
                    # Predict Tree 2 
                    1,1,1,1,2,1,1,
                    1,1,1,1,1,1,2,
                    3,3,1,1,1,1,2,
                    1,1,1,1,1,1,1,
                    2,1,1,1,1,1,1,
                    1,1,2,2,1,1,
                    
                    # Predict Tree 1 
                3,1,3,1,1,1,1,
                 3,1,3,3,3,3,1,
                 1,3,1,1,2,3,1,
                 3,3,1,1,1,1,1,
                 1,1,1,3,1,1,1,
                 3,1,1,3,2,1,1,
                 1,1,1,3,1,1,1,
                 1,1,3,1,3,1
                    
                    ]
    
    result=np.select(conditions,Type_attack)

  
    st.markdown("### Decision Tree Diagram ")
    x = df[['ct_dst_ltm','is_ftp_login','ct_srv_dst','ct_dst_src_ltm','ct_flw_http_mthd','ct_ftp_cmd']]
    y = df[['attack_cat']]
    x_train,x_test,y_train,y_test = train_test_split (x,y, test_size = 0.70, random_state = 20)
    decision_tree = DecisionTreeClassifier(random_state=20, max_depth=6)
    start = time.time()
    decision_tree = decision_tree.fit(x_train,y_train)
    r = export_text(decision_tree,spacing=3,feature_names=['ct_dst_ltm','is_ftp_login','ct_srv_dst','Ct_Dst_src_ltm','Ct_flw_http_mthd','Ct_ftp_cmd'])
    st.write(f"🔀 Train/Test Split:")
    st.write(f"   Training samples : {x_train.shape[0]:,}")
    st.write(f"   Testing samples  : {x_test.shape[0]:,}")
    st.text(r)
    st.write(tree.plot_tree(decision_tree))
    


    st.markdown("""\n""")
    st.markdown("## Result ")
    st.markdown("""\n""")
    st.markdown("""\n""")
    df_result=pd.DataFrame(result,columns=['Result'])
    st.dataframe(df_result,hide_index=True) 

    st.markdown("### Result Description ")
    st.markdown("3: Exploits")
    st.markdown("2: DoS")
    st.markdown("1: Normal")
    elapsed = time.time() - start
    st.write(f"✅ Training completed in {elapsed:.2f} seconds")
    st.markdown("""\n""")
    st.download_button(
        "Download the result .csv",
        df_result.to_csv(index=None).encode("utf-8"),
        "Decision Tree Model Detection Result.csv",
        "text/csv",
        key="download-csv",
    )
    

    st.markdown("""\n""")
    st.markdown("### Model Evaluation & Metrics")

    uploaded_files = st.file_uploader("Upload The Result data", accept_multiple_files=True, type="csv")
    for uploaded_file in uploaded_files:
     df_predict = pd.DataFrame(pd.read_csv(uploaded_file))
     
     y_true = df['attack_cat']
     y_pred = df_predict['Result']
     target_names = ['Normal', 'DoS','Exploits']
     
     st.text_area(classification_report(y_true, y_pred, target_names=target_names,digits=4))
     cm = confusion_matrix(y_true, y_pred)
     fig, ax = plt.subplots(figsize=(3, 4))
     sns.heatmap(cm, annot=True, fmt=',', cmap='Blues',xticklabels=target_names,yticklabels=target_names, ax=ax)
     ax.set_xlabel('Predicted Label')
     ax.set_ylabel('True Label')
     ax.set_title('Confusion Matrix — Random Forest IDS')
     st.pyplot(fig)

    st.markdown("#Result Description ")
    st.markdown("3: Exploits")
    st.markdown("2: DoS")
    st.markdown("1: Normal")
    st.markdown("""\n""")
    st.markdown("### Save Model ")


    message = st.text_area("Model and Conditions", value="Tree 1\n"
    "(Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 1.5) & (Df_Ct_flw_http_mthd<= 0.5)&(Df_Ct_Dst_src_ltm<= 1.5)&(Df_is_ftp_login<= 0.5),\n"
    "(Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 1.5) & (Df_Ct_flw_http_mthd<= 2.5)&(Df_Ct_Dst_src_ltm<= 1.5)&(Df_is_ftp_login> 0.5),\n"
    "(Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 1.5) & (Df_Ct_flw_http_mthd <=2.5)& (Df_Ct_flw_http_mthd >0.5)&(Df_Ct_Dst_src_ltm<= 1.5),\n"
    "(Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 1.5) & (Df_Ct_flw_http_mthd >2.5)&(Df_Ct_Dst_src_ltm<= 1.5),\n"
    "(Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 1.5) & (Df_ct_dst_ltm <= 2.5) & ( Df_is_ftp_login <= 0.5)&(Df_Ct_Dst_src_ltm<= 1.5)& (Df_Ct_flw_http_mthd <=5),\n"
    "(Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 1.5) & (Df_ct_dst_ltm <= 2.5)&( Df_is_ftp_login <= 0.5)&(Df_Ct_Dst_src_ltm<= 1.5)& (Df_Ct_flw_http_mthd >5),\n"
    "(Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 1.5)& (Df_ct_dst_ltm <= 2.5) & ( Df_is_ftp_login > 0.5)&(Df_Ct_Dst_src_ltm<= 1.5),\n"
    "(Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 1.5) &(Df_Ct_Dst_src_ltm<= 26)&(Df_Ct_Dst_src_ltm> 1.5),\n"
    "(Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 2.5) &(Df_Ct_Dst_src_ltm <= 47)&(Df_Ct_Dst_src_ltm> 26),\n"
    "(Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 1.5) &(Df_Ct_Dst_src_ltm > 47),\n"
    "(Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 1.5)  & (Df_ct_dst_ltm <= 2.5)&(Df_Ct_Dst_src_ltm > 1.5)&(Df_Ct_flw_http_mthd <= 0.5)&(Df_Ct_ftp_cmd <= 0.5),\n"
    "(Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 1.5) & (Df_ct_dst_ltm <= 2.5)&(Df_Ct_Dst_src_ltm > 1.5)&(Df_Ct_flw_http_mthd <= 0.5)&(Df_Ct_ftp_cmd > 0.5),\n"
    "(Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 1.5)& (Df_ct_dst_ltm <=2.5) &(Df_Ct_Dst_src_ltm > 1.5)&(Df_Ct_flw_http_mthd <= 1.5),\n"
    "(Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 1.5) & (Df_ct_dst_ltm <= 2.5) &(Df_Ct_Dst_src_ltm > 1.5)&(Df_Ct_flw_http_mthd > 1.5),\n"
    "(Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 4.5)& (Df_ct_dst_ltm > 2.5) &(Df_Ct_Dst_src_ltm <= 2.5),\n"
    "(Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 4.5)& (Df_ct_dst_ltm > 2.5) &(Df_Ct_Dst_src_ltm <= 8.5)  &(Df_Ct_Dst_src_ltm > 2.5),\n"
    "(Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 4.5) &(Df_Ct_Dst_src_ltm <= 8.5)&(Df_Ct_ftp_cmd <= 0.5),\n"
    "(Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 4.5) &(Df_Ct_Dst_src_ltm <= 8.5)&(Df_Ct_ftp_cmd > 0.5),\n"
    "(Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 2.5) &(Df_Ct_Dst_src_ltm > 8.5)&(Df_Ct_Dst_src_ltm <= 9.5),\n"
    "(Df_ct_srv_dst<= 1.5 )  & (Df_ct_dst_ltm > 2.5)& (Df_ct_dst_ltm <= 4) &(Df_Ct_Dst_src_ltm <= 12)&(Df_Ct_Dst_src_ltm > 9.5),\n"
    "(Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 4) &(Df_Ct_Dst_src_ltm <= 12)&(Df_Ct_Dst_src_ltm > 9.5),\n"
    "(Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 2.5) &(Df_Ct_Dst_src_ltm <= 23.5) &(Df_Ct_Dst_src_ltm > 12),\n"
    "(Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 2.5) &(Df_Ct_Dst_src_ltm > 23.5)&(Df_Ct_Dst_src_ltm <= 28.5),\n"
    "(Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 2.5) &(Df_Ct_Dst_src_ltm > 28.5),\n"
    "(Df_ct_srv_dst > 1.5 ) & (Df_ct_srv_dst <= 2.5) & (Df_ct_dst_ltm <= 1.5) &(Df_Ct_Dst_src_ltm <= 1.5),\n"
    "(Df_ct_srv_dst > 1.5 )  & (Df_ct_srv_dst <= 2.5)&(Df_Ct_Dst_src_ltm <= 1.5)& (Df_ct_dst_ltm > 1.5) &(Df_ct_dst_ltm <=2.5),\n"
    "(Df_ct_srv_dst <= 2.5 ) & (Df_ct_srv_dst > 1.5) & (Df_ct_dst_ltm <= 1.5) &(Df_Ct_Dst_src_ltm > 1.5)&(Df_Ct_Dst_src_ltm <= 3.5),\n"
    "(Df_ct_srv_dst <= 2.5 ) & (Df_ct_srv_dst >1.5)& (Df_ct_dst_ltm <= 2.5)& (Df_ct_dst_ltm > 1.5) &(Df_Ct_Dst_src_ltm > 1.5)&(Df_Ct_Dst_src_ltm <= 3.5),\n"
    "(Df_ct_srv_dst <= 8.5 )& (Df_ct_srv_dst > 2.5) & (Df_ct_dst_ltm <= 2.5) &(Df_Ct_Dst_src_ltm <= 2.5),  \n"
    "(Df_ct_srv_dst <= 8.5 ) & (Df_ct_srv_dst > 2.5)  & (Df_ct_dst_ltm <= 2.5) &(Df_Ct_Dst_src_ltm > 2.5)&(Df_Ct_Dst_src_ltm <= 3.5),\n  "
    "(Df_ct_srv_dst > 8.5 ) & (Df_ct_dst_ltm <= 2.5) &(Df_Ct_Dst_src_ltm <= 1.5),  \n"
    "(Df_ct_srv_dst > 8.5 )& (Df_ct_dst_ltm <= 2.5) & (Df_Ct_Dst_src_ltm<= 3.5) &(Df_Ct_Dst_src_ltm > 1.5), \n "
    "(Df_ct_srv_dst > 1.5 ) & (Df_ct_dst_ltm <= 3.5)& (Df_ct_dst_ltm > 2.5) &(Df_Ct_Dst_src_ltm <= 2.5)&(Df_Ct_flw_http_mthd <= 2.5),\n"
    "(Df_ct_srv_dst > 1.5 ) & (Df_ct_dst_ltm <= 3.5)& (Df_ct_dst_ltm > 2.5) &(Df_Ct_Dst_src_ltm <= 2.5)&(Df_Ct_flw_http_mthd > 2.5),\n"
    "(Df_ct_srv_dst <= 14.5 )& (Df_ct_srv_dst > 1.5) & (Df_ct_dst_ltm <= 3.5)& (Df_ct_dst_ltm > 2.5) &(Df_Ct_Dst_src_ltm > 2.5),\n"
    "(Df_ct_srv_dst > 14.5 )  & (Df_ct_dst_ltm <= 3.5) & (Df_ct_dst_ltm > 2.5)&(Df_Ct_Dst_src_ltm > 2.5)&(Df_Ct_Dst_src_ltm <=3.5),\n"
    "(Df_ct_srv_dst <= 22.5 ) &(Df_ct_srv_dst > 1.5 )& (Df_ct_dst_ltm > 3.5) &(Df_Ct_Dst_src_ltm <= 3.5),\n"
    "(Df_ct_srv_dst > 22.5 ) & (Df_ct_dst_ltm > 3.5) &(Df_Ct_Dst_src_ltm <= 3.5),\n"
    "(Df_ct_srv_dst > 25 ) & (Df_ct_dst_ltm > 3.5) &(Df_Ct_Dst_src_ltm <= 2),\n"
    "(Df_ct_srv_dst > 25 ) & (Df_ct_dst_ltm > 3.5)&(Df_Ct_Dst_src_ltm <= 3.5) &(Df_Ct_Dst_src_ltm > 2),\n"
    "(Df_ct_srv_dst > 1.5 ) & (Df_ct_dst_ltm <= 1.5) &(Df_Ct_Dst_src_ltm > 3.5)&(Df_Ct_Dst_src_ltm <= 7.5)& (Df_Ct_flw_http_mthd <= 0.5),\n"
    "(Df_ct_srv_dst > 1.5 ) & (Df_ct_dst_ltm <= 1.5) &(Df_Ct_Dst_src_ltm > 7.5)& (Df_Ct_flw_http_mthd <= 0.5),\n"
    "(Df_ct_srv_dst <= 3.5 ) & (Df_ct_srv_dst > 1.5 )& (Df_ct_dst_ltm <= 1.5) &(Df_Ct_Dst_src_ltm > 3.5)& (Df_Ct_flw_http_mthd > 0.5),\n"
    "(Df_ct_srv_dst > 3.5 ) & (Df_ct_dst_ltm <= 1.5) &(Df_Ct_Dst_src_ltm > 3.5)& (Df_Ct_flw_http_mthd > 0.5),\n"
    " (Df_ct_srv_dst <= 10.5 ) & (Df_ct_srv_dst > 1.5 )& (Df_ct_dst_ltm > 1.5) & (Df_ct_dst_ltm <= 6.5)&(Df_Ct_Dst_src_ltm <= 10.5)&(Df_Ct_Dst_src_ltm > 3.5),\n"
    "(Df_ct_srv_dst > 10.5 ) & (Df_ct_dst_ltm > 1.5) & (Df_ct_dst_ltm <= 6.5)&(Df_Ct_Dst_src_ltm <= 10.5),\n"
    "(Df_ct_srv_dst <= 2.5 ) &(Df_ct_srv_dst > 1.5 )& (Df_ct_dst_ltm > 1.5) & (Df_ct_dst_ltm <= 6.5)&(Df_Ct_Dst_src_ltm > 10.5),\n"
    "(Df_ct_srv_dst > 2.5 ) & (Df_ct_dst_ltm > 1.5)& (Df_ct_dst_ltm <= 6.5) &(Df_Ct_Dst_src_ltm > 10.5),\n"
    " (Df_ct_srv_dst > 1.5 ) & (Df_ct_dst_ltm <= 8.5)& (Df_ct_dst_ltm > 6.5) &(Df_Ct_Dst_src_ltm <= 9.5)&(Df_Ct_Dst_src_ltm > 3.5),\n"
    "(Df_ct_srv_dst > 1.5 ) & (Df_ct_dst_ltm > 8.5) &(Df_Ct_Dst_src_ltm <= 9.5)&(Df_Ct_Dst_src_ltm > 3.5),\n"
    "(Df_ct_srv_dst > 1.5 ) & (Df_ct_dst_ltm <= 9.5) & (Df_ct_dst_ltm > 6.5)&(Df_Ct_Dst_src_ltm > 9.5)&(Df_Ct_Dst_src_ltm <= 14.5),\n"
    "(Df_ct_srv_dst > 1.5 ) & (Df_ct_dst_ltm > 9.5) &(Df_Ct_Dst_src_ltm > 9.5)&(Df_Ct_Dst_src_ltm <= 14.5),\n"
    "(Df_ct_srv_dst > 1.5 ) &  (Df_ct_srv_dst <= 2.5 )& (Df_ct_dst_ltm <= 7.5)& (Df_ct_dst_ltm > 6.5) &(Df_Ct_Dst_src_ltm > 14.5),\n"
    "(Df_ct_srv_dst > 1.5 )&  (Df_ct_srv_dst <= 2.5 ) & (Df_ct_dst_ltm > 7.5) &(Df_Ct_Dst_src_ltm > 14.5),\n"
    "(Df_ct_srv_dst > 2.5 )& (Df_ct_dst_ltm > 6.5) &(Df_Ct_Dst_src_ltm > 14.5)\n\n"
    
    "Tree 2\n"

    "Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 1.5) & (Df_Ct_flw_http_mthd<= 0.5)&(Df_Ct_Dst_src_ltm<= 1.5)&(Df_is_ftp_login<= 0.5),\n"
    "(Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 1.5) & (Df_Ct_flw_http_mthd<= 0.5)&(Df_Ct_Dst_src_ltm<= 1.5)&(Df_is_ftp_login> 0.5),\n"
    "(Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 1.5) & (Df_Ct_flw_http_mthd <=0.5)&(Df_Ct_Dst_src_ltm<= 5.5),\n"
        "(Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 1.5) & (Df_Ct_flw_http_mthd <=0.5)&(Df_Ct_Dst_src_ltm> 5.5 )&(Df_Ct_Dst_src_ltm<= 47 ),\n"
        "(Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 1.5) & (Df_Ct_flw_http_mthd <=0.5)&(Df_Ct_Dst_src_ltm> 47 ),\n"
        "(Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 1.5) & (Df_Ct_flw_http_mthd <=2.5)&(Df_Ct_Dst_src_ltm<= 1.5)& (Df_Ct_flw_http_mthd >0.5),\n"
        "(Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 1.5) & (Df_Ct_flw_http_mthd <=2.5)&(Df_Ct_Dst_src_ltm>1.5)& (Df_Ct_flw_http_mthd >0.5),\n"

        "(Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 1.5) & (Df_Ct_flw_http_mthd <=6.5)& (Df_Ct_flw_http_mthd >0.5),\n"
        "(Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 1.5) & (Df_Ct_flw_http_mthd >6.5),\n"
        "(Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 2.5) & (Df_ct_dst_ltm > 1.5) & (Df_Ct_flw_http_mthd <=0.5)&(Df_Ct_Dst_src_ltm<=1.5)& (Df_is_ftp_login <=0.5),\n"
        "(Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 2.5) &  (Df_ct_dst_ltm > 1.5) &(Df_Ct_flw_http_mthd <=0.5)&(Df_Ct_Dst_src_ltm<=1.5)& (Df_is_ftp_login >0.5),\n"
        "(Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 2.5) &  (Df_ct_dst_ltm > 1.5)& (Df_Ct_flw_http_mthd >0.5)&(Df_Ct_Dst_src_ltm<=1.5),\n"
        "(Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 2.5) &  (Df_ct_dst_ltm > 1.5)  &(Df_Ct_Dst_src_ltm<=7.5)& (Df_Ct_ftp_cmd<=0.5),\n"
        "(Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 2.5)  &  (Df_ct_dst_ltm > 1.5) &(Df_Ct_Dst_src_ltm>7.5)& (Df_Ct_ftp_cmd<=0.5),\n"
        "(Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 2.5) &  (Df_ct_dst_ltm > 1.5)  &(Df_Ct_Dst_src_ltm<=2.5)&(Df_Ct_Dst_src_ltm>1.5),\n"
        "(Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 2.5)  &  (Df_ct_dst_ltm > 1.5) &(Df_Ct_Dst_src_ltm>2.5)&(Df_Ct_Dst_src_ltm>2.5),\n"
        "(Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 2.5) & (Df_ct_dst_ltm <= 10.5) &(Df_Ct_Dst_src_ltm<=1.5),\n"
        "(Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 21.5) & (Df_ct_dst_ltm > 10.5) &(Df_Ct_Dst_src_ltm<=1.5),\n"
        "(Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 21.5) & (Df_ct_dst_ltm > 2.5) &(Df_Ct_Dst_src_ltm<=4.5) &(Df_Ct_Dst_src_ltm>1.5),\n"
        "(Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 21.5) & (Df_ct_dst_ltm > 2.5) &(Df_Ct_Dst_src_ltm>4.5) ,\n"
        "(Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 21.5) ,\n"

        "(Df_ct_srv_dst > 1.5 ) &  (Df_ct_srv_dst <= 2.5)& (Df_ct_dst_ltm <= 1.5) &(Df_Ct_Dst_src_ltm <= 1.5),\n"
        "(Df_ct_srv_dst > 1.5 ) &  (Df_ct_srv_dst <= 2.5)& (Df_ct_dst_ltm > 1.5) & (Df_ct_dst_ltm <= 3.5)&(Df_Ct_Dst_src_ltm <= 1.5),\n"
        "(Df_ct_srv_dst > 2.5 ) &  (Df_ct_srv_dst <= 9.5)& (Df_ct_dst_ltm <= 3.5) &(Df_Ct_Dst_src_ltm <= 1.5),\n"
        "(Df_ct_srv_dst > 9.5)& (Df_ct_dst_ltm <= 3.5) &(Df_Ct_Dst_src_ltm <= 1.5),\n"
        "(Df_ct_srv_dst > 1.5 ) &  (Df_ct_srv_dst <= 2.5)& (Df_ct_dst_ltm <= 1.5) &(Df_Ct_Dst_src_ltm > 1.5)&(Df_Ct_Dst_src_ltm <= 3.5),\n"
        "(Df_ct_srv_dst > 2.5)& (Df_ct_dst_ltm <= 1.5) &(Df_Ct_Dst_src_ltm > 1.5)&(Df_Ct_Dst_src_ltm <= 3.5),\n"
        "(Df_ct_srv_dst <= 9.5)& (Df_ct_srv_dst > 1.5) & (Df_ct_dst_ltm > 1.5)& (Df_ct_dst_ltm <= 3.5) &(Df_Ct_Dst_src_ltm > 1.5)&(Df_Ct_Dst_src_ltm <= 3.5),\n"


        "(Df_ct_srv_dst > 25 ) &  (Df_ct_dst_ltm > 3.5) &(Df_Ct_Dst_src_ltm <= 3.5),\n"
        "(Df_ct_srv_dst <=2.5 )&  (Df_ct_srv_dst > 1.5) &  (Df_ct_dst_ltm <= 6.5)&  (Df_ct_dst_ltm > 3.5) &(Df_Ct_Dst_src_ltm <= 3.5),\n"
        "(Df_ct_srv_dst <=2.5 )&  (Df_ct_srv_dst > 1.5) &  (Df_ct_dst_ltm > 6.5)&(Df_Ct_Dst_src_ltm <= 3.5),\n"
        "(Df_ct_srv_dst <=3.5 )&  (Df_ct_srv_dst > 2.5) &  (Df_ct_dst_ltm > 3.5)&(Df_Ct_Dst_src_ltm <= 3.5),\n"
        "(Df_ct_srv_dst > 3.5)&  (Df_ct_srv_dst <= 25) &  (Df_ct_dst_ltm > 3.5)&(Df_Ct_Dst_src_ltm <= 3.5),\n"
        "(Df_ct_srv_dst > 1.5)&  (Df_ct_srv_dst <= 10.5) &(Df_Ct_Dst_src_ltm <= 6.5)&(Df_Ct_Dst_src_ltm > 3.5),\n"
        "(Df_ct_srv_dst > 10.5)&(Df_Ct_Dst_src_ltm <= 6.5)&(Df_Ct_Dst_src_ltm > 3.5),\n"


        "(Df_ct_srv_dst > 1.5)&(Df_Ct_Dst_src_ltm > 6.5)&(Df_Ct_Dst_src_ltm <= 10.5)&  (Df_ct_dst_ltm <= 7.5),\n"
        "(Df_ct_srv_dst > 1.5)&(Df_Ct_Dst_src_ltm > 6.5)&(Df_Ct_Dst_src_ltm <= 10.5)&  (Df_ct_dst_ltm > 7.5),\n"
        "(Df_ct_srv_dst > 1.5)&(Df_Ct_Dst_src_ltm > 10.5)&  (Df_ct_dst_ltm <= 13.5),\n"
        "(Df_ct_srv_dst > 1.5)&(Df_Ct_Dst_src_ltm > 10.5)&(Df_Ct_Dst_src_ltm <= 16.5)&  (Df_ct_dst_ltm <= 17.5)&  (Df_ct_dst_ltm > 13.5),\n"
        "(Df_ct_srv_dst > 1.5)&(Df_Ct_Dst_src_ltm > 10.5)&(Df_Ct_Dst_src_ltm <= 16.5)& (Df_ct_dst_ltm > 17.5),\n"
        "(Df_ct_srv_dst > 1.5)&(Df_Ct_Dst_src_ltm > 16.5)& (Df_ct_dst_ltm > 13.5),\n"
        
        "Conditions\n"
        "Tree 1\n"
        " 3,1,3,1,1,1,1,3,1,3,3,3,3,1,1,3,1,1,2,3,1,3,3,1,1,1,1,1,1,1,1,3,1,1,1,3,1,1,3,2,1,1,1,1,1,3,1,1,1,1,1,3,1,3,1\n\n"
        "Tree 2\n"
        "1,1,1,1,2,1,1,1,1,1,1,1,1,2,3,3,1,1,1,1,2,1,1,1,1,1,1,1,2,1,1,1,1,1,1,1,1,2,2,1,1"

    
    
    )    
    if st.button("Prepare download"):
      st.download_button(label="Download text",data=message,file_name="message.txt",on_click="ignore",type="primary",icon=":material/download:")
    
    st.markdown("🎉 IDS Pipeline Complete — Ready for deployment to IoT Environment!")
   

    
    
def Decision_Tree():
   st.markdown("# Decision Tree Model")
   st.markdown("##Load The NSW-15NB Dataset")
   uploaded_files = st.file_uploader("Upload data", accept_multiple_files=True, type="csv")
   for uploaded_file in uploaded_files:
    df = pd.DataFrame(pd.read_csv(uploaded_file))
    st.write(df)
    st.markdown("## Data Analysis")
    
    st.markdown(f"   Total Samples  : {df.shape[0]:,}")
    st.markdown(f"   Total Features : {df.shape[1] - 1}")

    Df_Attack=df['attack_cat']
    Df_is_ftp_login=df['is_ftp_login']
    Df_ct_dst_ltm=df['ct_dst_ltm']
    Df_ct_srv_dst=df['ct_srv_dst'] 
    Df_Ct_ftp_cmd=df['ct_ftp_cmd']
    Df_Ct_Dst_src_ltm=df['ct_dst_src_ltm']
    Df_Ct_flw_http_mthd=df['ct_flw_http_mthd']

   
    fig, axes = plt.subplots(2, figsize=(14, 5))

    Df_Attack.value_counts().head(10).plot(
    kind='barh', ax=axes[0],
    color=sns.color_palette('coolwarm', 10))
    axes[0].set_title('Top 10 Traffic Categories')
    plt.tight_layout()
    plt.show()
    st.pyplot(fig)
    st.markdown("#Traffic Description ")
    st.markdown("3: Exploits")
    st.markdown("2: DoS")
    st.markdown("1: Normal")
    

    conditions=[
       
        
            
            (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 1.5) & (Df_Ct_flw_http_mthd<= 0.5)&(Df_Ct_Dst_src_ltm<= 1.5)&(Df_is_ftp_login<= 0.5),#3
            (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 1.5) & (Df_Ct_flw_http_mthd<= 2.5)&(Df_Ct_Dst_src_ltm<= 1.5)&(Df_is_ftp_login> 0.5),#1
            (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 1.5) & (Df_Ct_flw_http_mthd <=2.5)& (Df_Ct_flw_http_mthd >0.5)&(Df_Ct_Dst_src_ltm<= 1.5),#3
            (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 1.5) & (Df_Ct_flw_http_mthd >2.5)&(Df_Ct_Dst_src_ltm<= 1.5),#1
            (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 1.5) & (Df_ct_dst_ltm <= 2.5) & ( Df_is_ftp_login <= 0.5)&(Df_Ct_Dst_src_ltm<= 1.5)& (Df_Ct_flw_http_mthd <=5),#1
            (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 1.5) & (Df_ct_dst_ltm <= 2.5)&( Df_is_ftp_login <= 0.5)&(Df_Ct_Dst_src_ltm<= 1.5)& (Df_Ct_flw_http_mthd >5),#1
            (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 1.5)& (Df_ct_dst_ltm <= 2.5) & ( Df_is_ftp_login > 0.5)&(Df_Ct_Dst_src_ltm<= 1.5),#1

            (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 1.5) &(Df_Ct_Dst_src_ltm<= 26)&(Df_Ct_Dst_src_ltm> 1.5),#3
            (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 2.5) &(Df_Ct_Dst_src_ltm <= 47)&(Df_Ct_Dst_src_ltm> 26),#1
            (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 1.5) &(Df_Ct_Dst_src_ltm > 47),#3
            (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 1.5)  & (Df_ct_dst_ltm <= 2.5)&(Df_Ct_Dst_src_ltm > 1.5)&(Df_Ct_flw_http_mthd <= 0.5)&(Df_Ct_ftp_cmd <= 0.5),#3
            (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 1.5) & (Df_ct_dst_ltm <= 2.5)&(Df_Ct_Dst_src_ltm > 1.5)&(Df_Ct_flw_http_mthd <= 0.5)&(Df_Ct_ftp_cmd > 0.5),#3
            (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 1.5)& (Df_ct_dst_ltm <=2.5) &(Df_Ct_Dst_src_ltm > 1.5)&(Df_Ct_flw_http_mthd <= 1.5),#3
            (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 1.5) & (Df_ct_dst_ltm <= 2.5) &(Df_Ct_Dst_src_ltm > 1.5)&(Df_Ct_flw_http_mthd > 1.5),#1
            
            (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 4.5)& (Df_ct_dst_ltm > 2.5) &(Df_Ct_Dst_src_ltm <= 2.5),#1
            (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 4.5)& (Df_ct_dst_ltm > 2.5) &(Df_Ct_Dst_src_ltm <= 8.5)  &(Df_Ct_Dst_src_ltm > 2.5),#3
            (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 4.5) &(Df_Ct_Dst_src_ltm <= 8.5)&(Df_Ct_ftp_cmd <= 0.5),#1
            (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 4.5) &(Df_Ct_Dst_src_ltm <= 8.5)&(Df_Ct_ftp_cmd > 0.5),#1
            (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 2.5) &(Df_Ct_Dst_src_ltm > 8.5)&(Df_Ct_Dst_src_ltm <= 9.5),#2
            (Df_ct_srv_dst<= 1.5 )  & (Df_ct_dst_ltm > 2.5)& (Df_ct_dst_ltm <= 4) &(Df_Ct_Dst_src_ltm <= 12)&(Df_Ct_Dst_src_ltm > 9.5),#3
            (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 4) &(Df_Ct_Dst_src_ltm <= 12)&(Df_Ct_Dst_src_ltm > 9.5),#1
            
           
            (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 2.5) &(Df_Ct_Dst_src_ltm <= 23.5) &(Df_Ct_Dst_src_ltm > 12),#3
            (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 2.5) &(Df_Ct_Dst_src_ltm > 23.5)&(Df_Ct_Dst_src_ltm <= 28.5),#3
            (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 2.5) &(Df_Ct_Dst_src_ltm > 28.5),#1
            (Df_ct_srv_dst > 1.5 ) & (Df_ct_srv_dst <= 2.5) & (Df_ct_dst_ltm <= 1.5) &(Df_Ct_Dst_src_ltm <= 1.5),#1
            (Df_ct_srv_dst > 1.5 )  & (Df_ct_srv_dst <= 2.5)&(Df_Ct_Dst_src_ltm <= 1.5)& (Df_ct_dst_ltm > 1.5) &(Df_ct_dst_ltm <=2.5),#1
            (Df_ct_srv_dst <= 2.5 ) & (Df_ct_srv_dst > 1.5) & (Df_ct_dst_ltm <= 1.5) &(Df_Ct_Dst_src_ltm > 1.5)&(Df_Ct_Dst_src_ltm <= 3.5),#1
            (Df_ct_srv_dst <= 2.5 ) & (Df_ct_srv_dst >1.5)& (Df_ct_dst_ltm <= 2.5)& (Df_ct_dst_ltm > 1.5) &(Df_Ct_Dst_src_ltm > 1.5)&(Df_Ct_Dst_src_ltm <= 3.5),#1
            (Df_ct_srv_dst <= 8.5 )& (Df_ct_srv_dst > 2.5) & (Df_ct_dst_ltm <= 2.5) &(Df_Ct_Dst_src_ltm <= 2.5),  #1
            (Df_ct_srv_dst <= 8.5 ) & (Df_ct_srv_dst > 2.5)  & (Df_ct_dst_ltm <= 2.5) &(Df_Ct_Dst_src_ltm > 2.5)&(Df_Ct_Dst_src_ltm <= 3.5),  #1

            (Df_ct_srv_dst > 8.5 ) & (Df_ct_dst_ltm <= 2.5) &(Df_Ct_Dst_src_ltm <= 1.5),  #1
            (Df_ct_srv_dst > 8.5 )& (Df_ct_dst_ltm <= 2.5) & (Df_Ct_Dst_src_ltm<= 3.5) &(Df_Ct_Dst_src_ltm > 1.5),  #3
            (Df_ct_srv_dst > 1.5 ) & (Df_ct_dst_ltm <= 3.5)& (Df_ct_dst_ltm > 2.5) &(Df_Ct_Dst_src_ltm <= 2.5)&(Df_Ct_flw_http_mthd <= 2.5),#1
            (Df_ct_srv_dst > 1.5 ) & (Df_ct_dst_ltm <= 3.5)& (Df_ct_dst_ltm > 2.5) &(Df_Ct_Dst_src_ltm <= 2.5)&(Df_Ct_flw_http_mthd > 2.5),#1
            (Df_ct_srv_dst <= 14.5 )& (Df_ct_srv_dst > 1.5) & (Df_ct_dst_ltm <= 3.5)& (Df_ct_dst_ltm > 2.5) &(Df_Ct_Dst_src_ltm > 2.5),#1
            (Df_ct_srv_dst > 14.5 )  & (Df_ct_dst_ltm <= 3.5) & (Df_ct_dst_ltm > 2.5)&(Df_Ct_Dst_src_ltm > 2.5)&(Df_Ct_Dst_src_ltm <=3.5),#3

            (Df_ct_srv_dst <= 22.5 ) &(Df_ct_srv_dst > 1.5 )& (Df_ct_dst_ltm > 3.5) &(Df_Ct_Dst_src_ltm <= 3.5),#1
            (Df_ct_srv_dst > 22.5 ) & (Df_ct_dst_ltm > 3.5) &(Df_Ct_Dst_src_ltm <= 3.5),#1
            (Df_ct_srv_dst > 25 ) & (Df_ct_dst_ltm > 3.5) &(Df_Ct_Dst_src_ltm <= 2),#3
            (Df_ct_srv_dst > 25 ) & (Df_ct_dst_ltm > 3.5)&(Df_Ct_Dst_src_ltm <= 3.5) &(Df_Ct_Dst_src_ltm > 2),#2
            (Df_ct_srv_dst > 1.5 ) & (Df_ct_dst_ltm <= 1.5) &(Df_Ct_Dst_src_ltm > 3.5)&(Df_Ct_Dst_src_ltm <= 7.5)& (Df_Ct_flw_http_mthd <= 0.5),#1
            (Df_ct_srv_dst > 1.5 ) & (Df_ct_dst_ltm <= 1.5) &(Df_Ct_Dst_src_ltm > 7.5)& (Df_Ct_flw_http_mthd <= 0.5),#1
            (Df_ct_srv_dst <= 3.5 ) & (Df_ct_srv_dst > 1.5 )& (Df_ct_dst_ltm <= 1.5) &(Df_Ct_Dst_src_ltm > 3.5)& (Df_Ct_flw_http_mthd > 0.5),#1
            (Df_ct_srv_dst > 3.5 ) & (Df_ct_dst_ltm <= 1.5) &(Df_Ct_Dst_src_ltm > 3.5)& (Df_Ct_flw_http_mthd > 0.5),#1
            (Df_ct_srv_dst <= 10.5 ) & (Df_ct_srv_dst > 1.5 )& (Df_ct_dst_ltm > 1.5) & (Df_ct_dst_ltm <= 6.5)&(Df_Ct_Dst_src_ltm <= 10.5)&(Df_Ct_Dst_src_ltm > 3.5),#1
            (Df_ct_srv_dst > 10.5 ) & (Df_ct_dst_ltm > 1.5) & (Df_ct_dst_ltm <= 6.5)&(Df_Ct_Dst_src_ltm <= 10.5),#3
            (Df_ct_srv_dst <= 2.5 ) &(Df_ct_srv_dst > 1.5 )& (Df_ct_dst_ltm > 1.5) & (Df_ct_dst_ltm <= 6.5)&(Df_Ct_Dst_src_ltm > 10.5),#1
            (Df_ct_srv_dst > 2.5 ) & (Df_ct_dst_ltm > 1.5)& (Df_ct_dst_ltm <= 6.5) &(Df_Ct_Dst_src_ltm > 10.5),#1

            (Df_ct_srv_dst > 1.5 ) & (Df_ct_dst_ltm <= 8.5)& (Df_ct_dst_ltm > 6.5) &(Df_Ct_Dst_src_ltm <= 9.5)&(Df_Ct_Dst_src_ltm > 3.5),#1
            (Df_ct_srv_dst > 1.5 ) & (Df_ct_dst_ltm > 8.5) &(Df_Ct_Dst_src_ltm <= 9.5)&(Df_Ct_Dst_src_ltm > 3.5),#1   
            (Df_ct_srv_dst > 1.5 ) & (Df_ct_dst_ltm <= 9.5) & (Df_ct_dst_ltm > 6.5)&(Df_Ct_Dst_src_ltm > 9.5)&(Df_Ct_Dst_src_ltm <= 14.5),#1
            (Df_ct_srv_dst > 1.5 ) & (Df_ct_dst_ltm > 9.5) &(Df_Ct_Dst_src_ltm > 9.5)&(Df_Ct_Dst_src_ltm <= 14.5),#3
            
            (Df_ct_srv_dst > 1.5 ) &  (Df_ct_srv_dst <= 2.5 )& (Df_ct_dst_ltm <= 7.5)& (Df_ct_dst_ltm > 6.5) &(Df_Ct_Dst_src_ltm > 14.5),#1
            (Df_ct_srv_dst > 1.5 )&  (Df_ct_srv_dst <= 2.5 ) & (Df_ct_dst_ltm > 7.5) &(Df_Ct_Dst_src_ltm > 14.5),#3
             (Df_ct_srv_dst > 2.5 )& (Df_ct_dst_ltm > 6.5) &(Df_Ct_Dst_src_ltm > 14.5),#1

        ]
    
    Type_attack=[3,1,3,1,1,1,1,
                 3,1,3,3,3,3,1,
                 1,3,1,1,2,3,1,
                 3,3,1,1,1,1,1,
                 1,1,1,3,1,1,1,
                 3,1,1,3,2,1,1,
                 1,1,1,3,1,1,1,
                 1,1,3,1,3,1]
    

    result=np.select(conditions,Type_attack)

  

    st.markdown("### Decision Tree Diagram ")
    x = df[['ct_dst_ltm','is_ftp_login','ct_srv_dst','ct_dst_src_ltm','ct_flw_http_mthd','ct_ftp_cmd']]
    y = df[['attack_cat']]
    x_train,x_test,y_train,y_test = train_test_split (x,y, test_size = 0.45, random_state = 20)
    decision_tree = DecisionTreeClassifier(random_state=20, max_depth=6)
    decision_tree = decision_tree.fit(x_train,y_train)
    r = export_text(decision_tree,spacing=3,feature_names=['ct_dst_ltm','is_ftp_login','ct_srv_dst','Ct_Dst_src_ltm','Ct_flw_http_mthd','Ct_ftp_cmd'])
    start = time.time()

   
    st.write(f"🔀 Train/Test Split:")
    st.write(f"   Training samples : {x_train.shape[0]:,}")
    st.write(f"   Testing samples  : {x_test.shape[0]:,}")

    st.text(r)
    st.write(tree.plot_tree(decision_tree))
    
    st.markdown("""\n""")
    st.markdown("## Result")
    st.markdown("""\n""")
    st.markdown("""\n""")
    df_result=pd.DataFrame(result,columns=['Result'])
    st.dataframe(df_result,hide_index=True) 


    st.markdown("#Result Description ")
    st.markdown("3: Exploits")
    st.markdown("2: DoS")
    st.markdown("1: Normal")
    elapsed = time.time() - start
    st.write(f"✅ Training completed in {elapsed:.2f} seconds")

    st.markdown("""\n""")
    st.download_button(
        "Download the result .csv",
        df_result.to_csv(index=None).encode("utf-8"),
        "Decision Tree Model Detection Result.csv",
        "text/csv",
        key="download-csv",
    )
    
   
    st.markdown("""\n""")
    st.markdown("### Upload Result data to show the accuracy Intrusion detection")

    uploaded_files = st.file_uploader("Upload Result data", accept_multiple_files=True, type="csv")
    for uploaded_file in uploaded_files:
     df_predict = pd.DataFrame(pd.read_csv(uploaded_file))
     
     y_true = df['attack_cat']
     y_pred = df_predict['Result']
     target_names = ['Normal', 'DoS','Exploits']

     st.text(classification_report(y_true, y_pred, target_names=target_names))

     st.text_area(classification_report(y_true, y_pred, target_names=target_names,digits=4))
     cm = confusion_matrix(y_true, y_pred)
     fig, ax = plt.subplots(figsize=(3, 4))
     sns.heatmap(cm, annot=True, fmt=',', cmap='Blues',xticklabels=target_names,yticklabels=target_names, ax=ax)
     ax.set_xlabel('Predicted Label')
     ax.set_ylabel('True Label')
     ax.set_title('Confusion Matrix — Decision Tree IDS')
     st.pyplot(fig)

    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel().tolist()
    st.text(tn, fp, fn, tp)
    

    st.markdown("""\n""")
    st.markdown("### Save Model ")
     
    message = st.text_area("Model and Conditions", value="Tree 1\n"
 
    "(Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 1.5) & (Df_Ct_flw_http_mthd<= 0.5)&(Df_Ct_Dst_src_ltm<= 1.5)&(Df_is_ftp_login<= 0.5),\n"
    "(Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 1.5) & (Df_Ct_flw_http_mthd<= 2.5)&(Df_Ct_Dst_src_ltm<= 1.5)&(Df_is_ftp_login> 0.5),\n"
    "(Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 1.5) & (Df_Ct_flw_http_mthd <=2.5)& (Df_Ct_flw_http_mthd >0.5)&(Df_Ct_Dst_src_ltm<= 1.5),\n"
    "(Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 1.5) & (Df_Ct_flw_http_mthd >2.5)&(Df_Ct_Dst_src_ltm<= 1.5),\n"
    "(Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 1.5) & (Df_ct_dst_ltm <= 2.5) & ( Df_is_ftp_login <= 0.5)&(Df_Ct_Dst_src_ltm<= 1.5)& (Df_Ct_flw_http_mthd <=5),\n"
    "(Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 1.5) & (Df_ct_dst_ltm <= 2.5)&( Df_is_ftp_login <= 0.5)&(Df_Ct_Dst_src_ltm<= 1.5)& (Df_Ct_flw_http_mthd >5),\n"
    "(Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 1.5)& (Df_ct_dst_ltm <= 2.5) & ( Df_is_ftp_login > 0.5)&(Df_Ct_Dst_src_ltm<= 1.5),\n"
    "(Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 1.5) &(Df_Ct_Dst_src_ltm<= 26)&(Df_Ct_Dst_src_ltm> 1.5),\n"
    "(Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 2.5) &(Df_Ct_Dst_src_ltm <= 47)&(Df_Ct_Dst_src_ltm> 26),\n"
    "(Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 1.5) &(Df_Ct_Dst_src_ltm > 47),\n"
    "(Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 1.5)  & (Df_ct_dst_ltm <= 2.5)&(Df_Ct_Dst_src_ltm > 1.5)&(Df_Ct_flw_http_mthd <= 0.5)&(Df_Ct_ftp_cmd <= 0.5),\n"
    "(Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 1.5) & (Df_ct_dst_ltm <= 2.5)&(Df_Ct_Dst_src_ltm > 1.5)&(Df_Ct_flw_http_mthd <= 0.5)&(Df_Ct_ftp_cmd > 0.5),\n"
    "(Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 1.5)& (Df_ct_dst_ltm <=2.5) &(Df_Ct_Dst_src_ltm > 1.5)&(Df_Ct_flw_http_mthd <= 1.5),\n"
    "(Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 1.5) & (Df_ct_dst_ltm <= 2.5) &(Df_Ct_Dst_src_ltm > 1.5)&(Df_Ct_flw_http_mthd > 1.5),\n"
    "(Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 4.5)& (Df_ct_dst_ltm > 2.5) &(Df_Ct_Dst_src_ltm <= 2.5),\n"
    "(Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 4.5)& (Df_ct_dst_ltm > 2.5) &(Df_Ct_Dst_src_ltm <= 8.5)  &(Df_Ct_Dst_src_ltm > 2.5),\n"
    "(Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 4.5) &(Df_Ct_Dst_src_ltm <= 8.5)&(Df_Ct_ftp_cmd <= 0.5),\n"
    "(Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 4.5) &(Df_Ct_Dst_src_ltm <= 8.5)&(Df_Ct_ftp_cmd > 0.5),\n"
    "(Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 2.5) &(Df_Ct_Dst_src_ltm > 8.5)&(Df_Ct_Dst_src_ltm <= 9.5),\n"
    "(Df_ct_srv_dst<= 1.5 )  & (Df_ct_dst_ltm > 2.5)& (Df_ct_dst_ltm <= 4) &(Df_Ct_Dst_src_ltm <= 12)&(Df_Ct_Dst_src_ltm > 9.5),\n"
    "(Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 4) &(Df_Ct_Dst_src_ltm <= 12)&(Df_Ct_Dst_src_ltm > 9.5),\n"
    "(Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 2.5) &(Df_Ct_Dst_src_ltm <= 23.5) &(Df_Ct_Dst_src_ltm > 12),\n"
    "(Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 2.5) &(Df_Ct_Dst_src_ltm > 23.5)&(Df_Ct_Dst_src_ltm <= 28.5),\n"
    "(Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 2.5) &(Df_Ct_Dst_src_ltm > 28.5),\n"
    "(Df_ct_srv_dst > 1.5 ) & (Df_ct_srv_dst <= 2.5) & (Df_ct_dst_ltm <= 1.5) &(Df_Ct_Dst_src_ltm <= 1.5),\n"
    "(Df_ct_srv_dst > 1.5 )  & (Df_ct_srv_dst <= 2.5)&(Df_Ct_Dst_src_ltm <= 1.5)& (Df_ct_dst_ltm > 1.5) &(Df_ct_dst_ltm <=2.5),\n"
    "(Df_ct_srv_dst <= 2.5 ) & (Df_ct_srv_dst > 1.5) & (Df_ct_dst_ltm <= 1.5) &(Df_Ct_Dst_src_ltm > 1.5)&(Df_Ct_Dst_src_ltm <= 3.5),\n"
    "(Df_ct_srv_dst <= 2.5 ) & (Df_ct_srv_dst >1.5)& (Df_ct_dst_ltm <= 2.5)& (Df_ct_dst_ltm > 1.5) &(Df_Ct_Dst_src_ltm > 1.5)&(Df_Ct_Dst_src_ltm <= 3.5),\n"
    "(Df_ct_srv_dst <= 8.5 )& (Df_ct_srv_dst > 2.5) & (Df_ct_dst_ltm <= 2.5) &(Df_Ct_Dst_src_ltm <= 2.5),  \n"
    "(Df_ct_srv_dst <= 8.5 ) & (Df_ct_srv_dst > 2.5)  & (Df_ct_dst_ltm <= 2.5) &(Df_Ct_Dst_src_ltm > 2.5)&(Df_Ct_Dst_src_ltm <= 3.5),\n  "
    "(Df_ct_srv_dst > 8.5 ) & (Df_ct_dst_ltm <= 2.5) &(Df_Ct_Dst_src_ltm <= 1.5),  \n"
    "(Df_ct_srv_dst > 8.5 )& (Df_ct_dst_ltm <= 2.5) & (Df_Ct_Dst_src_ltm<= 3.5) &(Df_Ct_Dst_src_ltm > 1.5), \n "
    "(Df_ct_srv_dst > 1.5 ) & (Df_ct_dst_ltm <= 3.5)& (Df_ct_dst_ltm > 2.5) &(Df_Ct_Dst_src_ltm <= 2.5)&(Df_Ct_flw_http_mthd <= 2.5),\n"
    "(Df_ct_srv_dst > 1.5 ) & (Df_ct_dst_ltm <= 3.5)& (Df_ct_dst_ltm > 2.5) &(Df_Ct_Dst_src_ltm <= 2.5)&(Df_Ct_flw_http_mthd > 2.5),\n"
    "(Df_ct_srv_dst <= 14.5 )& (Df_ct_srv_dst > 1.5) & (Df_ct_dst_ltm <= 3.5)& (Df_ct_dst_ltm > 2.5) &(Df_Ct_Dst_src_ltm > 2.5),\n"
    "(Df_ct_srv_dst > 14.5 )  & (Df_ct_dst_ltm <= 3.5) & (Df_ct_dst_ltm > 2.5)&(Df_Ct_Dst_src_ltm > 2.5)&(Df_Ct_Dst_src_ltm <=3.5),\n"
    "(Df_ct_srv_dst <= 22.5 ) &(Df_ct_srv_dst > 1.5 )& (Df_ct_dst_ltm > 3.5) &(Df_Ct_Dst_src_ltm <= 3.5),\n"
    "(Df_ct_srv_dst > 22.5 ) & (Df_ct_dst_ltm > 3.5) &(Df_Ct_Dst_src_ltm <= 3.5),\n"
    "(Df_ct_srv_dst > 25 ) & (Df_ct_dst_ltm > 3.5) &(Df_Ct_Dst_src_ltm <= 2),\n"
    "(Df_ct_srv_dst > 25 ) & (Df_ct_dst_ltm > 3.5)&(Df_Ct_Dst_src_ltm <= 3.5) &(Df_Ct_Dst_src_ltm > 2),\n"
    "(Df_ct_srv_dst > 1.5 ) & (Df_ct_dst_ltm <= 1.5) &(Df_Ct_Dst_src_ltm > 3.5)&(Df_Ct_Dst_src_ltm <= 7.5)& (Df_Ct_flw_http_mthd <= 0.5),\n"
    "(Df_ct_srv_dst > 1.5 ) & (Df_ct_dst_ltm <= 1.5) &(Df_Ct_Dst_src_ltm > 7.5)& (Df_Ct_flw_http_mthd <= 0.5),\n"
    "(Df_ct_srv_dst <= 3.5 ) & (Df_ct_srv_dst > 1.5 )& (Df_ct_dst_ltm <= 1.5) &(Df_Ct_Dst_src_ltm > 3.5)& (Df_Ct_flw_http_mthd > 0.5),\n"
    "(Df_ct_srv_dst > 3.5 ) & (Df_ct_dst_ltm <= 1.5) &(Df_Ct_Dst_src_ltm > 3.5)& (Df_Ct_flw_http_mthd > 0.5),\n"
    " (Df_ct_srv_dst <= 10.5 ) & (Df_ct_srv_dst > 1.5 )& (Df_ct_dst_ltm > 1.5) & (Df_ct_dst_ltm <= 6.5)&(Df_Ct_Dst_src_ltm <= 10.5)&(Df_Ct_Dst_src_ltm > 3.5),\n"
    "(Df_ct_srv_dst > 10.5 ) & (Df_ct_dst_ltm > 1.5) & (Df_ct_dst_ltm <= 6.5)&(Df_Ct_Dst_src_ltm <= 10.5),\n"
    "(Df_ct_srv_dst <= 2.5 ) &(Df_ct_srv_dst > 1.5 )& (Df_ct_dst_ltm > 1.5) & (Df_ct_dst_ltm <= 6.5)&(Df_Ct_Dst_src_ltm > 10.5),\n"
    "(Df_ct_srv_dst > 2.5 ) & (Df_ct_dst_ltm > 1.5)& (Df_ct_dst_ltm <= 6.5) &(Df_Ct_Dst_src_ltm > 10.5),\n"
    " (Df_ct_srv_dst > 1.5 ) & (Df_ct_dst_ltm <= 8.5)& (Df_ct_dst_ltm > 6.5) &(Df_Ct_Dst_src_ltm <= 9.5)&(Df_Ct_Dst_src_ltm > 3.5),\n"
    "(Df_ct_srv_dst > 1.5 ) & (Df_ct_dst_ltm > 8.5) &(Df_Ct_Dst_src_ltm <= 9.5)&(Df_Ct_Dst_src_ltm > 3.5),\n"
    "(Df_ct_srv_dst > 1.5 ) & (Df_ct_dst_ltm <= 9.5) & (Df_ct_dst_ltm > 6.5)&(Df_Ct_Dst_src_ltm > 9.5)&(Df_Ct_Dst_src_ltm <= 14.5),\n"
    "(Df_ct_srv_dst > 1.5 ) & (Df_ct_dst_ltm > 9.5) &(Df_Ct_Dst_src_ltm > 9.5)&(Df_Ct_Dst_src_ltm <= 14.5),\n"
    "(Df_ct_srv_dst > 1.5 ) &  (Df_ct_srv_dst <= 2.5 )& (Df_ct_dst_ltm <= 7.5)& (Df_ct_dst_ltm > 6.5) &(Df_Ct_Dst_src_ltm > 14.5),\n"
    "(Df_ct_srv_dst > 1.5 )&  (Df_ct_srv_dst <= 2.5 ) & (Df_ct_dst_ltm > 7.5) &(Df_Ct_Dst_src_ltm > 14.5),\n"
    "(Df_ct_srv_dst > 2.5 )& (Df_ct_dst_ltm > 6.5) &(Df_Ct_Dst_src_ltm > 14.5)\n\n"
    )
    if st.button("Prepare download"):
      st.download_button(label="Download text",data=message,file_name="message.txt",on_click="ignore",type="primary",icon=":material/download:")
    
    st.markdown("🎉 IDS Pipeline Complete — Ready for deployment to IoT Environment!")



def InfluxDB():
    

    
    org = "CQU"
    host = "https://us-east-1-1.aws.cloud2.influxdata.com"

    client = InfluxDBClient3(host=host, token="eL95h-pilVCJ3G1rZfB3J26H82XuDjsHPzUSOPjMwHdvQrWun8_gxEFJlonfT4CCHeKqoEKvxNKqR_NNhoOQrw==", org=org,disable_grpc_compression=True)
    
    database="Test"

    query = """SELECT *
    FROM 'Network2'
    WHERE time >= now() - interval '24 hours'"""
    

    
    table = client.query(query=query, database="Test", language='sql') 
    
    df1 = table.to_pandas().sort_values(by="time")
    df = pd.DataFrame(df1)
    st.write(df)

    st.markdown(f"   Total Samples  : {df.shape[0]:,}")
    st.markdown(f"   Total Features : {df.shape[1] - 1}")

    Df_Attack=df['Attack_cat']
    Df_is_ftp_login=df['Is_ftp_login']
    Df_ct_dst_ltm=df['Ct_dst_ltm']
    Df_ct_srv_dst=df['Ct_srv_dst'] 
    Df_Ct_ftp_cmd=df['Ct_ftp_cmd']
    Df_Ct_Dst_src_ltm=df['Ct_dst_src_ltm']
    Df_Ct_flw_http_mthd=df['Ct_flw_http_mthd']

   
 

    conditions=[
       
            
            (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 1.5) & (Df_Ct_flw_http_mthd<= 0.5)&(Df_Ct_Dst_src_ltm<= 1.5)&(Df_is_ftp_login<= 0.5),#3
            (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 1.5) & (Df_Ct_flw_http_mthd<= 2.5)&(Df_Ct_Dst_src_ltm<= 1.5)&(Df_is_ftp_login> 0.5),#1
            (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 1.5) & (Df_Ct_flw_http_mthd <=2.5)& (Df_Ct_flw_http_mthd >0.5)&(Df_Ct_Dst_src_ltm<= 1.5),#3
            (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 1.5) & (Df_Ct_flw_http_mthd >2.5)&(Df_Ct_Dst_src_ltm<= 1.5),#1
            (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 1.5) & (Df_ct_dst_ltm <= 2.5) & ( Df_is_ftp_login <= 0.5)&(Df_Ct_Dst_src_ltm<= 1.5)& (Df_Ct_flw_http_mthd <=5),#1
            (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 1.5) & (Df_ct_dst_ltm <= 2.5)&( Df_is_ftp_login <= 0.5)&(Df_Ct_Dst_src_ltm<= 1.5)& (Df_Ct_flw_http_mthd >5),#1
            (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 1.5)& (Df_ct_dst_ltm <= 2.5) & ( Df_is_ftp_login > 0.5)&(Df_Ct_Dst_src_ltm<= 1.5),#1

            (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 1.5) &(Df_Ct_Dst_src_ltm<= 26)&(Df_Ct_Dst_src_ltm> 1.5),#3
            (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 2.5) &(Df_Ct_Dst_src_ltm <= 47)&(Df_Ct_Dst_src_ltm> 26),#1
            (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 1.5) &(Df_Ct_Dst_src_ltm > 47),#3
            (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 1.5)  & (Df_ct_dst_ltm <= 2.5)&(Df_Ct_Dst_src_ltm > 1.5)&(Df_Ct_flw_http_mthd <= 0.5)&(Df_Ct_ftp_cmd <= 0.5),#3
            (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 1.5) & (Df_ct_dst_ltm <= 2.5)&(Df_Ct_Dst_src_ltm > 1.5)&(Df_Ct_flw_http_mthd <= 0.5)&(Df_Ct_ftp_cmd > 0.5),#3
            (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 1.5)& (Df_ct_dst_ltm <=2.5) &(Df_Ct_Dst_src_ltm > 1.5)&(Df_Ct_flw_http_mthd <= 1.5),#3
            (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 1.5) & (Df_ct_dst_ltm <= 2.5) &(Df_Ct_Dst_src_ltm > 1.5)&(Df_Ct_flw_http_mthd > 1.5),#1
            
            (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 4.5)& (Df_ct_dst_ltm > 2.5) &(Df_Ct_Dst_src_ltm <= 2.5),#1
            (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm <= 4.5)& (Df_ct_dst_ltm > 2.5) &(Df_Ct_Dst_src_ltm <= 8.5)  &(Df_Ct_Dst_src_ltm > 2.5),#3
            (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 4.5) &(Df_Ct_Dst_src_ltm <= 8.5)&(Df_Ct_ftp_cmd <= 0.5),#1
            (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 4.5) &(Df_Ct_Dst_src_ltm <= 8.5)&(Df_Ct_ftp_cmd > 0.5),#1
            (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 2.5) &(Df_Ct_Dst_src_ltm > 8.5)&(Df_Ct_Dst_src_ltm <= 9.5),#2
            (Df_ct_srv_dst<= 1.5 )  & (Df_ct_dst_ltm > 2.5)& (Df_ct_dst_ltm <= 4) &(Df_Ct_Dst_src_ltm <= 12)&(Df_Ct_Dst_src_ltm > 9.5),#3
            (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 4) &(Df_Ct_Dst_src_ltm <= 12)&(Df_Ct_Dst_src_ltm > 9.5),#1
            
           
            (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 2.5) &(Df_Ct_Dst_src_ltm <= 23.5) &(Df_Ct_Dst_src_ltm > 12),#3
            (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 2.5) &(Df_Ct_Dst_src_ltm > 23.5)&(Df_Ct_Dst_src_ltm <= 28.5),#3
            (Df_ct_srv_dst<= 1.5 ) & (Df_ct_dst_ltm > 2.5) &(Df_Ct_Dst_src_ltm > 28.5),#1
            (Df_ct_srv_dst > 1.5 ) & (Df_ct_srv_dst <= 2.5) & (Df_ct_dst_ltm <= 1.5) &(Df_Ct_Dst_src_ltm <= 1.5),#1
            (Df_ct_srv_dst > 1.5 )  & (Df_ct_srv_dst <= 2.5)&(Df_Ct_Dst_src_ltm <= 1.5)& (Df_ct_dst_ltm > 1.5) &(Df_ct_dst_ltm <=2.5),#1
            (Df_ct_srv_dst <= 2.5 ) & (Df_ct_srv_dst > 1.5) & (Df_ct_dst_ltm <= 1.5) &(Df_Ct_Dst_src_ltm > 1.5)&(Df_Ct_Dst_src_ltm <= 3.5),#1
            (Df_ct_srv_dst <= 2.5 ) & (Df_ct_srv_dst >1.5)& (Df_ct_dst_ltm <= 2.5)& (Df_ct_dst_ltm > 1.5) &(Df_Ct_Dst_src_ltm > 1.5)&(Df_Ct_Dst_src_ltm <= 3.5),#1
            (Df_ct_srv_dst <= 8.5 )& (Df_ct_srv_dst > 2.5) & (Df_ct_dst_ltm <= 2.5) &(Df_Ct_Dst_src_ltm <= 2.5),  #1
            (Df_ct_srv_dst <= 8.5 ) & (Df_ct_srv_dst > 2.5)  & (Df_ct_dst_ltm <= 2.5) &(Df_Ct_Dst_src_ltm > 2.5)&(Df_Ct_Dst_src_ltm <= 3.5),  #1

            (Df_ct_srv_dst > 8.5 ) & (Df_ct_dst_ltm <= 2.5) &(Df_Ct_Dst_src_ltm <= 1.5),  #1
            (Df_ct_srv_dst > 8.5 )& (Df_ct_dst_ltm <= 2.5) & (Df_Ct_Dst_src_ltm<= 3.5) &(Df_Ct_Dst_src_ltm > 1.5),  #3
            (Df_ct_srv_dst > 1.5 ) & (Df_ct_dst_ltm <= 3.5)& (Df_ct_dst_ltm > 2.5) &(Df_Ct_Dst_src_ltm <= 2.5)&(Df_Ct_flw_http_mthd <= 2.5),#1
            (Df_ct_srv_dst > 1.5 ) & (Df_ct_dst_ltm <= 3.5)& (Df_ct_dst_ltm > 2.5) &(Df_Ct_Dst_src_ltm <= 2.5)&(Df_Ct_flw_http_mthd > 2.5),#1
            (Df_ct_srv_dst <= 14.5 )& (Df_ct_srv_dst > 1.5) & (Df_ct_dst_ltm <= 3.5)& (Df_ct_dst_ltm > 2.5) &(Df_Ct_Dst_src_ltm > 2.5),#1
            (Df_ct_srv_dst > 14.5 )  & (Df_ct_dst_ltm <= 3.5) & (Df_ct_dst_ltm > 2.5)&(Df_Ct_Dst_src_ltm > 2.5)&(Df_Ct_Dst_src_ltm <=3.5),#3

            (Df_ct_srv_dst <= 22.5 ) &(Df_ct_srv_dst > 1.5 )& (Df_ct_dst_ltm > 3.5) &(Df_Ct_Dst_src_ltm <= 3.5),#1
            (Df_ct_srv_dst > 22.5 ) & (Df_ct_dst_ltm > 3.5) &(Df_Ct_Dst_src_ltm <= 3.5),#1
            (Df_ct_srv_dst > 25 ) & (Df_ct_dst_ltm > 3.5) &(Df_Ct_Dst_src_ltm <= 2),#3
            (Df_ct_srv_dst > 25 ) & (Df_ct_dst_ltm > 3.5)&(Df_Ct_Dst_src_ltm <= 3.5) &(Df_Ct_Dst_src_ltm > 2),#2
            (Df_ct_srv_dst > 1.5 ) & (Df_ct_dst_ltm <= 1.5) &(Df_Ct_Dst_src_ltm > 3.5)&(Df_Ct_Dst_src_ltm <= 7.5)& (Df_Ct_flw_http_mthd <= 0.5),#1
            (Df_ct_srv_dst > 1.5 ) & (Df_ct_dst_ltm <= 1.5) &(Df_Ct_Dst_src_ltm > 7.5)& (Df_Ct_flw_http_mthd <= 0.5),#1
            (Df_ct_srv_dst <= 3.5 ) & (Df_ct_srv_dst > 1.5 )& (Df_ct_dst_ltm <= 1.5) &(Df_Ct_Dst_src_ltm > 3.5)& (Df_Ct_flw_http_mthd > 0.5),#1
            (Df_ct_srv_dst > 3.5 ) & (Df_ct_dst_ltm <= 1.5) &(Df_Ct_Dst_src_ltm > 3.5)& (Df_Ct_flw_http_mthd > 0.5),#1
            (Df_ct_srv_dst <= 10.5 ) & (Df_ct_srv_dst > 1.5 )& (Df_ct_dst_ltm > 1.5) & (Df_ct_dst_ltm <= 6.5)&(Df_Ct_Dst_src_ltm <= 10.5)&(Df_Ct_Dst_src_ltm > 3.5),#1
            (Df_ct_srv_dst > 10.5 ) & (Df_ct_dst_ltm > 1.5) & (Df_ct_dst_ltm <= 6.5)&(Df_Ct_Dst_src_ltm <= 10.5),#3
            (Df_ct_srv_dst <= 2.5 ) &(Df_ct_srv_dst > 1.5 )& (Df_ct_dst_ltm > 1.5) & (Df_ct_dst_ltm <= 6.5)&(Df_Ct_Dst_src_ltm > 10.5),#1
            (Df_ct_srv_dst > 2.5 ) & (Df_ct_dst_ltm > 1.5)& (Df_ct_dst_ltm <= 6.5) &(Df_Ct_Dst_src_ltm > 10.5),#1

            (Df_ct_srv_dst > 1.5 ) & (Df_ct_dst_ltm <= 8.5)& (Df_ct_dst_ltm > 6.5) &(Df_Ct_Dst_src_ltm <= 9.5)&(Df_Ct_Dst_src_ltm > 3.5),#1
            (Df_ct_srv_dst > 1.5 ) & (Df_ct_dst_ltm > 8.5) &(Df_Ct_Dst_src_ltm <= 9.5)&(Df_Ct_Dst_src_ltm > 3.5),#1   
            (Df_ct_srv_dst > 1.5 ) & (Df_ct_dst_ltm <= 9.5) & (Df_ct_dst_ltm > 6.5)&(Df_Ct_Dst_src_ltm > 9.5)&(Df_Ct_Dst_src_ltm <= 14.5),#1
            (Df_ct_srv_dst > 1.5 ) & (Df_ct_dst_ltm > 9.5) &(Df_Ct_Dst_src_ltm > 9.5)&(Df_Ct_Dst_src_ltm <= 14.5),#3
            
            (Df_ct_srv_dst > 1.5 ) &  (Df_ct_srv_dst <= 2.5 )& (Df_ct_dst_ltm <= 7.5)& (Df_ct_dst_ltm > 6.5) &(Df_Ct_Dst_src_ltm > 14.5),#1
            (Df_ct_srv_dst > 1.5 )&  (Df_ct_srv_dst <= 2.5 ) & (Df_ct_dst_ltm > 7.5) &(Df_Ct_Dst_src_ltm > 14.5),#3
             (Df_ct_srv_dst > 2.5 )& (Df_ct_dst_ltm > 6.5) &(Df_Ct_Dst_src_ltm > 14.5),#1

        ]
    
    Type_attack=["Exploits","Normal","Exploits","Normal","Normal","Normal","Normal",
                 "Exploits","Normal","Exploits","Exploits","Exploits","Exploits","Normal",
                 "Normal","Exploits","Normal","Normal","DoS","Exploits","Normal",
                 "Exploits","Exploits","Normal","Normal","Normal","Normal","Normal",
                 "Normal","Normal","Normal","Exploits","Normal","Normal","Normal",
                 "Exploits","Normal","Normal","Exploits","DoS","Normal","Normal",
                 "Normal","Normal","Normal","Exploits","Normal","Normal","Normal",
                 "Normal","Normal","Exploits","Normal","Exploits","Normal"]
    

    result=np.select(conditions,Type_attack)


    df_result=pd.DataFrame(result,columns=['Result']) 

    fig, ax = plt.subplots(figsize=(6, 5))
    df_result.value_counts().head(10).plot(
    kind='barh', ax=ax,
    color=sns.color_palette('coolwarm', 10))
    ax.set_xlabel('Type of Attack')
    ax.set_ylabel('Number of Attack')
    ax.set_title('IDS Result')
    plt.tight_layout()
    plt.show()
    st.pyplot(fig)


    
    


broker = 's72d970b.ala.asia-southeast1.emqxsl.com'
port = 8883
topic = 'testtopic/network1' 
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

    return client


 
  
def subscribe(client: mqtt_client):
    def on_message(client, userdata, msg):
        st.text(f"Received `{msg.payload.decode()}` from `{msg.topic}` topic")

    client.subscribe(topic)
    client.on_message = on_message
        
    
def main():
    setup_basic()
    InfluxDB()
    client = connect_mqtt()
    subscribe(client)
    client.loop_forever()

   

    

   


if __name__ == "__main__":
    main()
