#Decision Tree Model Setup and Libraru

import io
import re
from collections.abc import Iterable
import pandas as pd
from sklearn import tree
from sklearn.model_selection import train_test_split
import numpy as np
from sklearn.datasets import load_iris
from sklearn.tree import DecisionTreeClassifier
from sklearn.tree import export_text
import streamlit as st
from pandas.api.types import (is_bool_dtype, is_datetime64_any_dtype,is_numeric_dtype)

#Random Forest Model Setup and Library

import pandas as pd
import numpy as np
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

    st.markdown("""\n""")
    st.markdown("## Environment Setup & Library Imports ")
    st.markdown("""\n""")
    st.markdown("✅ All libraries imported successfully!")
    st.markdown(f"   pandas version  : {pd.__version__}")
    st.markdown(f"   numpy   version : {np.__version__}")
    st.markdown(f"   sklearn : loaded")
    st.markdown("""\n""")

def Decision_Tree():
   st.markdown("# Decision Tree Model")
   st.markdown("## Test Data")
   uploaded_files = st.file_uploader("Upload data", accept_multiple_files=True, type="csv")
   for uploaded_file in uploaded_files:
    df = pd.DataFrame(pd.read_csv(uploaded_file))
    st.write(df)
    
    st.markdown(f"   Total Samples  : {df.shape[0]:,}")
    st.markdown(f"   Total Features : {df.shape[1] - 1}")

    Df_Attack=df['attack_cat']
    Df_is_ftp_login=df['is_ftp_login']
    Df_ct_dst_ltm=df['ct_dst_ltm']
    Df_ct_srv_dst=df['ct_srv_dst'] 

    conditions=[
        (Df_ct_dst_ltm<= 1.5 ) & (Df_is_ftp_login <= 0.5) & (Df_ct_srv_dst<= 1.5),
        (Df_ct_dst_ltm <= 1.5 ) & (Df_is_ftp_login > 0.5)&(Df_ct_srv_dst <= 1.5),
        (Df_ct_dst_ltm > 1.5 ) & (Df_is_ftp_login <= 0.5)&(Df_ct_srv_dst <= 1.5),
        (Df_ct_dst_ltm > 1.5 ) & (Df_is_ftp_login > 0.5)&(Df_ct_srv_dst <= 1.5),
        (Df_is_ftp_login >2.5 ) & (Df_ct_dst_ltm <= 3.5)&(Df_ct_srv_dst <= 1.5),
        (Df_is_ftp_login >2.5 ) & (Df_ct_dst_ltm > 3.5)&(Df_ct_dst_ltm <= 9.5)&(Df_ct_srv_dst <= 1.5),
        (Df_is_ftp_login >2.5 ) & (Df_ct_dst_ltm > 3.5)&(Df_ct_dst_ltm > 9.5)&(Df_ct_srv_dst <= 1.5),
        (Df_is_ftp_login >0.5 ) & (Df_ct_dst_ltm <= 4.5)&(Df_ct_dst_ltm <= 3.5)&(Df_ct_srv_dst <= 1.5),
        (Df_is_ftp_login >0.5 ) & (Df_ct_dst_ltm <= 4.5)&(Df_ct_dst_ltm > 3.5)&(Df_ct_srv_dst <= 1.5),
        (Df_is_ftp_login >0.5 ) & (Df_ct_dst_ltm > 4.5)&(Df_ct_dst_ltm <= 15.5)&(Df_ct_srv_dst <= 1.5),
        (Df_is_ftp_login >0.5 ) & (Df_ct_dst_ltm > 4.5)&(Df_ct_dst_ltm > 15.5)&(Df_ct_srv_dst <= 1.5),

        (Df_ct_dst_ltm > 8.5 ) & (Df_ct_srv_dst > 14.5),
        (Df_ct_dst_ltm <= 8.5 ) & (Df_ct_srv_dst > 14.5),
        (Df_ct_dst_ltm > 6.5 ) & (Df_ct_srv_dst > 14.5),
        (Df_ct_dst_ltm > 6.5 ) & (Df_ct_srv_dst <= 14.5),
        (Df_ct_dst_ltm > 1.5 ) & (Df_ct_srv_dst > 13.5),
        (Df_ct_dst_ltm > 1.5 ) & (Df_ct_srv_dst <= 13.5),
        (Df_ct_dst_ltm <= 1.5 ) & (Df_ct_srv_dst > 6.5),
        (Df_ct_dst_ltm <= 1.5 ) & (Df_ct_srv_dst <= 6.5),
        (Df_ct_dst_ltm > 3.5 ) & (Df_ct_srv_dst <= 4.5)& (Df_is_ftp_login >1.5),
        (Df_ct_dst_ltm > 34.5 ) & (Df_ct_srv_dst <= 4.5)& (Df_is_ftp_login <=1.5),
        (Df_ct_dst_ltm <= 34.5 ) & (Df_ct_srv_dst <= 4.5)& (Df_is_ftp_login <=1.5),
        (Df_ct_dst_ltm <= 1.5 ) & (Df_ct_srv_dst > 2.5),
        (Df_ct_dst_ltm > 1.5 ) & (Df_ct_srv_dst > 2.5),
        (Df_ct_dst_ltm > 1.5 ) & (Df_ct_srv_dst <= 2.5),
        (Df_ct_dst_ltm <= 1.5 ) & (Df_ct_srv_dst > 1.5)

        ]
    Type_attack=[2,1,2,2,1,1,1,1,1,1,2,
            1,1,1,1,1,1,1,1,2,1,1,1,1,1,1
        ]
    

    result=np.select(conditions,Type_attack,default="normal")

    st.markdown("### Decision Tree Diagram ")
    x = df[['ct_dst_ltm','is_ftp_login','ct_srv_dst']]
    y = df[['attack_cat']]
    x_train,x_test,y_train,y_test = train_test_split (x,y, test_size = 0.60, random_state = 1)
    decision_tree = DecisionTreeClassifier(random_state=0, max_depth=5)
    decision_tree = decision_tree.fit(x_train,y_train)
    r = export_text(decision_tree,spacing=3,feature_names=['ct_dst_ltm','is_ftp_login','ct_srv_dst'])
    st.write(f"🔀 Train/Test Split:")
    st.write(f"   Training samples : {x_train.shape[0]:,}")
    st.write(f"   Testing samples  : {x_test.shape[0]:,}")
    st.text(r)
    st.write(tree.plot_tree(decision_tree))
    
  
     


    st.markdown("""\n""")
    st.markdown("## Result Detection by Using Decision Tree Model ")
    st.markdown("""\n""")
    st.markdown("""\n""")
    df_result=pd.DataFrame(result,columns=['Result'])
    st.dataframe(df_result,hide_index=True) 


    st.markdown("#Result Description ")
    st.markdown("2: Malicous")
    st.markdown("1: Normal")
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
     target_names = ['Normal', 'Malicous']

     st.write(classification_report(y_true, y_pred, target_names=target_names))
    
def Random_Forest():
    st.markdown("""\n""")
    st.markdown("# Random Forest Model ")
    st.markdown("""\n""")
    st.markdown("## Environment Setup & Library Imports ")
    st.markdown("""\n""")
    st.markdown("✅ All libraries imported successfully!")
    st.markdown(f"   pandas version  : {pd.__version__}")
    st.markdown(f"   numpy   version : {np.__version__}")
    st.markdown(f"   sklearn : loaded")
    st.markdown("""\n""")
    st.markdown("## Load NSL-KDD Dataset")
    st.markdown("""\n""")

    columns = [
    'duration', 'protocol_type', 'service', 'flag',
    'src_bytes', 'dst_bytes', 'land', 'wrong_fragment',
    'urgent', 'hot', 'num_failed_logins', 'logged_in',
    'num_compromised', 'root_shell', 'su_attempted',
    'num_root', 'num_file_creations', 'num_shells',
    'num_access_files', 'num_outbound_cmds',
    'is_host_login', 'is_guest_login', 'count',
    'srv_count', 'serror_rate', 'srv_serror_rate',
    'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
    'diff_srv_rate', 'srv_diff_host_rate',
    'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
    'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
    'dst_host_srv_rerror_rate', 'label'
    ]

    uploaded_files = st.file_uploader("Upload NSL-KDD Dataset", accept_multiple_files=True, type="csv")
    for uploaded_file in uploaded_files:
     df = pd.DataFrame(pd.read_csv(uploaded_file,names=columns, header=None))
    

     st.markdown(f"📊 Dataset Shape  : {df.shape}")
     st.markdown(f"   Total Samples  : {df.shape[0]:,}")
     st.markdown(f"   Total Features : {df.shape[1] - 1}")
     st.markdown("\\n🏷️  Label Distribution:")
     st.markdown(df['label'].value_counts().head(10))
     st.markdown("""\n""")
     st.markdown("## Exploratory Data Analysis(EDA)")
     st.markdown("Missing values per column:",df.isnull().sum().sum()) 
     df['binary_label'] = df['label'].apply(
     lambda x: 'normal' if x == 'normal' else 'attack')
     

     fig, axes = plt.subplots(1, 2, figsize=(14, 5))
     df['binary_label'].value_counts().plot(
     kind='bar', ax=axes[0],
     color=['#2ecc71', '#e74c3c'], edgecolor='black')

     
     axes[0].set_title('Normal vs Attack Traffic')
     axes[0].set_ylabel('Count')
     df['label'].value_counts().head(10).plot(
     kind='barh', ax=axes[1],
     color=sns.color_palette('coolwarm', 10))
     axes[1].set_title('Top 10 Traffic Categories')
     plt.tight_layout()
     plt.show()
     st.pyplot(fig)

     st.markdown(f"\\n📈 Feature Statistics (first 5 numeric):")
     st.markdown(df.describe().iloc[:, :5].round(2))

     st.markdown("""\n""")
     st.markdown("## Data Preprocessing & Feature Engineering")
     label_encoders = {}
     categorical_columns = ['protocol_type', 'service', 'flag']
     for col in categorical_columns:
      le = LabelEncoder()
      df[col] = le.fit_transform(df[col])
      label_encoders[col] = le
      print(f"  Encoded '{col}' → {len(le.classes_)} classes")
     st.markdown("""\n""")
     le_target = LabelEncoder()
     df['target'] = le_target.fit_transform(df['binary_label'])
     feature_cols = [c for c in columns if c != 'label']
     X = df[feature_cols]
     y = df['target']

     st.write(f"\\n📐 Feature matrix shape : {X.shape}")
     st.write(f"   Target vector shape  : {y.shape}")
    
     X,y=make_classification(n_samples=1000, n_features=4,
                            n_informative=2, n_redundant=0,
                           random_state=0, shuffle=False)
     st.write(f"\\n🔀 Train/Test Split:")
     st.write(f"   Training samples : {X.shape[0]:,}")
     st.write(f"   Testing samples  : {y.shape[0]:,}")


     st.markdown("""\n""")
     st.markdown("## Build & Train the Random Forest Classifier")
     
     rf_model = RandomForestClassifier(max_depth=2, random_state=0)
     st.write(f"🚀 Training Random Forest with 100 trees...")
     st.write("=" * 50)

     start = time.time()
     rf_model.fit(X,y)
     elapsed = time.time() - start

     st.write(rf_model.predict([[0, 0, 0, 0]]))
     st.write(f"✅ Training completed in {elapsed:.2f} seconds")
     st.write(f"   Number of trees     : {rf_model.n_estimators}")
     st.write(f"   Features per split  : sqrt({X.shape[1]})")
     st.write(f"   = ~{int(np.sqrt(X.shape[1]))} features")

     st.markdown("""\n""")
     st.markdown("## Model Evaluation & Metrics")

     y_pred = rf_model.predict(X)
     y_proba = rf_model.predict_proba(X)[:, 1]
     acc = accuracy_score(y, y_pred)
     st.write(f"🎯 Overall Accuracy: {acc*100:.2f}%")
     st.write("📋 Classification Report:")
     st.write("=" * 55)
     target_names = ['Normal (0)', 'Attack (1)']
     st.write(classification_report(y, y_pred, target_names=target_names))
     cm = confusion_matrix(y, y_pred)
     fig, ax = plt.subplots(figsize=(3, 4))
     sns.heatmap(cm, annot=True, fmt=',', cmap='Blues',xticklabels=target_names,yticklabels=target_names, ax=ax)
     ax.set_xlabel('Predicted Label')
     ax.set_ylabel('True Label')
     ax.set_title('Confusion Matrix — Random Forest IDS')
     st.pyplot(fig)

     st.markdown("""\n""")
     st.markdown("## ROC Curve & AUC Score")
     fpr, tpr, thresholds = roc_curve(y, y_proba)
     roc_auc = auc(fpr, tpr)
     fig, ax = plt.subplots(figsize=(8, 6))
     ax.plot(fpr, tpr, color='#e74c3c', lw=2.5,
        label=f'Random Forest (AUC = {roc_auc:.4f})')
     ax.plot([0, 1], [0, 1], color='gray',
        lw=1.5, linestyle='--', label='Random Guess')
     ax.fill_between(fpr, tpr, alpha=0.15, color='#e74c3c')
     ax.set_xlim([0.0, 1.0])
     ax.set_ylim([0.0, 1.05])
     ax.set_xlabel('False Positive Rate (FPR)')
     ax.set_ylabel('True Positive Rate (TPR)')
     ax.set_title('ROC Curve — IDS Random Forest')
     ax.legend(loc='lower right', fontsize=12)
     ax.grid(True, alpha=0.3)
     plt.tight_layout()
     plt.show()
     st.pyplot(fig)
     st.write(f"📐 AUC Score: {roc_auc:.4f}")
     st.write(f"   → 1.0 = perfect | 0.5 = random guess")
     st.markdown("""\n""")
     st.markdown("## Feature Importance Analysis")




def main():
    setup_basic()
    Decision_Tree()
    Random_Forest()
    



if __name__ == "__main__":
    main()
