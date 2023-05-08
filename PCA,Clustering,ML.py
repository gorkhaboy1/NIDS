#!/usr/bin/env python
# coding: utf-8

# In[1]:


import pandas as pd
from scapy.all import *
from sklearn.preprocessing import StandardScaler
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split


# In[3]:


# Read the pcap file
packets = rdpcap('captured_traffics.pcap')
packets


# In[4]:


# Create a list of dictionaries
packet_list = []
for packet in packets:
    if 'IP' in packet and 'TCP' in packet:
        packet_dict = {
            'src': packet['IP'].src,
            'dst': packet['IP'].dst,
            'sport': packet['TCP'].sport,
            'dport': packet['TCP'].dport,
            'seq': packet['TCP'].seq,
            'ack': packet['TCP'].ack,
            'flags': packet['TCP'].flags,
            'len': len(packet['TCP'].payload),
            'time': packet.time,
            'anomaly': 'non anomaly'  # add a default value for the 'anomaly' column
        }
              
        packet_list.append(packet_dict)


# In[5]:


# Create a DataFrame from the list of dictionaries
df = pd.DataFrame(packet_list)


# In[6]:


# Step 1: Feature engineering
features = df[['len', 'src', 'dst', 'sport', 'dport', 'flags', 'time']]


# In[7]:


# Encode categorical features
categorical_cols = ['src', 'dst', 'flags']
le = LabelEncoder()
for col in categorical_cols:
    df[col] = le.fit_transform(df[col])


# In[8]:


# Step 2: Scaling
# Select only numeric columns from the dataframe
numeric_cols = df.select_dtypes(include=['float64', 'int64'])


# In[9]:


# Scale the numeric columns
scaler = StandardScaler()
scaled_features = scaler.fit_transform(numeric_cols)


# In[10]:


# Step 3: Dimensionality reduction with PCA
from sklearn.decomposition import PCA
pca = PCA(n_components=2)
principal_components = pca.fit_transform(scaled_features)


# In[11]:


# Step 4: Clustering with KMeans
from sklearn.cluster import KMeans
kmeans = KMeans(n_clusters=3, random_state=42)
clusters = kmeans.fit_predict(principal_components)


# In[13]:


# Add cluster labels as a new column to the original dataset
df['cluster'] = clusters
df


# In[14]:


# create new column 'anomaly' based on 'cluster' column
df['anomaly'] = df['cluster'].apply(lambda x: 'anomaly' if x == 0 else 'not anomaly')
# drop 'cluster' column from DataFrame
df.drop('cluster', axis=1, inplace=True)
df


# In[16]:


df['anomaly'] = df['anomaly'].replace({'not anomaly': 0, 'anomaly': 1})
df


# In[18]:


# Select the feature columns and target column
X = df[['len', 'src', 'dst', 'sport', 'dport', 'flags', 'time']]
y = df['anomaly']


# In[19]:


# Split the data into training and test sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)


# In[20]:


# Train a random forest classifier
rfc = RandomForestClassifier(n_estimators=100, random_state=42)
rfc.fit(X_train, y_train)


# In[21]:


# Predict on the test set
y_pred = rfc.predict(X_test)


# In[22]:


# Evaluate the model
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
print('Accuracy score:', accuracy_score(y_test, y_pred))
print('Confusion matrix:\n', confusion_matrix(y_test, y_pred))
print('Classification report:\n', classification_report(y_test, y_pred))

