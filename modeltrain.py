#!/usr/bin/env python
# coding: utf-8

# In[1]:


import pandas as pd
from scapy.all import *
from sklearn.preprocessing import StandardScaler
from sklearn.preprocessing import LabelEncoder, OneHotEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split


# In[2]:


# Read the pcap file
packets = rdpcap('captured_traffics.pcap')


# In[3]:


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
            'time': packet.time
        }
              
        packet_list.append(packet_dict)


# In[4]:


# Create a DataFrame from the list of dictionaries
df = pd.DataFrame(packet_list)


# In[5]:


# Step 1: Feature engineering
features = df[['len', 'src', 'dst', 'sport', 'dport', 'flags', 'time']]


# In[6]:


# Select only numeric columns from the dataframe
numeric_cols = df.select_dtypes(include=['float64', 'int64'])


# In[7]:


# Scale the numeric columns
scaler = StandardScaler()
scaled_features = scaler.fit_transform(numeric_cols)


# In[8]:


# Step 4: PCA
from sklearn.decomposition import PCA
pca = PCA(n_components=2)
principal_components = pca.fit_transform(scaled_features)


# In[9]:


# Step 5: Clustering
from sklearn.cluster import KMeans
kmeans = KMeans(n_clusters=3, random_state=42)
clusters = kmeans.fit_predict(principal_components)


# In[10]:


# Add cluster labels as a new column to the original dataset
df['cluster'] = clusters


# In[11]:


df


# In[13]:


# Encode categorical features
categorical_cols = ['src', 'dst', 'flags']
le = LabelEncoder()
for col in categorical_cols:
    df[col] = le.fit_transform(df[col])
df


# In[17]:


# One-hot encode categorical features
categorical_cols = features.select_dtypes(include=['int64'])
ohe = OneHotEncoder()
categorical_cols_idx = [features.columns.get_loc(col) for col in categorical_cols.columns]
ohe_df = ohe.fit_transform(df.iloc[:, categorical_cols_idx]).toarray()

if hasattr(ohe, 'get_feature_names'):
    ohe_df = pd.DataFrame(ohe_df, columns=ohe.get_feature_names(categorical_cols.columns))
else:
    ohe_df = pd.DataFrame(ohe_df)
df = pd.concat([df, ohe_df], axis=1)


# In[18]:


# Combine one-hot encoded features with numeric features
final_features = pd.concat([df[['len', 'seq', 'ack', 'sport', 'dport', 'time']], ohe_df], axis=1)


# In[19]:


# Create target variable
target = df['cluster']


# In[28]:


# Split data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(final_features, target, test_size=0.2, random_state=42)

# Convert all feature names to strings
X_train.columns = X_train.columns.astype(str)
X_test.columns = X_test.columns.astype(str)

# Train a Random Forest classifier
rf = RandomForestClassifier(n_estimators=100, random_state=42)
X_train.columns = X_train.columns.astype(str)
rf.fit(X_train, y_train)


# In[ ]:





# In[29]:


# Evaluate the model on the test set
accuracy = rf.score(X_test, y_test)
print('Accuracy:', accuracy)

