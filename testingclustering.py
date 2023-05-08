#!/usr/bin/env python
# coding: utf-8

# In[6]:


from sklearn.preprocessing import StandardScaler
from scapy.all import *
import numpy as np
import matplotlib.pyplot as plt
from sklearn.cluster import KMeans


# In[7]:


# Load pcap file
packets = rdpcap('captured_traffics.pcap')
print('Loaded {} packets.'.format(len(packets)))


# In[74]:


# Extract features
features = []
for packet in packets:
    feature = [packet.time, len(packet)]
    features.append(feature)


# In[75]:


# Normalize features
scaler = StandardScaler()
normalized_features = scaler.fit_transform(features)


# In[76]:


# Cluster the normalized features
n_clusters = 5
kmeans = KMeans(n_clusters=n_clusters)
kmeans.fit(normalized_features)


# In[77]:


# Assign a label to each packet
labels = []
for feature in normalized_features:
    label = kmeans.predict([feature])[0]
    labels.append(label)


# In[78]:


# Analyze anomalous behavior
anomalies = []
for i, packet in enumerate(packets):
    if len(packet) > 1500 or labels[i] == n_clusters-1:
        anomalies.append(i)


# In[55]:


print('Found {} anomalous packets.'.format(len(anomalies)))


# In[56]:


# Visualize the clusters
plt.figure(figsize=(8, 6))
plt.scatter(normalized_features[:, 0], normalized_features[:, 1], c=labels, alpha=0.7)
plt.title('Clustering results')
plt.xlabel('Time')
plt.ylabel('Packet length')
plt.show()


# In[62]:


# Visualize the anomalies
plt.figure(figsize=(8, 6))
plt.scatter(normalized_features[:, 0], normalized_features[:, 1], alpha=0.7)
plt.scatter(normalized_features[anomalies, 0], normalized_features[anomalies, 1], c='r')
plt.title('Anomalous packets')
plt.xlabel('Time')
plt.ylabel('Packet length')
plt.show()


# In[83]:


import pickle

# Save KMeans model
with open('kmeans_model.pkl', 'wb') as f:
    pickle.dump(kmeans, f)

# Save scaler object
with open('scaler.pkl', 'wb') as f:
    pickle.dump(scaler, f)


# In[80]:


# Cluster live traffic
live_packets = sniff(count=100)
live_features = []
for packet in live_packets:
    feature = [packet.time, len(packet)]
    live_features.append(feature)


# In[81]:


live_packets


# In[82]:


normalized_live_features = scaler.transform(live_features)
live_labels = kmeans.predict(normalized_live_features)


# In[67]:


# Visualize live traffic
plt.figure(figsize=(8, 6))
plt.scatter(normalized_features[:, 0], normalized_features[:, 1], c=labels, alpha=0.7)
plt.scatter(normalized_live_features[:, 0], normalized_live_features[:, 1], c=live_labels, alpha=0.7)
plt.title('Live traffic')
plt.xlabel('Time')
plt.ylabel('Packet length')
plt.show()


# In[68]:


# Analyze anomalous behavior in live traffic
live_anomalies = []
for i, packet in enumerate(live_packets):
    if len(packet) > 1500 or live_labels[i] == n_clusters-1:
        live_anomalies.append(i)

print('Found {} anomalous packets in live traffic.'.format(len(live_anomalies)))


# In[71]:


# Visualize the anomalies in live traffic
plt.figure(figsize=(8, 6))
plt.scatter(normalized_features[:, 0], normalized_features[:, 1], alpha=0.7)
plt.scatter(normalized_live_features[:, 0], normalized_live_features[:, 1], c='b', alpha=0.7)
plt.scatter(normalized_live_features[live_anomalies, 0], normalized_live_features[live_anomalies, 1], c='r')
plt.title('Anomalous packets in live traffic')
plt.xlabel('Time')
plt.ylabel('Packet length')
plt.show()

