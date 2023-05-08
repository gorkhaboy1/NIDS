#!/usr/bin/env python
# coding: utf-8

# In[1]:


import datetime
import threading
from scapy.all import *
from sklearn.cluster import KMeans
from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import DBSCAN
import numpy as np
import pandas as pd
import plotly.graph_objs as go
from flask import Flask, render_template
import datetime


# In[2]:


app = Flask(__name__)

PACKETS = []
X = []


# In[3]:


# Number of clusters to form
K = 3


# In[5]:


# Load and fit PCA model
pca = PCA(n_components=5)


# In[6]:


# Load and fit KMeans model
kmeans = KMeans(n_clusters=K, random_state=0)

# Load and fit DBSCAN model
dbscan = DBSCAN(eps=0.5, min_samples=5)


# In[7]:


@app.route('/')
def index():
    packet_count = 0 # replace this with a variable that holds the count of received packets
    current_time = datetime.now().strftime("%m/%d/%Y %H:%M:%S") # replace this with a variable that holds the current time
    return render_template('index.html', packet_size=packet_count, timestamp=current_time)


# In[8]:


@app.route('/graph')
def graph():
    return render_template('index.html')


# In[16]:


def sniff_packets():
    global PACKETS, X

    # Sniff network traffic
    sniffed_packets = sniff(count=100, iface="en0")


# In[21]:


for packet in PACKETS:
    try:
        # Extract features
        size = len(packet)
        protocol = packet.getlayer(1).name
        src_ip = packet.getlayer(1).src
        dst_ip = packet.getlayer(1).dst
        src_port = packet.getlayer(2).sport
        dst_port = packet.getlayer(2).dport

        # Add to dataset
        X.append([size, src_port, dst_port])

        # Convert to numpy array
        X_arr = np.array(X)

        # Scale the data
        scaler = StandardScaler()
        X_arr = scaler.fit_transform(X_arr)

        # Apply PCA
        pca_X = pca.fit_transform(X_arr)

        # Cluster using KMeans
        kmeans_labels = kmeans.fit_predict(pca_X)

        # Cluster using DBSCAN
        dbscan_labels = dbscan.fit_predict(pca_X)

        # Find which cluster DBSCAN identified as outliers (-1)
        dbscan_outliers = np.where(dbscan_labels == -1)[0]

        # Get the data points in the outlier cluster for KMeans
        kmeans_outliers = pca_X[np.where(kmeans_labels == np.bincount(kmeans_labels).argmax())[0]]

        # Add color codes to data points
        colors = ['blue'] * len(pca_X)
        for i in dbscan_outliers:
            colors[i] = 'red'
        for i in kmeans_outliers:
            colors[np.where(pca_X == i)[0][0]] = 'green'

        # Create plotly figure
        fig = go.Figure(data=go.Scatter(x=pca_X[:, 0], y=pca_X[:, 1], mode='markers', marker=dict(color=colors)))

        # Save plotly figure
        fig.write_html("index.html")

    except Exception as e:
        print(e)


# In[ ]:


def start_sniffing():
    t = threading.Thread(target=sniff_packets)
    t.start()

if __name__ == '__main__':
    start_sniffing()
    app.run()
    

