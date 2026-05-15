import streamlit as st
import pandas as pd
import sqlite3
import time
import tempfile
import os
import netifaces
import json
import config
import anomaly_detector
import networkx as nx
from pyvis.network import Network

st.set_page_config(page_title="Internal Threat Detection", page_icon="🛡️", layout="wide")

st.markdown("""
<style>
    .stApp {background-color: #0e1117;}
    div[data-testid="stMetricValue"] {font-family: monospace; color: #00ff41;}
</style>
""", unsafe_allow_html=True)

if 'detector' not in st.session_state:
    st.session_state.detector = anomaly_detector.AnomalyDetector()
    
if 'graph_html' not in st.session_state:
    st.session_state.graph_html = ""
    
if 'last_graph_update_id' not in st.session_state:
    st.session_state.last_graph_update_id = 0

detector = st.session_state.detector

def get_local_ips():
    ips = set()
    try:
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface).get(netifaces.AF_INET, [])
            for addr in addrs:
                ips.add(addr['addr'])
    except ValueError:
        pass
    return ips

local_ips = get_local_ips()

def get_db_connection():
    try:
        conn = sqlite3.connect(config.DB_PATH, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn
    except sqlite3.Error:
        return None

def load_packets(limit=None, since_id=None):
    if not os.path.exists(config.DB_PATH):
        return pd.DataFrame()
        
    conn = get_db_connection()
    if not conn:
        return pd.DataFrame()
        
    query = "SELECT * FROM packets"
    if since_id:
        query += f" WHERE id > {since_id}"
    query += " ORDER BY id DESC"
    if limit:
        query += f" LIMIT {limit}"
        
    try:
        df = pd.read_sql_query(query, conn)
    except Exception:
        df = pd.DataFrame()
    finally:
        conn.close()
    return df

def sniffer_running():
    if not os.path.exists(config.DB_PATH):
        return False
    try:
        mtime = os.path.getmtime(config.DB_PATH)
        return (time.time() - mtime) < 10
    except OSError:
        return False

def build_graph(packets):
    G = nx.Graph()
    for _, row in packets.iterrows():
        src = row['src']
        dst = row['dst']
        src_color = "#00b4d8"
        dst_color = "#00b4d8"
        if str(src).startswith(config.INTERNAL_PREFIXES):
            src_color = "#00ff41"
        if str(dst).startswith(config.INTERNAL_PREFIXES):
            dst_color = "#00ff41"
        G.add_node(src, label=src, color=src_color, title=src)
        G.add_node(dst, label=dst, color=dst_color, title=dst)
        G.add_edge(src, dst, color="#444444")

    pos = nx.spring_layout(G, seed=42, k=1.5, iterations=100)
    net = Network(height="550px", width="100%", bgcolor="#0e1117", font_color="white")
    net.from_nx(G)
    
    for node in G.nodes():
        net_node = net.get_node(node)
        if net_node:
            net_node['x'] = pos[node][0] * 800
            net_node['y'] = pos[node][1] * 800
            
    options = {
        "physics": {"enabled": False},
        "layout": {"improvedLayout": False},
        "interaction": {"navigationButtons": True}
    }
    net.set_options(json.dumps(options))
    return net

def simulate_attack():
    import attack_sim
    attack_sim.inject_attack_packets()

st.title("🛡️ Internal Network Threat Detection")
st.caption("Entropy-Based Anomaly Detection")

with st.sidebar:
    st.header("Controls")
    if st.button("Simulate Attack"):
        simulate_attack()
        st.success("Attack packets injected!")
    st.markdown("---")
    st.subheader("Sniffer Status")
    if sniffer_running():
        st.success("✅ Sniffer is active")
    else:
        st.error("❌ Sniffer not running")
    if st.button("Refresh Now"):
        st.rerun()

new_packets = load_packets(since_id=detector.last_id)
if not new_packets.empty:
    detector.update_entropy_window(new_packets.to_dict('records'))

packets_df = load_packets(limit=config.GRAPH_LIMIT)
all_packets = load_packets() if not packets_df.empty else pd.DataFrame()

entropy = detector.calculate_entropy()

col1, col2 = st.columns([3, 1])

with col1:
    st.subheader("Real-Time Network Topology")
    
    current_max_id = packets_df['id'].max() if not packets_df.empty else 0
    
    if current_max_id != st.session_state.last_graph_update_id and not packets_df.empty:
        net = build_graph(packets_df)
        with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as f:
            net.save_graph(f.name)
            f.flush()
            with open(f.name, 'r', encoding='utf-8') as html_f:
                st.session_state.graph_html = html_f.read()
        try:
            os.unlink(f.name)
        except OSError:
            pass
        st.session_state.last_graph_update_id = current_max_id
    
    if st.session_state.graph_html:
        st.components.v1.html(st.session_state.graph_html, height=570, scrolling=False)
    else:
        st.info("Waiting for network traffic...")

with col2:
    st.subheader("Security Metrics")
    m1, m2 = st.columns(2)
    total_packets = len(all_packets)
    nodes = set()
    if not all_packets.empty:
        nodes.update(all_packets['src'].tolist() + all_packets['dst'].tolist())
    
    m1.metric("Total Packets", total_packets)
    m2.metric("Active Nodes", len(nodes))
    st.markdown("---")
    
    st.metric("Shannon Entropy", f"{entropy:.4f}")
    if entropy > config.ENTROPY_THRESHOLD:
        st.error("🚨 HIGH RANDOMNESS DETECTED")
    else:
        st.success("✅ TRAFFIC STABLE")
        
    st.markdown("---")
    st.write("Recent Logs:")
    if not packets_df.empty:
        st.dataframe(packets_df[['time','src','dst','port']].head(5), hide_index=True)

time.sleep(2)
st.rerun()