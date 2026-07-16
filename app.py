import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
from sklearn.ensemble import IsolationForest
import datetime
import os
import io
import time
import requests

# --- 1. SYSTEM & PAGE CONFIGURATION ---
st.set_page_config(
    page_title="AXPS Cyber & Financial Inspector",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- 2. EXTREME GLOW CSS ENGINE ---
st.markdown("""
    <style>
        /* Force Deep Space Master Background */
        body, .main, [data-testid="stAppViewContainer"], [data-testid="stHeader"] {
            background-color: #040612 !important;
            color: #f1f5f9 !important;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        }
        
        /* Eliminate default padding to maximize dashboard screen space */
        .block-container {
            padding-top: 1.5rem !important;
            padding-bottom: 1.5rem !important;
            padding-left: 2rem !important;
            padding-right: 2rem !important;
            max-width: 100% !important;
        }
        
        /* Premium Sidebar Customization */
        [data-testid="stSidebar"] {
            background-color: #070919 !important;
            border-right: 1px solid #1e293b !important;
        }
        
        /* Force solid, glowing backgrounds on all containers */
        div[data-testid="stVerticalBlockBorder"] {
            background-color: #080d24 !important;
            background: #080d24 !important;
            border: 1px solid #1e293b !important;
            border-radius: 12px !important;
            padding: 22px !important;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.5) !important;
        }
        
        /* Custom High-Velocity Gradient API Cards */
        .api-card-cyber {
            background: linear-gradient(135deg, #1b092b 0%, #0c051a 100%) !important;
            border: 1px solid #ff007f !important;
            border-left: 6px solid #ff007f !important;
            border-radius: 8px !important;
            padding: 12px 16px !important;
            margin-bottom: 12px !important;
            box-shadow: 0 0 10px rgba(255, 0, 127, 0.15) !important;
        }

        .api-card-financial {
            background: linear-gradient(135deg, #051a24 0%, #030a1c 100%) !important;
            border: 1px solid #00ffcc !important;
            border-left: 6px solid #00ffcc !important;
            border-radius: 8px !important;
            padding: 12px 16px !important;
            margin-bottom: 12px !important;
            box-shadow: 0 0 10px rgba(0, 255, 204, 0.15) !important;
        }
        
        /* Custom Button Overrides */
        div.stButton > button {
            background-color: #0d1536 !important;
            color: #38bdf8 !important;
            border: 1px solid #1e293b !important;
            border-radius: 6px !important;
            transition: all 0.2s ease;
            width: 100%;
            font-weight: 600;
        }
        div.stButton > button:hover {
            border-color: #00ffcc !important;
            color: #00ffcc !important;
            box-shadow: 0 0 10px rgba(0, 255, 204, 0.2) !important;
        }
    </style>
""", unsafe_allow_html=True)

# --- 3. PERSISTENT SYSTEM STATE ENGINE ---
if "axps_secured_registry" not in st.session_state:
    st.session_state["axps_secured_registry"] = {
        "8.8.8.8": {
            "Account": "ACC-99812",
            "Timestamp": datetime.datetime.now().strftime('%H:%M:%S'),
            "Reason": "ICCCL Art. 14: System Interference / High Capacity Overrun",
            "Action": "Isolate Source",
            "Section": "Art. 14: Computer Fraud",
            "Country": "United States",
            "ISP": "Google LLC",
            "Email": "security@google.com"
        },
        "1.1.1.1": {
            "Account": "ACC-77241",
            "Timestamp": datetime.datetime.now().strftime('%H:%M:%S'),
            "Reason": "ICCCL Art. 18: Forgery / Compromised Routing Signatures",
            "Action": "Block Access Completely",
            "Section": "Art. 18: Content Offenses",
            "Country": "Australia",
            "ISP": "Cloudflare Inc.",
            "Email": "abuse@cloudflare.com"
        }
    }

if "traffic_is_running" not in st.session_state:
    st.session_state["traffic_is_running"] = True

if "geo_cache" not in st.session_state:
    st.session_state["geo_cache"] = {}

# Dynamic IP Blacklist tracking
if "blocked_ips_set" not in st.session_state:
    st.session_state["blocked_ips_set"] = {"8.8.8.8", "1.1.1.1", "192.168.1.99", "103.255.4.12"}

# --- 4. REAL-TIME GEO & ISP LOOKUP ENGINES ---
def fetch_ip_meta(ip_address):
    if ip_address in st.session_state["geo_cache"]:
        return st.session_state["geo_cache"][ip_address]
        
    if ip_address.startswith("192.168.") or ip_address.startswith("10.") or ip_address.startswith("127."):
        meta = {
            "country": "Local Intranet Node",
            "org": "AXPS Virtual Private Lab",
            "email": f"network-admin@{ip_address.replace('.', '-')}.internal"
        }
        st.session_state["geo_cache"][ip_address] = meta
        return meta

    try:
        response = requests.get(f"http://ip-api.com/json/{ip_address}?fields=country,org,status", timeout=1.5)
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "success":
                org = data.get("org", "Unknown Network Operator")
                domain = org.lower().split(" ")[0].replace(",", "") + ".com"
                meta = {
                    "country": data.get("country", "Unknown Territory"),
                    "org": org,
                    "email": f"abuse@{domain}"
                }
                st.session_state["geo_cache"][ip_address] = meta
                return meta
    except Exception:
        pass

    fallback = {
        "country": "Unknown Region",
        "org": "Dynamic ISP Pipeline",
        "email": f"abuse-desk@ip-route.net"
    }
    st.session_state["geo_cache"][ip_address] = fallback
    return fallback

# --- 5. DATA SIMULATOR ENGINE ---
LIVE_FILE_PATH = "live_network_logs.csv"

def populate_default_live_csv(file_path):
    np.random.seed(int(time.time()) % 1000)
    timestamps = [(datetime.datetime.now() - datetime.timedelta(seconds=i*15)).strftime('%Y-%m-%d %H:%M:%S') for i in range(120)]
    timestamps.reverse()
    
    public_pool = ["8.8.8.8", "1.1.1.1", "104.244.42.1", "140.82.112.4", "192.168.1.99", "103.255.4.12"]
    ips = [np.random.choice(public_pool) if np.random.rand() > 0.6 else f"192.168.1.{np.random.randint(10, 254)}" for _ in range(120)]
    
    protocols = np.random.choice(['TCP', 'UDP', 'HTTP', 'HTTPS'], size=120)
    packet_sizes = np.random.uniform(100, 4500, size=120)
    requests_sec = np.random.uniform(10, 400, size=120)
    
    df_gen = pd.DataFrame({
        "Timestamp": timestamps,
        "IP Address": ips,
        "Protocol": protocols,
        "Packet Size (KB)": packet_sizes,
        "Requests/sec": requests_sec
    })
    df_gen.to_csv(file_path, index=False)

if not os.path.exists(LIVE_FILE_PATH):
    populate_default_live_csv(LIVE_FILE_PATH)

def parse_and_transform_ledger(file_path):
    try:
        if os.path.exists(file_path):
            raw_df = pd.read_csv(file_path)
            if not raw_df.empty:
                fin_df = pd.DataFrame()
                fin_df["Timestamp"] = pd.to_datetime(raw_df["Timestamp"])
                fin_df["Value ($)"] = (raw_df["Packet Size (KB)"] * 5.5).round(2)
                fin_df["Quantity (Tx/Min)"] = (raw_df["Requests/sec"] / 10).round(1)
                fin_df["IP Address"] = raw_df["IP Address"]
                
                unique_ips = raw_df["IP Address"].unique()
                ip_to_acc = {ip: f"ACC-{np.random.randint(10000, 99999)}" for ip in unique_ips}
                fin_df["Account"] = raw_df["IP Address"].map(ip_to_acc)
                
                action_map = {'TCP': 'WIRE TRANSFER', 'UDP': 'ATM WITHDRAWAL', 'HTTP': 'MERCHANT CHARGE', 'HTTPS': 'ONLINE TRANSFER'}
                fin_df["Quality Segment"] = raw_df["Protocol"].map(action_map).fillna("ONLINE TRANSFER")
                return fin_df
    except Exception:
        pass
    
    populate_default_live_csv(LIVE_FILE_PATH)
    return parse_and_transform_ledger(LIVE_FILE_PATH)

# --- 6. UNIFIED OPERATIONS CONTROL PANEL (SIDEBAR) ---
st.sidebar.markdown("<h2 style='color: #00ffcc; font-weight:800; margin-bottom: 0;'>AGENTIX POWER SPACE</h2>", unsafe_allow_html=True)
st.sidebar.markdown("<p style='color: #38bdf8; font-size:12px; margin-top:0;'>AXPS Cyber Inspector v3.0</p>", unsafe_allow_html=True)
st.sidebar.markdown("<hr style='margin: 10px 0 20px 0; border-color: #1e293b;'/>", unsafe_allow_html=True)

st.sidebar.markdown("### 🔄 Inspector Mode Select")
system_mode = st.sidebar.radio(
    label="Select Security Context",
    options=["🌐 Cyber Network Traffic Inspector", "🔒 Financial Data Security Ledger"],
    index=0
)

st.sidebar.markdown("---")
st.sidebar.markdown("### ⚙️ Operations Control")

# Live Traffic Controller Switch
traffic_status = st.sidebar.selectbox(
    "📡 Live Traffic Engine",
    options=["🟢 Traffic: ON (Running)", "🔴 Traffic: OFF (Paused)"],
    index=0 if st.session_state["traffic_is_running"] else 1
)
st.session_state["traffic_is_running"] = (traffic_status == "🟢 Traffic: ON (Running)")

# Operational Control Panel Actions
fetch_clicked = st.sidebar.button("⚡ Fetch Latest Cyber Logs", key="btn_fetch")
if fetch_clicked:
    if not st.session_state["traffic_is_running"]:
        populate_default_live_csv(LIVE_FILE_PATH)
        st.toast("Static logs fetched successfully!", icon="✅")
    else:
        st.sidebar.warning("Live Traffic is active! Set the status above to 'OFF' to trigger static data fetching.")

if st.sidebar.button("🔄 Reset System State", key="btn_reset"):
    st.session_state["axps_secured_registry"] = {}
    st.session_state["geo_cache"] = {}
    st.session_state["blocked_ips_set"] = {"8.8.8.8", "1.1.1.1", "192.168.1.99", "103.255.4.12"}
    populate_default_live_csv(LIVE_FILE_PATH)
    st.toast("System configuration hard-rebooted successfully.", icon="🔄")
    st.rerun()

st.sidebar.markdown("---")
st.sidebar.markdown("### 🚦 System Filter Thresholds")
max_tx_amount = st.sidebar.slider("Max Transaction Limit ($/Qty)", min_value=1000, max_value=25000, value=15000, step=1000)
max_velocity = st.sidebar.slider("Max Traffic Velocity (Req/Min)", min_value=5, max_value=50, value=20, step=5)

# SYNCED SUSPICIOUS / BLOCKED ACCOUNTS COMPONENT
joined_blocks = ", ".join(sorted(list(st.session_state["blocked_ips_set"])))
flagged_accounts_input = st.sidebar.text_area("Suspicious Accounts / IPs (Blocked IDS)", joined_blocks)
# Update live set with manual updates from textbox
if flagged_accounts_input:
    st.session_state["blocked_ips_set"] = {ip.strip() for ip in flagged_accounts_input.split(",") if ip.strip()}

# --- 7. STATIC PAGE ELEMENTS ---
st.markdown("<h1 style='margin:0; color: #00ffcc; letter-spacing: -1.0px; font-weight:800; font-size:38px;'>AGENTIX POWER SPACE</h1>", unsafe_allow_html=True)
st.markdown(f"<p style='color: #94a3b8; margin:0 0 25px 0; font-size: 13px; font-weight:600; letter-spacing:1px;'>AXPS CYBER INSPECTOR • ACTIVE MODE: <span style='color:#38bdf8;'>{system_mode.upper()}</span></p>", unsafe_allow_html=True)

# --- 8. ASYNC STREAM ENGINE (@st.fragment) ---
@st.fragment(run_every=2 if st.session_state["traffic_is_running"] else None)
def live_stream_fragment():
    if st.session_state["traffic_is_running"]:
        populate_default_live_csv(LIVE_FILE_PATH)
        
    df = parse_and_transform_ledger(LIVE_FILE_PATH)
    
    if not df.empty and len(df) >= 2:
        df = df.sort_values("Timestamp").reset_index(drop=True)
        X = df[["Value ($)", "Quantity (Tx/Min)"]]
        clf = IsolationForest(contamination=0.05, random_state=42)
        df["Anomaly_Score"] = clf.fit_predict(X)

        security_status = []
        for idx, row in df.iterrows():
            ip = row["IP Address"]
            acc = row["Account"]
            
            # BLOCK IP ROUTE DIRECTLY IF MATCHED
            if ip in st.session_state["blocked_ips_set"]:
                security_status.append("UNSECURED: Blocked IP Source")
            else:
                is_overbudget = row["Value ($)"] > max_tx_amount
                is_high_velocity = row["Quantity (Tx/Min)"] > max_velocity
                
                if is_overbudget or is_high_velocity:
                    security_status.append("ATTENTION: Limit Exceeded")
                    reasons = []
                    if is_overbudget: reasons.append(f"Value of ${row['Value ($)']:,}")
                    if is_high_velocity: reasons.append(f"High-Volume rate ({row['Quantity (Tx/Min)']} tx/min)")
                    violation_reason = " & ".join(reasons)
                    
                    sec = "Art. 14: Computer-related Fraud" if is_overbudget else "Art. 18: Traffic Signal Tampering"
                    
                    # Core integration of Geolocation Lookup API details into newly isolated threat entries
                    geo_meta = fetch_ip_meta(ip)
                    st.session_state["axps_secured_registry"][ip] = {
                        "Account": acc,
                        "Timestamp": row["Timestamp"].strftime('%H:%M:%S'),
                        "Reason": f"Cyber Trespass & Overrun: {violation_reason}",
                        "Action": "Isolate Source",
                        "Section": sec,
                        "Country": geo_meta["country"],
                        "ISP": geo_meta["org"],
                        "Email": geo_meta["email"]
                    }
                    # AUTO APPEND VIOLATING IPS DIRECTLY INTO SYSTEM FIREWALL BLOCKPOOL
                    st.session_state["blocked_ips_set"].add(ip)
                    
                elif "Anomaly_Score" in row and row["Anomaly_Score"] == -1:
                    security_status.append("ALERT: High Risk Data Pattern")
                else:
                    security_status.append("Secured")
                    
        df["Security State"] = security_status
        anomalies_df = df[df["Security State"] != "Secured"]
    else:
        df["Security State"] = "Secured"
        anomalies_df = pd.DataFrame()

    # --- GLOWING METRIC CARDS ---
    total_scanned = len(df)
    total_anomalies = len(anomalies_df)
    total_blocked = len(st.session_state["blocked_ips_set"])
    total_directives = len(st.session_state["blocked_ips_set"]) + len(st.session_state["axps_secured_registry"])

    st.markdown(f"""
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 20px; margin-bottom: 25px;">
            <div style="background: linear-gradient(135deg, #091a24 0%, #030a13 100%); border: 1.5px solid #00f2fe; border-top: 5px solid #00f2fe; border-radius: 10px; padding: 18px; box-shadow: 0 4px 15px rgba(0,242,254,0.15);">
                <div style="color: #94a3b8; font-size: 11px; text-transform: uppercase; font-weight: 700; letter-spacing: 1.5px;">📊 Scanned Log Entities</div>
                <div style="color: #00f2fe; font-size: 34px; font-weight: 800; margin-top: 8px;">{total_scanned}</div>
            </div>
            <div style="background: linear-gradient(135deg, #240a1b 0%, #0c030d 100%); border: 1.5px solid #ff007f; border-top: 5px solid #ff007f; border-radius: 10px; padding: 18px; box-shadow: 0 4px 15px rgba(255,0,127,0.15);">
                <div style="color: #94a3b8; font-size: 11px; text-transform: uppercase; font-weight: 700; letter-spacing: 1.5px;">⚠️ Anomalies Isolated</div>
                <div style="color: #ff007f; font-size: 34px; font-weight: 800; margin-top: 8px;">{total_anomalies}</div>
            </div>
            <div style="background: linear-gradient(135deg, #241a09 0%, #0e0a03 100%); border: 1.5px solid #f59e0b; border-top: 5px solid #f59e0b; border-radius: 10px; padding: 18px; box-shadow: 0 4px 15px rgba(245,158,11,0.15);">
                <div style="color: #94a3b8; font-size: 11px; text-transform: uppercase; font-weight: 700; letter-spacing: 1.5px;">🛑 Blocked IP Sources</div>
                <div style="color: #f59e0b; font-size: 34px; font-weight: 800; margin-top: 8px;">{total_blocked}</div>
            </div>
            <div style="background: linear-gradient(135deg, #1b092e 0%, #0a0314 100%); border: 1.5px solid #a855f7; border-top: 5px solid #a855f7; border-radius: 10px; padding: 18px; box-shadow: 0 4px 15px rgba(168,85,247,0.15);">
                <div style="color: #94a3b8; font-size: 11px; text-transform: uppercase; font-weight: 700; letter-spacing: 1.5px;">⚖️ Treaty Directives (ICCCL)</div>
                <div style="color: #a855f7; font-size: 34px; font-weight: 800; margin-top: 8px;">{total_directives}</div>
            </div>
        </div>
    """, unsafe_allow_html=True)

    # --- 9. TWO-COLUMN DYNAMIC INTERACTION SECTION ---
    col_left_chart, col_right_log = st.columns([12, 8])

    with col_left_chart:
        with st.container(border=True):
            if system_mode == "🌐 Cyber Network Traffic Inspector":
                st.markdown("<h3 style='margin-top:0; color:#38bdf8;'>📈 System Network Anomaly Mapping</h3>", unsafe_allow_html=True)
                title_label = "📈 Click to Expand System Network Anomaly Mapping"
                fig = px.scatter(
                    df, 
                    x="Timestamp", 
                    y="Quantity (Tx/Min)", 
                    color="Security State",
                    size="Value ($)",
                    color_discrete_map={
                        "Secured": "#10b981", 
                        "ALERT: High Risk Data Pattern": "#f59e0b",
                        "ATTENTION: Limit Exceeded": "#ef4444",
                        "UNSECURED: Blocked IP Source": "#a855f7"
                    },
                    hover_data=["IP Address", "Quantity (Tx/Min)"]
                )
            else:
                st.markdown("<h3 style='margin-top:0; color:#00ffcc;'>💰 Financial Transaction Risk Analysis</h3>", unsafe_allow_html=True)
                title_label = "💰 Click to Expand Financial Transaction Risk Analysis"
                fig = px.scatter(
                    df, 
                    x="Timestamp", 
                    y="Value ($)", 
                    color="Security State",
                    size="Quantity (Tx/Min)",
                    color_discrete_map={
                        "Secured": "#10b981", 
                        "ALERT: High Risk Data Pattern": "#f59e0b",
                        "ATTENTION: Limit Exceeded": "#ef4444",
                        "UNSECURED: Blocked IP Source": "#a855f7"
                    },
                    hover_data=["Account", "Value ($)", "Quality Segment"]
                )
                
            fig.update_layout(
                plot_bgcolor='rgba(0,0,0,0)',
                paper_bgcolor='rgba(0,0,0,0)',
                font_color='#f0f6fc',
                margin=dict(l=5, r=5, t=5, b=5),
                height=320,
                xaxis=dict(showgrid=False, linecolor="#1e293b"),
                yaxis=dict(gridcolor='#1e293b', linecolor="#1e293b")
            )
            
            # Collapse System Network Anomaly Mapping by default
            with st.expander(title_label, expanded=False):
                st.plotly_chart(fig, use_container_width=True)

    with col_right_log:
        with st.container(border=True):
            st.markdown("<h3 style='margin-top:0; color:#ef4444;'>📡 Live Threat Log Pipeline</h3>", unsafe_allow_html=True)
            
            with st.expander("📁 Click to Expand/Collapse Live Pipeline", expanded=True):
                with st.container(height=320):
                    if not df.empty:
                        sorted_logs = df.iloc[::-1]
                        for _, row in sorted_logs.head(15).iterrows():
                            badge_color = "#10b981" if row["Security State"] == "Secured" else "#ef4444"
                            card_class = "api-card-cyber" if system_mode == "🌐 Cyber Network Traffic Inspector" else "api-card-financial"
                            val_label = f"Weight: <strong>{row['Value ($)']:,} KB</strong>" if system_mode == "🌐 Cyber Network Traffic Inspector" else f"Amt: <strong>${row['Value ($)']:,}</strong>"
                            
                            st.markdown(f"""
                                <div class="{card_class}">
                                    <div style="display: flex; justify-content: space-between; font-size:11px;">
                                        <span style="color: #94a3b8; font-weight:600;">{row['Timestamp'].strftime('%H:%M:%S')}</span>
                                        <span style="color: {badge_color}; font-weight: bold;">{row['Security State']}</span>
                                    </div>
                                    <div style="font-size:14px; margin-top:5px; font-weight:700; color:#f1f5f9;">
                                        Src IP: <code style="color: #38bdf8;">{row['IP Address']}</code> ➔ {row['Quality Segment']}
                                    </div>
                                    <div style="font-size:11px; color:#e2e8f0; margin-top:4px; letter-spacing:0.5px;">
                                        {val_label} | Rate: <strong>{row['Quantity (Tx/Min)']} Req/m</strong>
                                    </div>
                                </div>
                            """, unsafe_allow_html=True)
                    else:
                        st.info("No active pipeline data discovered.")

    # --- 10. LEGAL ACTION & THREAT ENFORCEMENT CONSOLE (INTERNATIONALIZED + AUTO-BLOCKS) ---
    with st.container(border=True):
        st.markdown("<h3 style='color: #00ffcc; margin-top:0; margin-bottom: 2px;'>🛡️ Legal Action & Threat Enforcement Console</h3>", unsafe_allow_html=True)
        st.markdown("<p style='color: #94a3b8; font-size:12px; margin-bottom:15px;'>Database registry administered directly in accordance with the International Cyber Crime Laws (ICCCL) & Budapest Convention.</p>", unsafe_allow_html=True)

        with st.expander("📁 Click to Expand/Collapse Threat Registry Table", expanded=False):
            if st.session_state["axps_secured_registry"]:
                reg_table_data = []
                for ip, info in st.session_state["axps_secured_registry"].items():
                    reg_table_data.append({
                        "Threat IP Source": ip,
                        "Linked Account": info.get("Account", "N/A"),
                        "Timestamp": info.get("Timestamp", "N/A"),
                        "ICCCL Regulatory Clause": info.get("Section", "N/A"),
                        "Identified Violation Reason": info.get("Reason", "N/A"),
                        "Mitigation Action Plan": info.get("Action", "N/A"),
                        "Geographic Location": info.get("Country", "Local Node"),
                        "Operator ISP Org": info.get("ISP", "N/A"),
                        "Primary Compliance Email": info.get("Email", "N/A")
                    })
                
                registry_df = pd.DataFrame(reg_table_data)
                st.dataframe(registry_df, use_container_width=True, hide_index=True)
            else:
                empty_df = pd.DataFrame([{
                    "Threat IP Source": "🟢 NO DISCOVERED THREATS",
                    "Linked Account": "SECURED",
                    "Timestamp": "N/A",
                    "ICCCL Regulatory Clause": "COMPLIANT",
                    "Identified Violation Reason": "No limit overrun or unauthorized routing trends.",
                    "Mitigation Action Plan": "CONTINUOUS SCANNING",
                    "Geographic Location": "Global Intranets Active",
                    "Operator ISP Org": "AXPS Lab",
                    "Primary Compliance Email": "N/A"
                }])
                st.dataframe(empty_df, use_container_width=True, hide_index=True)

        # Row removal clearing logic
        if st.session_state["axps_secured_registry"]:
            st.write("")
            col_clear_sel, col_clear_btn = st.columns([8, 2])
            with col_clear_sel:
                clear_target = st.selectbox("Select Flagged IP Address to Clear Security Countermeasures", list(st.session_state["axps_secured_registry"].keys()))
            with col_clear_btn:
                st.markdown("<div style='height: 28px;'></div>", unsafe_allow_html=True)
                if st.button("🔓 Clear Selected Threat Record"):
                    if clear_target in st.session_state["axps_secured_registry"]:
                        del st.session_state["axps_secured_registry"][clear_target]
                        if clear_target in st.session_state["blocked_ips_set"]:
                            st.session_state["blocked_ips_set"].remove(clear_target)
                        st.toast(f"Threat clearance & unblocking executed for source: {clear_target}", icon="🔓")
                        st.rerun()

    # --- 11. AUDITS & RAW BACKLOG TABLES ---
    with st.container(border=True):
        st.markdown("<h3 style='color: #38bdf8; margin-top:0;'>📋 System Logs Auditing & Raw Backlogs</h3>", unsafe_allow_html=True)

        with st.expander("📁 Click to Expand/Collapse Complete Raw Log Database Table", expanded=False):
            st.dataframe(df, use_container_width=True, hide_index=True)

        col_text_report, col_excel_report = st.columns(2)

        with col_text_report:
            st.markdown("#### 📄 Export Security Compliance log (.txt)")
            report_text = f"""========================================================================
             AXPS CYBER INSPECTOR LEGAL SECURITY COMPLIANCE REPORT
========================================================================
Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Threat Level Status: {'CRITICAL' if len(st.session_state['axps_secured_registry']) > 0 else 'COMPLIANT'}

- Total Scanned Targets: {len(df)}
- Active isolated cases: {len(st.session_state['axps_secured_registry'])}
"""
            st.download_button(
                label="Download Compliance Log (.txt)",
                data=report_text,
                file_name=f"AXPS_Compliance_Log_{datetime.date.today()}.txt"
            )

        with col_excel_report:
            st.markdown("#### 🟢 Secure Financial & Network Ledger (.xlsx)")
            
            excel_buffer = io.BytesIO()
            with pd.ExcelWriter(excel_buffer, engine='xlsxwriter') as writer:
                df.to_excel(writer, sheet_name="Network Data Logs", index=False)
                if st.session_state["axps_secured_registry"]:
                    v_df = pd.DataFrame.from_dict(st.session_state["axps_secured_registry"], orient='index')
                    v_df.to_excel(writer, sheet_name="Active Legal Violations")
                    
            excel_data = excel_buffer.getvalue()
            st.download_button(
                label="Generate Security Ledger (.xlsx)",
                data=excel_data,
                file_name=f"AXPS_Compliance_Ledger_{datetime.date.today()}.xlsx"
            )

# Run Live stream fragment engine
live_stream_fragment()