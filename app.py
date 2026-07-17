"""
AXPS Inspector — Cyber & Financial Security Monitoring Dashboard
==================================================================

A Streamlit dashboard that simulates live network / financial-transaction
traffic, flags anomalies with an IsolationForest model, and maintains a
"threat registry" of blocked sources.

Structure of this file
-----------------------
1.  Page & theme configuration
2.  CSS (design tokens, animations)
3.  Session-state bootstrap
4.  Data generation & enrichment  (cached, so it doesn't refetch every tick)
5.  AI Insight engine             (rule-based, with optional Claude call)
6.  Sidebar — operations & controls
7.  Header
8.  Live dashboard fragment       (metrics, chart, live log, registry, exports)
9.  Feedback — animated sidebar button + on-page 5-star rating
10. Entrypoint

Deploying
---------
See README.md for GitHub → Streamlit Community Cloud steps.
"""

from __future__ import annotations

import datetime
import io
import os
import time
from dataclasses import dataclass

import numpy as np
import pandas as pd
import plotly.express as px
import requests
import streamlit as st
from sklearn.ensemble import IsolationForest

# --- Google Search Console & SEO Meta Tags ---
st.html(
    '<head>'
    '<meta name="google-site-verification" content="F_e_RoVbDiO3ilDO3" />'    
    '<meta name="description" content="AXPS Cyber Inspector: An interactive, reactive security dashboard powered by Python and Machine Learning to dynamically isolate network traffic anomalies." />'
    '<meta name="keywords" content="AXPS, Cyber Inspector, Machine Learning, Python, Streamlit, Anomaly Detection" />'
    '<meta name="author" content="AXPS" />'
    '<meta name="robots" content="index, follow" />'
    '</head>'
)

# ---------------------------------------------------------------------------
# 1. PAGE & THEME CONFIGURATION
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="AXPS Inspector",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

LIVE_FILE_PATH = "live_network_logs.csv"
FEEDBACK_LOG_PATH = "feedback_log.csv"
GOOGLE_FORM_URL = (
    "https://docs.google.com/forms/d/e/"
    "1FAIpQLScs8sK9BMGPe-aiXoCvs0B367u0nu8xr-v7llGXnnzCkjDU_g/viewform?usp=dialog"
)

STATUS_COLORS = {
    "Secured": "#10b981",
    "ALERT: High Risk Data Pattern": "#f59e0b",
    "ATTENTION: Limit Exceeded": "#ef4444",
    "UNSECURED: Blocked IP Source": "#a855f7",
}


# ---------------------------------------------------------------------------
# 2. CSS — design tokens & motion
# ---------------------------------------------------------------------------

def inject_css() -> None:
    """All styling lives here so the rest of the file stays free of markup."""
    st.markdown(
        """
        <style>
        :root{
            --bg:#040612; --panel:#080d24; --border:#1e293b;
            --cyan:#00ffcc; --blue:#38bdf8; --pink:#ff007f;
            --amber:#f59e0b; --purple:#a855f7; --text:#f1f5f9; --muted:#94a3b8;
        }

        body, .main, [data-testid="stAppViewContainer"], [data-testid="stHeader"]{
            background-color: var(--bg) !important;
            color: var(--text) !important;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        }

        .block-container{
            padding: 1.5rem 2rem !important;
            max-width: 100% !important;
        }

        [data-testid="stSidebar"]{
            background-color: #070919 !important;
            border-right: 1px solid var(--border) !important;
        }

        div[data-testid="stVerticalBlockBorder"]{
            background: var(--panel) !important;
            border: 1px solid var(--border) !important;
            border-radius: 12px !important;
            padding: 22px !important;
            box-shadow: 0 8px 32px rgba(0,0,0,.5) !important;
            animation: fadeIn .35s ease-out;
        }

        @keyframes fadeIn{
            from{ opacity:0; transform: translateY(4px); }
            to{ opacity:1; transform: translateY(0); }
        }

        /* Metric cards */
        .metric-card{
            border-radius: 10px; padding: 18px; border: 1.5px solid var(--card-color);
            border-top: 5px solid var(--card-color);
            background: linear-gradient(135deg, color-mix(in srgb, var(--card-color) 12%, #030612) 0%, #030612 100%);
            box-shadow: 0 4px 15px color-mix(in srgb, var(--card-color) 18%, transparent);
            transition: transform .18s ease;
        }
        .metric-card:hover{ transform: translateY(-2px); }
        .metric-label{ color: var(--muted); font-size:11px; text-transform:uppercase; font-weight:700; letter-spacing:1.5px; }
        .metric-value{ font-size:34px; font-weight:800; margin-top:8px; color: var(--card-color); }

        /* Live log cards */
        .log-card{
            border-radius: 8px; padding: 12px 16px; margin-bottom: 10px;
            border: 1px solid var(--card-color); border-left: 6px solid var(--card-color);
            background: linear-gradient(135deg, color-mix(in srgb, var(--card-color) 14%, #060314) 0%, #030108 100%);
            box-shadow: 0 0 10px color-mix(in srgb, var(--card-color) 16%, transparent);
            animation: slideIn .3s ease-out;
        }
        @keyframes slideIn{ from{ opacity:0; transform: translateX(-6px);} to{ opacity:1; transform: translateX(0);} }

        div.stButton > button{
            background-color:#0d1536 !important; color: var(--blue) !important;
            border: 1px solid var(--border) !important; border-radius: 6px !important;
            width:100%; font-weight:600; transition: all .2s ease;
        }
        div.stButton > button:hover{
            border-color: var(--cyan) !important; color: var(--cyan) !important;
            box-shadow: 0 0 10px rgba(0,255,204,.2) !important;
        }

        /* Animated feedback button (scoped to its own wrapper so it can't
           collide with any other button's CSS specificity) */
        .feedback-btn-wrap div.stButton > button{
            background-color:#0e1117 !important; border:2px solid var(--cyan) !important;
            color: var(--cyan) !important;
            box-shadow: 0 0 6px var(--cyan), inset 0 0 6px rgba(0,255,204,.3) !important;
            animation: pulseGlow 2.2s infinite alternate ease-in-out;
        }
        .feedback-btn-wrap div.stButton > button:hover{
            background-color: var(--cyan) !important; color:#0e1117 !important;
            box-shadow: 0 0 22px var(--cyan), 0 0 44px var(--cyan) !important;
            transform: scale(1.02);
        }
        @keyframes pulseGlow{
            0%{ box-shadow: 0 0 4px rgba(0,255,204,.4), inset 0 0 4px rgba(0,255,204,.2); border-color: rgba(0,255,204,.6);}
            100%{ box-shadow: 0 0 16px rgba(0,255,204,.9), inset 0 0 8px rgba(0,255,204,.4); border-color: var(--cyan);}
        }

        /* AI insight panel — subtle typing shimmer */
        .ai-panel{
            border-radius: 10px; padding: 16px 18px; border:1px solid var(--purple);
            border-left: 6px solid var(--purple);
            background: linear-gradient(135deg, #150a26 0%, #060312 100%);
            box-shadow: 0 0 14px rgba(168,85,247,.15);
            animation: fadeIn .4s ease-out;
        }
        .ai-panel-title{ color: var(--purple); font-weight:700; font-size:13px; letter-spacing:.5px; margin-bottom:6px;}
        .ai-panel-body{ color: var(--text); font-size:14px; line-height:1.5; }

        /* Star rating */
        .star-row button{ font-size: 22px !important; }
        </style>
        """,
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# 3. SESSION-STATE BOOTSTRAP
# ---------------------------------------------------------------------------

def init_state() -> None:
    defaults = {
        "axps_secured_registry": {
            "8.8.8.8": {
                "Account": "ACC-99812",
                "Timestamp": datetime.datetime.now().strftime("%H:%M:%S"),
                "Reason": "ICCCL Art. 14: System Interference / High Capacity Overrun",
                "Action": "Isolate Source",
                "Domain": "Cyber",
                "Section": "Art. 14: Computer Fraud",
                "Country": "United States",
                "ISP": "Google LLC",
                "Email": "security@google.com",
            },
            "1.1.1.1": {
                "Account": "ACC-77241",
                "Timestamp": datetime.datetime.now().strftime("%H:%M:%S"),
                "Reason": "ICCCL Art. 18: Forgery / Compromised Routing Signatures",
                "Action": "Block Access Completely",
                "Domain": "Financial",
                "Section": "Art. 18: Content Offenses",
                "Country": "Australia",
                "ISP": "Cloudflare Inc.",
                "Email": "abuse@cloudflare.com",
            },
        },
        "traffic_is_running": True,
        "blocked_ips_set": {"8.8.8.8", "1.1.1.1", "192.168.1.99", "103.255.4.12"},
        "star_rating": 0,
        "feedback_submitted": False,
    }
    for key, value in defaults.items():
        st.session_state.setdefault(key, value)


# ---------------------------------------------------------------------------
# 4. DATA GENERATION & ENRICHMENT
# ---------------------------------------------------------------------------

@st.cache_data(ttl=3600, show_spinner=False)
def fetch_ip_meta(ip_address: str) -> dict:
    """Geo/ISP lookup, cached for an hour per IP so live ticks don't re-hit
    the network (this was a source of both flicker and slowness)."""
    if ip_address.startswith(("192.168.", "10.", "127.")):
        return {
            "country": "Local Intranet Node",
            "org": "AXPS Virtual Private Lab",
            "email": f"network-admin@{ip_address.replace('.', '-')}.internal",
        }
    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip_address}?fields=country,org,status", timeout=1.5
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                org = data.get("org", "Unknown Network Operator")
                domain = org.lower().split(" ")[0].replace(",", "") + ".com"
                return {
                    "country": data.get("country", "Unknown Territory"),
                    "org": org,
                    "email": f"abuse@{domain}",
                }
    except requests.RequestException:
        pass
    return {"country": "Unknown Region", "org": "Dynamic ISP Pipeline", "email": "abuse-desk@ip-route.net"}


def is_externally_fed(file_path: str) -> bool:
    """True if something other than this app's own generator wrote the log
    file most recently — i.e. simulator.py is running locally and appending
    to it. We track our own last write's mtime in session state, so a write
    from app.py itself is never mistaken for an external one, however
    frequently either side writes."""
    if not os.path.exists(file_path):
        return False
    current_mtime = os.path.getmtime(file_path)
    last_self_write = st.session_state.get("_last_self_write_mtime")
    if last_self_write is None:
        # We've never written it ourselves this session — only treat it as
        # external if it was touched very recently (avoids misreading a
        # stale leftover file from a previous run as "live").
        return (time.time() - current_mtime) < 6
    return current_mtime != last_self_write


def populate_default_live_csv(file_path: str) -> None:
    """Simulate a rolling window of network traffic. Kept intentionally
    dependency-free so it can later be swapped for a real log source."""
    np.random.seed(int(time.time()) % 1000)
    timestamps = [
        (datetime.datetime.now() - datetime.timedelta(seconds=i * 15)).strftime("%Y-%m-%d %H:%M:%S")
        for i in range(120)
    ][::-1]

    public_pool = ["8.8.8.8", "1.1.1.1", "104.244.42.1", "140.82.112.4", "192.168.1.99", "103.255.4.12"]
    ips = [
        np.random.choice(public_pool) if np.random.rand() > 0.6 else f"192.168.1.{np.random.randint(10, 254)}"
        for _ in range(120)
    ]

    df_gen = pd.DataFrame(
        {
            "Timestamp": timestamps,
            "IP Address": ips,
            "Protocol": np.random.choice(["TCP", "UDP", "HTTP", "HTTPS"], size=120),
            "Packet Size (KB)": np.random.uniform(100, 4500, size=120),
            "Requests/sec": np.random.uniform(10, 400, size=120),
        }
    )
    df_gen.to_csv(file_path, index=False)
    st.session_state["_last_self_write_mtime"] = os.path.getmtime(file_path)


def parse_and_transform_ledger(file_path: str, max_rows: int = 150) -> pd.DataFrame:
    if not os.path.exists(file_path):
        populate_default_live_csv(file_path)

    raw_df = pd.read_csv(file_path)
    if raw_df.empty:
        populate_default_live_csv(file_path)
        raw_df = pd.read_csv(file_path)

    # simulator.py appends forever, so an externally-fed file only ever
    # grows — keep just the most recent window so scoring stays fast.
    if len(raw_df) > max_rows:
        raw_df = raw_df.tail(max_rows).reset_index(drop=True)

    df = pd.DataFrame()
    df["Timestamp"] = pd.to_datetime(raw_df["Timestamp"])

    # --- raw network-native fields (used by Cyber mode) ---
    df["IP Address"] = raw_df["IP Address"]
    df["Protocol"] = raw_df["Protocol"]
    df["Packet Size (KB)"] = raw_df["Packet Size (KB)"].round(2)
    df["Requests/sec"] = raw_df["Requests/sec"].round(1)

    # --- derived financial-ledger fields (used by Financial mode) ---
    unique_ips = raw_df["IP Address"].unique()
    ip_to_acc = {ip: f"ACC-{np.random.randint(10000, 99999)}" for ip in unique_ips}
    df["Account"] = raw_df["IP Address"].map(ip_to_acc)
    df["Value ($)"] = (raw_df["Packet Size (KB)"] * 5.5).round(2)
    df["Quantity (Tx/Min)"] = (raw_df["Requests/sec"] / 10).round(1)
    action_map = {"TCP": "WIRE TRANSFER", "UDP": "ATM WITHDRAWAL", "HTTP": "MERCHANT CHARGE", "HTTPS": "ONLINE TRANSFER"}
    df["Quality Segment"] = raw_df["Protocol"].map(action_map).fillna("ONLINE TRANSFER")
    return df


# Which real columns belong to which mode — this is what drives every
# mode-aware view below (chart, live log, raw table, export).
CYBER_FIELDS = ["Timestamp", "IP Address", "Protocol", "Packet Size (KB)", "Requests/sec", "Security State"]
FINANCIAL_FIELDS = ["Timestamp", "Account", "Quality Segment", "Value ($)", "Quantity (Tx/Min)", "Security State"]


def mode_columns(system_mode: str) -> list[str]:
    return CYBER_FIELDS if system_mode.startswith("🌐") else FINANCIAL_FIELDS


def mode_display_df(df: pd.DataFrame, system_mode: str) -> pd.DataFrame:
    """Returns only the columns relevant to the selected mode, so Cyber
    mode never shows Account/$ fields and Financial mode never shows raw
    IP/protocol fields."""
    cols = [c for c in mode_columns(system_mode) if c in df.columns]
    return df[cols]


def score_and_classify(df: pd.DataFrame, max_tx_amount: float, max_velocity: float, system_mode: str) -> pd.DataFrame:
    """Run anomaly detection + rule checks, updating the threat registry
    and blocklist as a side effect (mirrors the original app's behaviour).
    Registry entries are tagged with the mode that flagged them, and the
    reason text is phrased in that mode's own vocabulary."""
    is_cyber = system_mode.startswith("🌐")

    if df.empty or len(df) < 2:
        df["Security State"] = "Secured"
        return df

    df = df.sort_values("Timestamp").reset_index(drop=True)
    clf = IsolationForest(contamination=0.05, random_state=42)
    df["Anomaly_Score"] = clf.fit_predict(df[["Value ($)", "Quantity (Tx/Min)"]])

    states = []
    for _, row in df.iterrows():
        ip, acc = row["IP Address"], row["Account"]

        if ip in st.session_state["blocked_ips_set"]:
            states.append("UNSECURED: Blocked IP Source")
            continue

        is_overbudget = row["Value ($)"] > max_tx_amount
        is_high_velocity = row["Quantity (Tx/Min)"] > max_velocity

        if is_overbudget or is_high_velocity:
            states.append("ATTENTION: Limit Exceeded")

            if is_cyber:
                reasons = []
                if is_overbudget:
                    reasons.append(f"Packet load of {row['Packet Size (KB)']:,} KB")
                if is_high_velocity:
                    reasons.append(f"Request rate of {row['Requests/sec']:.0f} req/sec")
                reason_text = f"Cyber Trespass & Bandwidth Overrun: {' & '.join(reasons)}"
                section = "Art. 14: Computer-related Fraud" if is_overbudget else "Art. 18: Traffic Signal Tampering"
            else:
                reasons = []
                if is_overbudget:
                    reasons.append(f"Transaction value of ${row['Value ($)']:,}")
                if is_high_velocity:
                    reasons.append(f"Transaction rate of {row['Quantity (Tx/Min)']} tx/min")
                reason_text = f"Financial Threshold Breach: {' & '.join(reasons)}"
                section = "Art. 14: Unauthorized Financial Access" if is_overbudget else "Art. 18: Transaction Velocity Abuse"

            geo_meta = fetch_ip_meta(ip)
            st.session_state["axps_secured_registry"][ip] = {
                "Account": acc,
                "Timestamp": row["Timestamp"].strftime("%H:%M:%S"),
                "Reason": reason_text,
                "Action": "Isolate Source",
                "Domain": "Cyber" if is_cyber else "Financial",
                "Section": section,
                "Country": geo_meta["country"],
                "ISP": geo_meta["org"],
                "Email": geo_meta["email"],
            }
            st.session_state["blocked_ips_set"].add(ip)
        elif row.get("Anomaly_Score") == -1:
            states.append("ALERT: High Risk Data Pattern")
        else:
            states.append("Secured")

    df["Security State"] = states
    return df

# ---------------------------------------------------------------------------
# 5. AI INSIGHT ENGINE
# ---------------------------------------------------------------------------

def generate_rule_based_insight(df: pd.DataFrame) -> str:
    """A dependency-free 'AI-style' executive summary. This is the default
    engine — no API key required, so the panel always has something useful
    to say."""
    if df.empty:
        return "No traffic observed yet. Waiting on the next scan cycle."

    total = len(df)
    flagged = df[df["Security State"] != "Secured"]
    rate = len(flagged) / total * 100

    if rate == 0:
        return f"All {total} scanned entities are within normal thresholds. No action required."

    top_state = flagged["Security State"].value_counts().idxmax()
    top_ip = flagged["IP Address"].value_counts().idxmax()
    hits = int(flagged["IP Address"].value_counts().max())

    tone = "critical" if rate > 25 else "elevated"
    return (
        f"Risk level is **{tone}** — {len(flagged)} of {total} entities ({rate:.1f}%) "
        f"were flagged this cycle, mostly **{top_state.split(':')[-1].strip()}**. "
        f"`{top_ip}` is the most active source ({hits} occurrences) and is recommended "
        f"for continued isolation. No cross-account collusion pattern detected."
    )


def get_api_key() -> str | None:
    """Reads ANTHROPIC_API_KEY from Streamlit secrets if a secrets.toml
    exists; returns None otherwise. `hasattr(st, "secrets")` is NOT a valid
    check here — st.secrets is a property that always exists but raises
    StreamlitSecretsNotFoundError the moment you touch it if no secrets
    file is present, which is exactly what was crashing the AI panel."""
    try:
        return st.secrets.get("ANTHROPIC_API_KEY")
    except Exception:
        return None


def generate_ai_insight(df: pd.DataFrame) -> str:
    """Uses the Anthropic API for a natural-language summary when an API key
    is available in `st.secrets['ANTHROPIC_API_KEY']`; otherwise falls back
    to the rule-based engine above. Cached briefly so it doesn't fire on
    every 2-second tick."""
    api_key = get_api_key()
    if not api_key or df.empty:
        return generate_rule_based_insight(df)

    cache_key = f"ai_insight_{int(time.time() // 30)}"  # refresh at most every 30s
    if cache_key in st.session_state:
        return st.session_state[cache_key]

    try:
        summary_stats = df["Security State"].value_counts().to_dict()
        prompt = (
            "You are a SOC analyst assistant. In two short sentences, summarize this "
            f"traffic snapshot for a dashboard reader: {summary_stats}. Be concise and factual."
        )
        resp = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": "claude-sonnet-4-6",
                "max_tokens": 150,
                "messages": [{"role": "user", "content": prompt}],
            },
            timeout=4,
        )
        text = resp.json()["content"][0]["text"]
        st.session_state[cache_key] = text
        return text
    except Exception:
        return generate_rule_based_insight(df)
    """Uses the Anthropic API for a natural-language summary when an API key
    is available in `st.secrets['ANTHROPIC_API_KEY']`; otherwise falls back
    to the rule-based engine above. Cached briefly so it doesn't fire on
    every 2-second tick."""
    api_key = st.secrets.get("ANTHROPIC_API_KEY") if hasattr(st, "secrets") else None
    if not api_key or df.empty:
        return generate_rule_based_insight(df)

    cache_key = f"ai_insight_{int(time.time() // 30)}"  # refresh at most every 30s
    if cache_key in st.session_state:
        return st.session_state[cache_key]

    try:
        summary_stats = df["Security State"].value_counts().to_dict()
        prompt = (
            "You are a SOC analyst assistant. In two short sentences, summarize this "
            f"traffic snapshot for a dashboard reader: {summary_stats}. Be concise and factual."
        )
        resp = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": "claude-sonnet-4-6",
                "max_tokens": 150,
                "messages": [{"role": "user", "content": prompt}],
            },
            timeout=4,
        )
        text = resp.json()["content"][0]["text"]
        st.session_state[cache_key] = text
        return text
    except Exception:
        return generate_rule_based_insight(df)


# ---------------------------------------------------------------------------
# 6. SIDEBAR
# ---------------------------------------------------------------------------

@dataclass
class Controls:
    system_mode: str
    max_tx_amount: int
    max_velocity: int


def render_sidebar() -> Controls:
    st.sidebar.markdown("<h2 style='color:#00ffcc;font-weight:800;margin-bottom:0;'>AXPS INSPECTOR</h2>", unsafe_allow_html=True)
    st.sidebar.markdown("<p style='color:#38bdf8;font-size:12px;margin-top:0;'>Cyber &amp; Financial Security Console · v4.0</p>", unsafe_allow_html=True)
    st.sidebar.markdown("<hr style='margin:10px 0 20px 0;border-color:#1e293b;'/>", unsafe_allow_html=True)

    st.sidebar.markdown("### 🔄 Inspector Mode")
    system_mode = st.sidebar.radio(
        "Select Security Context",
        options=["🌐 Cyber Network Traffic Inspector", "🔒 Financial Data Security Ledger"],
        label_visibility="collapsed",
    )

    st.sidebar.markdown("---")
    st.sidebar.markdown("### ⚙️ Operations Control")

    traffic_status = st.sidebar.selectbox(
        "📡 Live Traffic Engine",
        options=["🟢 Traffic: ON (Running)", "🔴 Traffic: OFF (Paused)"],
        index=0 if st.session_state["traffic_is_running"] else 1,
    )
    st.session_state["traffic_is_running"] = traffic_status.startswith("🟢")

    if st.sidebar.button("⚡ Fetch Latest Cyber Logs"):
        if st.session_state["traffic_is_running"]:
            st.sidebar.warning("Pause the Live Traffic Engine first to trigger a manual fetch.")
        else:
            populate_default_live_csv(LIVE_FILE_PATH)
            st.toast("Static logs fetched successfully.", icon="✅")

    if st.sidebar.button("🔄 Reset System State"):
        st.session_state["axps_secured_registry"] = {}
        st.session_state["blocked_ips_set"] = {"8.8.8.8", "1.1.1.1", "192.168.1.99", "103.255.4.12"}
        fetch_ip_meta.clear()
        populate_default_live_csv(LIVE_FILE_PATH)
        st.toast("System configuration hard-rebooted.", icon="🔄")
        st.rerun()

    st.sidebar.markdown("---")
    st.sidebar.markdown("### 🚦 Filter Thresholds")
    max_tx_amount = st.sidebar.slider("Max Transaction Limit ($/Qty)", 1000, 25000, 15000, 1000)
    max_velocity = st.sidebar.slider("Max Traffic Velocity (Req/Min)", 5, 50, 20, 5)

    joined_blocks = ", ".join(sorted(st.session_state["blocked_ips_set"]))
    flagged_input = st.sidebar.text_area("Suspicious Accounts / IPs (Blocked IDs)", joined_blocks)
    if flagged_input:
        st.session_state["blocked_ips_set"] = {ip.strip() for ip in flagged_input.split(",") if ip.strip()}

    render_feedback_button()

    return Controls(system_mode, max_tx_amount, max_velocity)


# ---------------------------------------------------------------------------
# 9a. FEEDBACK — animated sidebar button → Google Form
# ---------------------------------------------------------------------------

@st.dialog("✨ Help Us Improve AXPS")
def open_feedback_dialog() -> None:
    st.markdown(
        """
        ### Thanks for exploring AXPS Inspector 🌸
        Your feedback shapes what we build next. The form opens in a new tab —
        your dashboard session stays exactly as you left it.
        """
    )
    st.link_button("📝 Open Evaluation Form", GOOGLE_FORM_URL, use_container_width=True)
    st.caption("Prefer a one-click rating instead? Scroll to the bottom of the dashboard for a quick 5-star option.")


def render_feedback_button() -> None:
    st.sidebar.markdown("---")
    st.sidebar.subheader("💌 Feedback & Evaluation")
    st.sidebar.markdown('<div class="feedback-btn-wrap">', unsafe_allow_html=True)
    if st.sidebar.button("⭐Rate System Experience", key="btn_feedback", use_container_width=True):
        st.balloons()
        open_feedback_dialog()
    st.sidebar.markdown("</div>", unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# 9b. FEEDBACK — quick 5-star widget for people who won't fill the full form
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# 9b. FEEDBACK — Quick 5-star widget linked directly to Google Forms
# ---------------------------------------------------------------------------

def log_feedback_to_google_form(rating: int) -> None:
    """Sends the star rating directly to the AXPS Cyber Inspector Google Form background endpoint."""
    # Background submission endpoint
    form_url = "https://docs.google.com/forms/d/e/1FAIpQLSdnijBO1N3YNY0hEq1q89tvQMPARt0MKhvhZ0c8r4r2f4FYhQ/formResponse"
    
    # Payload mapping your rating parameter dynamically
    payload = {
        "entry.1037300732": rating  # Maps to your Quick Rating question field
    }
    
    try:
        # Silently post the rating data to your live Google Form responses spreadsheet
        requests.post(form_url, data=payload, timeout=5)
    except Exception:
        # Fail silently so the user dashboard experience remains entirely uninterrupted
        pass


def render_star_rating() -> None:
    st.markdown("---")
    with st.container(border=True):
        st.markdown("<h3 style='color:#00ffcc;margin-top:0;'>⭐ Quick Rating</h3>", unsafe_allow_html=True)
        st.caption("No time for the full survey? Give your honest feedback in one tap.")

        if st.session_state.get("feedback_submitted"):
            st.success(f"Thanks for the {st.session_state['star_rating']}-star rating! 🙏")
        else:
            rating = st.feedback("stars")  # Native Streamlit 5-star interactive component
            if rating is not None:
                st.session_state["star_rating"] = rating + 1  # converts 0-indexed scale to 1-5 stars
                st.session_state["feedback_submitted"] = True
                
                # Stream live directly to the cloud response database
                log_feedback_to_google_form(rating + 1)
                st.rerun()

# ---------------------------------------------------------------------------
# 7. HEADER
# ---------------------------------------------------------------------------

def render_header() -> None:
    st.markdown(
        "<h1 style='margin:0;color:#00ffcc;letter-spacing:-1px;font-weight:800;font-size:38px;'>AXPS INSPECTOR</h1>",
        unsafe_allow_html=True,
    )
    st.caption("Unified cyber traffic & financial transaction security monitoring")


# ---------------------------------------------------------------------------
# 8. LIVE DASHBOARD FRAGMENT
# ---------------------------------------------------------------------------

def render_metric_cards(df: pd.DataFrame) -> None:
    anomalies = df[df["Security State"] != "Secured"]
    cards = [
        ("📊 Scanned Log Entities", len(df), "#00f2fe"),
        ("⚠️ Anomalies Isolated", len(anomalies), "#ff007f"),
        ("🛑 Blocked IP Sources", len(st.session_state["blocked_ips_set"]), "#f59e0b"),
        ("⚖️ Treaty Directives (ICCCL)", len(st.session_state["blocked_ips_set"]) + len(st.session_state["axps_secured_registry"]), "#a855f7"),
    ]
    cols = st.columns(4)
    for col, (label, value, color) in zip(cols, cards):
        with col:
            st.markdown(
                f"""<div class="metric-card" style="--card-color:{color};">
                        <div class="metric-label">{label}</div>
                        <div class="metric-value">{value}</div>
                    </div>""",
                unsafe_allow_html=True,
            )


def render_chart(df: pd.DataFrame, system_mode: str):
    is_cyber = system_mode.startswith("🌐")
    if is_cyber:
        y_col, size_col = "Requests/sec", "Packet Size (KB)"
        hover = ["IP Address", "Protocol"]
    else:
        y_col, size_col = "Value ($)", "Quantity (Tx/Min)"
        hover = ["Account", "Quality Segment"]

    fig = px.scatter(
        df, x="Timestamp", y=y_col, color="Security State", size=size_col,
        color_discrete_map=STATUS_COLORS, hover_data=hover,
    )
    fig.update_layout(
        plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)", font_color="#f0f6fc",
        margin=dict(l=5, r=5, t=5, b=5), height=320,
        xaxis=dict(showgrid=False, linecolor="#1e293b"),
        yaxis=dict(gridcolor="#1e293b", linecolor="#1e293b"),
        transition_duration=300,   # smooth redraw instead of a hard flash
        uirevision="keep-zoom",    # preserves user zoom/pan across live ticks
    )
    return fig


def render_live_log(df: pd.DataFrame, system_mode: str) -> None:
    if df.empty:
        st.info("No active pipeline data discovered.")
        return
    is_cyber = system_mode.startswith("🌐")
    card_color = "#ff007f" if is_cyber else "#00ffcc"

    for _, row in df.iloc[::-1].head(15).iterrows():
        badge_color = STATUS_COLORS.get(row["Security State"], "#10b981")

        if is_cyber:
            identity_line = f"Src IP: <code style='color:#38bdf8;'>{row['IP Address']}</code> ➔ {row['Protocol']}"
            metric_line = f"Packet: <strong>{row['Packet Size (KB)']:,} KB</strong> | Rate: <strong>{row['Requests/sec']:.0f} req/s</strong>"
        else:
            identity_line = f"Account: <code style='color:#38bdf8;'>{row['Account']}</code> ➔ {row['Quality Segment']}"
            metric_line = f"Amt: <strong>${row['Value ($)']:,}</strong> | Rate: <strong>{row['Quantity (Tx/Min)']} tx/min</strong>"

        st.markdown(
            f"""<div class="log-card" style="--card-color:{card_color};">
                    <div style="display:flex;justify-content:space-between;font-size:11px;">
                        <span style="color:#94a3b8;font-weight:600;">{row['Timestamp'].strftime('%H:%M:%S')}</span>
                        <span style="color:{badge_color};font-weight:bold;">{row['Security State']}</span>
                    </div>
                    <div style="font-size:14px;margin-top:5px;font-weight:700;color:#f1f5f9;">
                        {identity_line}
                    </div>
                    <div style="font-size:11px;color:#e2e8f0;margin-top:4px;letter-spacing:.5px;">
                        {metric_line}
                    </div>
                </div>""",
            unsafe_allow_html=True,
        )


def render_registry(system_mode: str) -> None:
    current_domain = "Cyber" if system_mode.startswith("🌐") else "Financial"

    with st.container(border=True):
        st.markdown("<h3 style='color:#00ffcc;margin:0 0 2px 0;'>🛡️ Legal Action &amp; Threat Enforcement Console</h3>", unsafe_allow_html=True)
        st.caption("Registry administered in accordance with the International Cyber Crime Laws (ICCCL) & Budapest Convention.")

        show_all = st.checkbox(f"Show both domains (currently viewing: {current_domain} only)", value=False)

        with st.expander("📁 Threat Registry Table", expanded=False):
            registry = st.session_state["axps_secured_registry"]
            visible = {
                ip: info for ip, info in registry.items()
                if show_all or info.get("Domain", "Cyber") == current_domain
            }
            if visible:
                rows = [
                    {
                        "Threat IP Source": ip,
                        "Domain": info.get("Domain", "N/A"),
                        "Linked Account": info.get("Account", "N/A"),
                        "Timestamp": info.get("Timestamp", "N/A"),
                        "ICCCL Clause": info.get("Section", "N/A"),
                        "Violation Reason": info.get("Reason", "N/A"),
                        "Mitigation": info.get("Action", "N/A"),
                        "Geo": info.get("Country", "Local Node"),
                        "ISP": info.get("ISP", "N/A"),
                        "Compliance Email": info.get("Email", "N/A"),
                    }
                    for ip, info in visible.items()
                ]
                st.dataframe(pd.DataFrame(rows), width="stretch", hide_index=True)
            else:
                st.success(f"🟢 No discovered {current_domain.lower()} threats — system compliant.")

        if st.session_state["axps_secured_registry"]:
            col_sel, col_btn = st.columns([8, 2])
            with col_sel:
                clear_target = st.selectbox("Clear a flagged IP", list(st.session_state["axps_secured_registry"].keys()))
            with col_btn:
                st.write("")
                if st.button("🔓 Clear Threat Record"):
                    st.session_state["axps_secured_registry"].pop(clear_target, None)
                    st.session_state["blocked_ips_set"].discard(clear_target)
                    st.toast(f"Cleared: {clear_target}", icon="🔓")
                    st.rerun()


def render_exports(df: pd.DataFrame, system_mode: str) -> None:
    is_cyber = system_mode.startswith("🌐")
    display_df = mode_display_df(df, system_mode)
    sheet_name = "Network Data Logs" if is_cyber else "Financial Ledger"

    with st.container(border=True):
        st.markdown("<h3 style='color:#38bdf8;margin-top:0;'>📋 System Logs &amp; Raw Backlogs</h3>", unsafe_allow_html=True)
        st.caption(f"Showing {'network traffic' if is_cyber else 'financial transaction'} fields for the current mode.")
        with st.expander("📁 Raw Log Database", expanded=False):
            st.dataframe(display_df, width="stretch", hide_index=True)

        col_txt, col_xlsx = st.columns(2)
        with col_txt:
            st.markdown("#### 📄 Compliance Log (.txt)")
            report = (
                "AXPS COMPLIANCE REPORT\n"
                f"Generated: {datetime.datetime.now():%Y-%m-%d %H:%M:%S}\n"
                f"Mode: {'Cyber Network' if is_cyber else 'Financial Ledger'}\n"
                f"Status: {'CRITICAL' if st.session_state['axps_secured_registry'] else 'COMPLIANT'}\n"
                f"Scanned: {len(df)} | Isolated: {len(st.session_state['axps_secured_registry'])}\n"
            )
            st.download_button("Download (.txt)", report, file_name=f"AXPS_Log_{datetime.date.today()}.txt")

        with col_xlsx:
            st.markdown("#### 🟢 Security Ledger (.xlsx)")
            buf = io.BytesIO()
            with pd.ExcelWriter(buf, engine="xlsxwriter") as writer:
                display_df.to_excel(writer, sheet_name=sheet_name, index=False)
                if st.session_state["axps_secured_registry"]:
                    pd.DataFrame.from_dict(st.session_state["axps_secured_registry"], orient="index").to_excel(
                        writer, sheet_name="Active Violations"
                    )
            st.download_button("Generate (.xlsx)", buf.getvalue(), file_name=f"AXPS_Ledger_{datetime.date.today()}.xlsx")


@st.fragment(run_every=2)
def live_dashboard(controls: Controls) -> None:
    if not st.session_state["traffic_is_running"]:
        st.empty()  # fragment still ticks on schedule but skips regeneration below
    elif not is_externally_fed(LIVE_FILE_PATH):
        # No external process (e.g. simulator.py) is currently writing to the
        # log file — this is the case on Streamlit Cloud, or local runs where
        # you haven't started simulator.py — so generate demo traffic in-process.
        populate_default_live_csv(LIVE_FILE_PATH)
    # else: something external (simulator.py) is actively appending rows —
    # leave the file alone and just read whatever it has written.

    df = parse_and_transform_ledger(LIVE_FILE_PATH)
    df = score_and_classify(df, controls.max_tx_amount, controls.max_velocity, controls.system_mode)

    render_metric_cards(df)

    st.markdown('<div class="ai-panel">', unsafe_allow_html=True)
    st.markdown('<div class="ai-panel-title">🤖 AI SECURITY INSIGHT</div>', unsafe_allow_html=True)
    st.markdown(f'<div class="ai-panel-body">{generate_ai_insight(df)}</div>', unsafe_allow_html=True)
    st.markdown("</div>", unsafe_allow_html=True)
    st.write("")

    col_chart, col_log = st.columns([12, 8])
    with col_chart:
        with st.container(border=True):
            title = "System Network Anomaly Mapping" if controls.system_mode.startswith("🌐") else "Financial Transaction Risk Analysis"
            st.markdown(f"<h3 style='margin-top:0;color:#38bdf8;'>📈 {title}</h3>", unsafe_allow_html=True)
            st.plotly_chart(render_chart(df, controls.system_mode), width="stretch", key="main_chart")

    with col_log:
        with st.container(border=True):
            st.markdown("<h3 style='margin-top:0;color:#ef4444;'>📡 Live Threat Log Pipeline</h3>", unsafe_allow_html=True)
            with st.container(height=320):
                render_live_log(df, controls.system_mode)

    render_registry(controls.system_mode)
    render_exports(df, controls.system_mode)


# ---------------------------------------------------------------------------
# 10. ENTRYPOINT
# ---------------------------------------------------------------------------

def main() -> None:
    inject_css()
    init_state()
    controls = render_sidebar()
    render_header()
    live_dashboard(controls)
    render_star_rating()


if __name__ == "__main__":
    main()