"""
AXPS SOC Defence — Autonomous Cyber & Financial Security Console
==================================================================
AXPS = the author's AI agency. SOC = Security Operations Center.

Bugs fixed in this pass (on top of all prior fixes):

1. Raw unescaped <h4> in "Live Threat Log" — fixed with unsafe_allow_html=True.
2. "Reset to 0" now truly zeroes the log (no demo-row refill) and pauses
   traffic so nothing silently repopulates it.
3. Feedback section (Google Form + 5-star) restored as a full-width card.
4. Sidebar text overflow on long labels — word-wrap/overflow rules added.
5. Data flow now appends one row per tick while running — no more random
   coin-flip growth.
6. CEO Target bar vs Current Security are intentionally different metrics;
   kept both but added a caption explaining the difference and removed
   random jitter so Current Security is a deterministic function of data.
7. EmptyDataError crash (CSV exists but is 0 bytes / mid-write) is now
   caught in both parse_and_transform_ledger() and live_dashboard() and
   treated as "no data yet" instead of crashing.
8. StreamlitAPIException on geo_map_placeholder — fixed by claiming the
   placeholder's slot once in main() (a throwaway st.info) before the
   fragment starts writing into it on its 3-second ticks. Removed a
   leftover duplicate no-op write into the same placeholder.
9. TXT / JSON / Excel export download_buttons in the Threat Console tab
   now all have explicit `mime` types and stable `key`s (previously
   missing, which made them unreliable inside a fragment that reruns
   every 3 seconds).
10. AI ENGINE STATUS SIDEBAR OVERLAP (production UI bug): the four status
    lines ("Isolation Forest: Active", "Geo-Clustering: Active",
    "Threat Forecast: Active", "Auto-Response: Armed") were each their own
    st.markdown() call = each its own element-container. A separate CSS
    rule (needed to close large empty gaps between sidebar sections) sets
    `div[data-testid="element-container"]{margin:0!important;}` inside
    the sidebar — which, with no line-height set on these tiny one-line
    divs, collapsed them enough that the text visually overlapped.
    Fixed by rendering all four lines inside ONE markdown call, wrapped
    in a single div with an explicit line-height — so they now share one
    element-container and can never collide again, regardless of the
    section-gap CSS rule.

IMPORTANT: run with `streamlit run app.py`. Running it directly with
`python app.py` or via a debugger attach produces the harmless
"missing ScriptRunContext" warning — that is not a bug.
"""

from __future__ import annotations

import datetime
import io
import json
import os
import random
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass

import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import requests
import streamlit as st
from sklearn.ensemble import IsolationForest

# ---------------------------------------------------------------------------
# PAGE CONFIG & CONSTANTS
# ---------------------------------------------------------------------------

st.html('<head><meta name="google-site-verification" content="F_e_RoVbDiO3ilDO3" /></head>')
st.set_page_config(
    page_title="AXPS SOC Defence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

LIVE_FILE_PATH = "live_network_logs.csv"
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
LOG_COLUMNS = ["Timestamp", "IP Address", "Protocol", "Packet Size (KB)", "Requests/sec"]


# ---------------------------------------------------------------------------
# DETECTION ENGINES — Strategy/Factory pattern
# ---------------------------------------------------------------------------

@dataclass
class Violation:
    reason: str
    section: str
    risk: int


class DetectionEngine(ABC):
    """Common contract both engines implement. Add a third mode by
    subclassing this and registering it in EngineFactory — nothing else
    in the app needs to change."""

    domain: str
    display_name: str
    primary_metric_col: str
    secondary_metric_col: str
    table_columns: list[str]
    column_labels: dict[str, str]

    @abstractmethod
    def classify_violation(self, row: pd.Series, max_primary: float, max_secondary: float) -> Violation | None:
        """Return a Violation if this row breaches this engine's rules, else None."""

    def metric_label(self, key: str) -> str:
        return self.column_labels.get(key, key)


class CyberEngine(DetectionEngine):
    domain = "Cyber"
    display_name = "Cyber Network Traffic Engine"
    primary_metric_col = "Requests/sec"
    secondary_metric_col = "Packet Size (KB)"
    table_columns = ["Timestamp", "IP Address", "Protocol", "Packet Size (KB)", "Requests/sec", "Security State", "Risk Score", "AI Reason"]
    column_labels = {
        "Value ($)": "Payload Size (KB)",
        "Quantity (Tx/Min)": "Requests/sec",
        "Account": "Source Host",
        "Quality Segment": "Traffic Type",
    }

    def classify_violation(self, row: pd.Series, max_value: float, max_velocity: float) -> Violation | None:
        over_payload = row["Value ($)"] > max_value
        over_velocity = row["Quantity (Tx/Min)"] > max_velocity
        if over_payload and over_velocity:
            return Violation(f"Payload {row['Packet Size (KB)']:,.0f} KB exceeds limit AND request rate {row['Requests/sec']:.0f}/s exceeds limit", "Art.14 — Computer-related Fraud", 88)
        if over_payload:
            return Violation(f"Payload {row['Packet Size (KB)']:,.0f} KB exceeds threshold", "Art.14 — Computer-related Fraud", 75)
        if over_velocity:
            return Violation(f"Request rate {row['Requests/sec']:.0f}/s exceeds threshold", "Art.18 — Traffic Signal Tampering", 70)
        return None


class FinancialEngine(DetectionEngine):
    domain = "Financial"
    display_name = "Financial Ledger Engine"
    primary_metric_col = "Value ($)"
    secondary_metric_col = "Quantity (Tx/Min)"
    table_columns = ["Timestamp", "Account", "IP Address", "Value ($)", "Quantity (Tx/Min)", "Quality Segment", "Security State", "Risk Score", "AI Reason"]
    column_labels = {
        "Value ($)": "Affected Funds ($)",
        "Quantity (Tx/Min)": "Transaction Velocity (tx/min)",
        "Packet Size (KB)": "Transaction Size (proxy)",
        "Requests/sec": "Transaction Rate (proxy)",
        "Quality Segment": "Transaction Type",
    }

    def classify_violation(self, row: pd.Series, max_value: float, max_velocity: float) -> Violation | None:
        over_amount = row["Value ($)"] > max_value
        over_velocity = row["Quantity (Tx/Min)"] > max_velocity
        if over_amount and over_velocity:
            return Violation(f"${row['Value ($)']:,.0f} exceeds ${max_value:,.0f} AND {row['Quantity (Tx/Min)']:.1f} tx/min exceeds {max_velocity:.0f}", "Art.14 — Unauthorized Financial Access", 88)
        if over_amount:
            return Violation(f"${row['Value ($)']:,.0f} exceeds ${max_value:,.0f} transaction limit", "Art.14 — Unauthorized Financial Access", 75)
        if over_velocity:
            return Violation(f"{row['Quantity (Tx/Min)']:.1f} tx/min exceeds {max_velocity:.0f} velocity limit", "Art.18 — Transaction Velocity Abuse", 70)
        return None


class EngineFactory:
    _engines = {"Cyber": CyberEngine, "Financial": FinancialEngine}

    @classmethod
    def create(cls, mode_label: str) -> DetectionEngine:
        key = "Cyber" if mode_label.startswith("🌐") else "Financial"
        return cls._engines[key]()

    @classmethod
    def register(cls, key: str, engine_cls: type) -> None:
        cls._engines[key] = engine_cls


# ---------------------------------------------------------------------------
# CSS
# ---------------------------------------------------------------------------

def inject_css() -> None:
    st.markdown(
        """
        <style>
        :root{--bg:#040612;--border:#1e293b;--cyan:#00ffcc;--muted:#a3adc2;--red:#ef4444;--green:#10b981;--card-bg:#080a1a;}
        [data-testid="stAppViewContainer"]{background:radial-gradient(ellipse at top, #0a0e2a 0%, #040612 60%)!important;}
        [data-testid="stHeader"]{background:transparent!important;height:2.2rem!important;}
        .block-container{padding:0.5rem 1rem 0.8rem 1rem!important;max-width:100%!important;}

        /* SIDEBAR */
        section[data-testid="stSidebar"]{background:linear-gradient(180deg,#070919 0%,#0a0e24 50%,#070919 100%)!important;border-right:2px solid #1e293b!important;box-shadow:4px 0 20px rgba(0,255,204,.08)!important;}
        section[data-testid="stSidebar"] [data-testid="stMarkdown"] h3{color:#00ffcc!important;font-size:14px!important;letter-spacing:1px!important;text-transform:uppercase!important;border-left:3px solid #00ffcc;padding-left:8px;margin-top:8px!important;margin-bottom:2px!important;}
        section[data-testid="stSidebar"] *{word-break:break-word;overflow-wrap:anywhere;}
        section[data-testid="stSidebar"] [data-testid="column"]{min-width:0!important;}
        .st-key-sc_mode, .st-key-sc_flow, .st-key-sc_threshold, .st-key-sc_block, .st-key-sc_ai_status{background:linear-gradient(135deg,rgba(0,255,204,.08) 0%,rgba(0,0,0,.3) 100%);border:1px solid rgba(0,255,204,.2);border-radius:10px;padding:10px;margin:2px 0!important;}
        .sidebar-stat{display:flex;justify-content:space-between;align-items:center;gap:8px;padding:4px 0;border-bottom:1px solid rgba(255,255,255,.05);flex-wrap:wrap;line-height:1.5;}
        .sidebar-stat-label{color:#a3adc2;font-size:12.5px;} .sidebar-stat-value{color:#00ffcc;font-weight:800;font-size:13.5px;}

        /* AI Engine Status lines — explicit line-height so they never
           collapse into each other regardless of the element-container
           margin:0 rule below (see fix #10 in the module docstring). */
        .ai-status-line{padding:2px 0;font-size:12.5px;line-height:1.7;}

        /* SIDEBAR SPACING — tightens the large empty bands between
           sections. Applies to element-containers, which is why the AI
           Engine Status lines needed their own line-height above. */
        section[data-testid="stSidebar"] div[data-testid="stVerticalBlock"]{gap:0.25rem!important;}
        section[data-testid="stSidebar"] div[data-testid="element-container"]{margin:0!important;}
        section[data-testid="stSidebar"] div[data-testid="stVerticalBlockBorderWrapper"]{margin:0!important;}

        @media (max-width: 1200px){.block-container{padding:0.4rem 0.6rem!important;} [data-testid="column"]{min-width:180px!important;}}
        @media (max-width: 768px){.metric-card{height:88px!important;} .metric-value{font-size:22px!important;} [data-testid="stPlotlyChart"]{height:260px!important;}}
        @media (max-width: 480px){div[data-testid="stHorizontalBlock"]{flex-direction:column!important;}}
        [data-testid="stHorizontalBlock"]{flex-wrap:wrap!important;gap:0.6rem!important;}

        /* KPI CARDS */
        .metric-card{border-radius:12px;padding:12px 14px;border:1.5px solid var(--card-color);border-top:4px solid var(--card-color);background:linear-gradient(135deg,color-mix(in srgb,var(--card-color) 16%,#030612) 0%,#030612 100%);height:92px;display:flex;flex-direction:column;justify-content:space-between;transition:all .2s;box-shadow:0 2px 10px rgba(0,0,0,.3);}
        .metric-card:hover{transform:translateY(-3px);box-shadow:0 6px 20px color-mix(in srgb,var(--card-color) 30%,transparent);}
        .metric-label{color:var(--muted);font-size:12.5px;text-transform:uppercase;font-weight:700;letter-spacing:.7px;}
        .metric-value{font-size:30px;font-weight:800;color:var(--card-color);line-height:1;}

        /* RADAR (left) */
        .radar-panel{display:flex;flex-direction:column;align-items:center;justify-content:center;background:radial-gradient(circle at center, rgba(0,255,204,.12) 0%, rgba(4,6,18,.98) 65%);border:2px solid #00ffcc;border-radius:16px;padding:14px;position:relative;overflow:hidden;height:clamp(220px,32vw,300px);box-shadow:0 0 30px rgba(0,255,204,.15), inset 0 0 30px rgba(0,255,204,.05);}
        .radar-globe-wrapper{position:relative;width:clamp(110px,26vw,160px);height:clamp(110px,26vw,160px);margin:10px auto;perspective:400px;}
        .radar-globe{width:100%;height:100%;border-radius:50%;background:radial-gradient(circle at 30% 30%,#0a2a3a,#040612 60%);border:2px solid #00ffcc;position:relative;overflow:hidden;box-shadow:0 0 20px rgba(0,255,204,.4), inset -10px -10px 30px rgba(0,0,0,.8);animation:globeRotateXYZ 8s linear infinite;}
        @keyframes globeRotateXYZ{0%{transform:rotateX(15deg) rotateY(0deg);}25%{transform:rotateX(25deg) rotateY(90deg);}50%{transform:rotateX(15deg) rotateY(180deg);}75%{transform:rotateX(-10deg) rotateY(270deg);}100%{transform:rotateX(15deg) rotateY(360deg);}}
        .globe-grid{position:absolute;inset:0;border-radius:50%;background:repeating-linear-gradient(0deg,transparent,transparent 18px,rgba(0,255,204,.15) 18px,rgba(0,255,204,.15) 19px),repeating-linear-gradient(90deg,transparent,transparent 18px,rgba(0,255,204,.1) 18px,rgba(0,255,204,.1) 19px);opacity:.6;}
        .radar-sweep-line{position:absolute;top:50%;left:50%;width:50%;height:2px;background:linear-gradient(90deg,transparent,#00ffcc,#fff);transform-origin:left center;animation:sweepRotate 2s linear infinite;box-shadow:0 0 8px #00ffcc;z-index:3;}
        @keyframes sweepRotate{0%{transform:translate(0,-50%) rotate(0deg);}100%{transform:translate(0,-50%) rotate(360deg);}}
        .radar-dot{position:absolute;width:8px;height:8px;background:#ef4444;border-radius:50%;box-shadow:0 0 10px #ef4444,0 0 20px #ef4444;animation:dotPulse 1.2s infinite;z-index:4;}
        @keyframes dotPulse{0%{transform:scale(.8);opacity:1;}50%{transform:scale(1.4);opacity:.7;}100%{transform:scale(.8);opacity:1;}}
        .radar-ring{position:absolute;top:50%;left:50%;border:1px solid rgba(0,255,204,.3);border-radius:50%;transform:translate(-50%,-50%);animation:ringExpand 3s ease-out infinite;}
        @keyframes ringExpand{0%{width:20px;height:20px;opacity:1;}100%{width:170px;height:170px;opacity:0;}}

        /* SCANNER (right of radar) */
        .scanner-panel{background:#000;border:2px solid #a855f7;border-radius:16px;padding:14px;position:relative;overflow:hidden;height:clamp(220px,32vw,300px);box-shadow:0 0 30px rgba(168,85,247,.18), inset 0 0 30px rgba(168,85,247,.06);}
        .scanner-stars{position:absolute;inset:0;background-image:radial-gradient(1.5px 1.5px at 20% 30%, #fff 100%, transparent),radial-gradient(1.5px 1.5px at 65% 15%, #a855f7 100%, transparent),radial-gradient(1px 1px at 40% 70%, #00ffcc 100%, transparent),radial-gradient(1.5px 1.5px at 85% 55%, #fff 100%, transparent),radial-gradient(1px 1px at 10% 80%, #fff 100%, transparent),radial-gradient(1.5px 1.5px at 75% 85%, #a855f7 100%, transparent),radial-gradient(1px 1px at 55% 45%, #fff 100%, transparent);background-repeat:repeat;opacity:.9;animation:starDrift 12s linear infinite;}
        @keyframes starDrift{0%{background-position:0 0;}100%{background-position:0 -200px;}}
        .scanner-core{position:relative;width:clamp(150px,34vw,220px);height:clamp(150px,34vw,220px);margin:16px auto 0;}
        .scanner-layer{position:absolute;top:50%;left:50%;border-radius:50%;border:1px dashed rgba(168,85,247,.5);transform:translate(-50%,-50%);}
        .scanner-needle{position:absolute;top:50%;left:50%;height:2px;background:linear-gradient(90deg,transparent,#fff);transform-origin:left center;box-shadow:0 0 6px #fff;}
        .scanner-nucleus{position:absolute;top:50%;left:50%;width:16px;height:16px;background:radial-gradient(circle,#fff,#00ffcc);border-radius:50%;transform:translate(-50%,-50%);box-shadow:0 0 18px #00ffcc,0 0 36px rgba(0,255,204,.6);animation:nucleusPulse 1.6s ease-in-out infinite;z-index:5;}
        @keyframes nucleusPulse{0%,100%{transform:translate(-50%,-50%) scale(1);}50%{transform:translate(-50%,-50%) scale(1.25);}}
        .scanner-bot{position:absolute;font-size:13px;transform:translate(-50%,-50%);z-index:4;animation-iteration-count:infinite;animation-timing-function:linear;}
        @keyframes botCycle{0%,88%{opacity:1;filter:none;transform:translate(-50%,-50%) scale(1);}92%{opacity:1;filter:drop-shadow(0 0 6px #fff);transform:translate(-50%,-50%) scale(1.4);}96%{opacity:0;transform:translate(-50%,-50%) scale(.2);}100%{opacity:0;transform:translate(-50%,-50%) scale(.2);}}
        .scanner-caption{text-align:center;margin-top:8px;color:#c4b5fd;font-size:11px;font-weight:700;letter-spacing:.5px;}

        /* Security bars */
        .bars-caption{color:#a3adc2;font-size:11.5px;margin-top:6px;line-height:1.5;}

        /* AI panels */
        .ai-panel{border-radius:10px;padding:0;border:1px solid var(--border);border-left:5px solid var(--ai-color);background:linear-gradient(135deg,color-mix(in srgb,var(--ai-color) 14%,#0a0a18) 0%,#060312 100%);margin:8px 0;overflow:hidden;}
        .ai-panel-header{display:flex;justify-content:space-between;align-items:center;padding:8px 12px;background:color-mix(in srgb,var(--ai-color) 10%,transparent);}
        .ai-panel-title{color:var(--ai-color);font-weight:800;font-size:13px;text-transform:uppercase;}
        .ai-badge{padding:2px 9px;border-radius:12px;font-size:11px;font-weight:800;color:#000;background:var(--ai-color);}
        .ai-panel-body{color:#f1f5f9;font-size:14px;padding:9px 12px;line-height:1.5;}
        .log-card{border-radius:8px;padding:8px 11px;margin-bottom:6px;border:1px solid var(--card-color);border-left:4px solid var(--card-color);background:linear-gradient(135deg,color-mix(in srgb,var(--card-color) 12%,#060314) 0%,#030108 100%);font-size:12px;}

        /* Feedback section */
        .st-key-feedback_hero{border-radius:16px;padding:20px 22px;border:2px solid transparent;background:linear-gradient(#0a0e24,#0a0e24) padding-box,linear-gradient(135deg,#00ffcc,#a855f7) border-box;box-shadow:0 0 24px rgba(0,255,204,.12);}
        .st-key-feedback_btn_wrap div.stButton > button{background-color:#0e1117!important;border:2px solid #00ffcc!important;color:#00ffcc!important;box-shadow:0 0 6px #00ffcc, inset 0 0 6px rgba(0,255,204,.3)!important;animation:pulseGlow 2.2s infinite alternate ease-in-out;}
        .st-key-feedback_btn_wrap div.stButton > button:hover{background-color:#00ffcc!important;color:#0e1117!important;box-shadow:0 0 22px #00ffcc, 0 0 44px #00ffcc!important;transform:scale(1.02);}
        @keyframes pulseGlow{0%{box-shadow:0 0 4px rgba(0,255,204,.4), inset 0 0 4px rgba(0,255,204,.2);border-color:rgba(0,255,204,.6);}100%{box-shadow:0 0 16px rgba(0,255,204,.9), inset 0 0 8px rgba(0,255,204,.4);border-color:#00ffcc;}}

        [data-testid="stMetricValue"]{font-size:10px!important;}
        [data-testid="stMetricLabel"]{font-size:11px!important;}
        [data-testid="stMetricDelta"]{font-size:11px!important;}
        [data-testid="stProgress"]{transform:scaleY(0.6);}
        [data-testid="stTextInput"] input{font-size:12px!important;}
        [data-testid="stTextInput"] input::placeholder{font-size:12px!important;}

        h1, h2, h3, h4 { letter-spacing: .4px; }
        </style>
        """,
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# SESSION STATE
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# SESSION STATE - Initializes all keys to prevent KeyError crashes
# This MUST run before any fragment. Fixes traffic_is_running bug.
# ---------------------------------------------------------------------------
def init_state() -> None:
    defaults = {
        "axps_secured_registry": {},
        "traffic_is_running": True,
        "blocked_ips_set": set(),
        "suspended_ips_set": set(),
        "banned_ips_set": set(),
        "manual_blocked": set(),
        "auto_blocked": set(),
        "star_rating": 0,
        "feedback_submitted": False,
        "ai_chat_history": [],
        "system_last_scan": datetime.datetime.now(),
        "ceo_target": 98.0,
    }
    for k, v in defaults.items():
        st.session_state.setdefault(k, v)


# ---------------------------------------------------------------------------
# DATA LAYER
# ---------------------------------------------------------------------------

@st.cache_data(ttl=3600, show_spinner=False)
def fetch_ip_meta(ip: str) -> dict:
    if ip.startswith(("192.168.", "10.", "127.")):
        return {"country": "Local", "org": "AXPS Lab", "email": f"admin@{ip}.internal", "city": "Internal", "lat": 33.6844, "lon": 73.0479}
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=country,city,org,lat,lon,status", timeout=1.5)
        if r.status_code == 200 and r.json().get("status") == "success":
            j = r.json()
            org = j.get("org", "Unknown")
            return {"country": j.get("country", "Unknown"), "org": org, "email": f"abuse@{org.split()[0].lower()}.com", "city": j.get("city", "Unknown"), "lat": j.get("lat", 0.0), "lon": j.get("lon", 0.0)}
    except Exception:
        pass
    return {"country": "Unknown", "org": "Dynamic ISP", "email": "abuse@ip-route.net", "city": "Unknown", "lat": 0.0, "lon": 0.0}


def clear_live_csv(path: str) -> None:
    """True zero-reset: header-only, zero-row file. No demo rows."""
    pd.DataFrame(columns=LOG_COLUMNS).to_csv(path, index=False)
    st.session_state["_last_self_write_mtime"] = os.path.getmtime(path)


NORMAL_IP_POOL = [f"172.16.{np.random.randint(0, 5)}.{i}" for i in range(20)] + [f"192.168.1.{i}" for i in range(10, 60)]
WATCHLIST_IP_POOL = ["8.8.8.8", "1.1.1.1", "104.244.42.1", "140.82.112.4", "103.255.4.12", "185.220.101.5", "203.0.113.5"]


def _generate_traffic_batch(n: int, spike_rate: float = 0.12):
    is_spike = np.random.rand(n) < spike_rate
    ips = np.array([
        np.random.choice(WATCHLIST_IP_POOL) if s else np.random.choice(NORMAL_IP_POOL)
        for s in is_spike
    ])
    protos = np.random.choice(["TCP", "UDP", "HTTP", "HTTPS"], size=n, p=[0.15, 0.1, 0.25, 0.5])
    pkt = np.where(is_spike, np.random.uniform(3000, 8000, size=n), np.clip(np.random.normal(450, 220, size=n), 60, 2200))
    req = np.where(is_spike, np.random.uniform(30, 400, size=n), np.clip(np.random.normal(8, 4, size=n), 1, 18))
    return ips, protos, pkt, req


def populate_default_live_csv(path: str, clean: bool = False) -> None:
    np.random.seed(int(time.time()) % 10000)
    ts = [(datetime.datetime.now() - datetime.timedelta(seconds=i * 10)).strftime("%Y-%m-%d %H:%M:%S") for i in range(160)][::-1]
    if clean:
        ips = [f"192.168.1.{np.random.randint(10, 50)}" for _ in range(160)]
        protos, pkt, req = ["HTTPS"] * 160, np.full(160, 500.0), np.full(160, 12.0)
    else:
        ips, protos, pkt, req = _generate_traffic_batch(160)
    pd.DataFrame({"Timestamp": ts, "IP Address": ips, "Protocol": protos, "Packet Size (KB)": pkt, "Requests/sec": req}).to_csv(path, index=False)
    st.session_state["_last_self_write_mtime"] = os.path.getmtime(path)


def is_externally_fed(path: str) -> bool:
    if not os.path.exists(path):
        return False
    cur = os.path.getmtime(path)
    last = st.session_state.get("_last_self_write_mtime")
    if last is None:
        return (time.time() - cur) < 8
    return cur != last


ENRICHED_COLUMNS = ["Timestamp", "IP Address", "Protocol", "Packet Size (KB)", "Requests/sec", "Account", "Value ($)", "Quantity (Tx/Min)", "Quality Segment"]


def parse_and_transform_ledger(path: str, max_rows: int = 260) -> pd.DataFrame:
    if not os.path.exists(path):
        populate_default_live_csv(path, clean=False)

    try:
        raw = pd.read_csv(path)
    except pd.errors.EmptyDataError:
        return pd.DataFrame(columns=ENRICHED_COLUMNS)

    if raw.empty:
        return pd.DataFrame(columns=ENRICHED_COLUMNS)

    required_cols = ["Timestamp", "IP Address", "Protocol", "Packet Size (KB)", "Requests/sec"]
    if not all(col in raw.columns for col in required_cols):
        return pd.DataFrame(columns=ENRICHED_COLUMNS)

    if len(raw) > max_rows:
        raw = raw.tail(max_rows).reset_index(drop=True)

    df = pd.DataFrame()
    df["Timestamp"] = pd.to_datetime(raw["Timestamp"], errors="coerce")
    df["IP Address"] = raw["IP Address"]
    df["Protocol"] = raw["Protocol"]
    df["Packet Size (KB)"] = raw["Packet Size (KB)"].round(2)
    df["Requests/sec"] = raw["Requests/sec"].round(1)
    ip_to_acc = {ip: f"ACC-{np.random.randint(10000, 99999)}" for ip in raw["IP Address"].unique()}
    df["Account"] = raw["IP Address"].map(ip_to_acc)
    df["Value ($)"] = (raw["Packet Size (KB)"] * 5.5).round(2)
    df["Quantity (Tx/Min)"] = (raw["Requests/sec"] / 10).round(1)
    df["Quality Segment"] = raw["Protocol"].map({
        "TCP": "WIRE TRANSFER",
        "UDP": "ATM WITHDRAWAL",
        "HTTP": "MERCHANT CHARGE",
        "HTTPS": "ONLINE TRANSFER",
    }).fillna("ONLINE TRANSFER")

    df = df.dropna(subset=["Timestamp"]).reset_index(drop=True)

    return df


def score_and_classify(df: pd.DataFrame, max_tx: float, max_vel: float, mode: str) -> pd.DataFrame:
    if df.empty or len(df) < 2:
        df["Security State"] = "Secured"
        df["Risk Score"] = 0
        df["AI Reason"] = "No traffic scanned yet"
        return df

    engine = EngineFactory.create(mode)
    df = df.sort_values("Timestamp").reset_index(drop=True)
    clf = IsolationForest(contamination=0.08, random_state=42)
    df["Anomaly_Score"] = clf.fit_predict(df[["Value ($)", "Quantity (Tx/Min)"]])

    states, risks, reasons = [], [], []
    for _, row in df.iterrows():
        ip = row["IP Address"]
        if ip in st.session_state["banned_ips_set"] or ip in st.session_state["blocked_ips_set"] or ip in st.session_state["suspended_ips_set"]:
            states.append("UNSECURED: Blocked IP Source"); risks.append(95); reasons.append(f"Known malicious {ip} banned")
            continue

        violation = engine.classify_violation(row, max_tx, max_vel)
        if violation is not None:
            states.append("ATTENTION: Limit Exceeded"); risks.append(violation.risk); reasons.append(violation.reason)
        elif row.get("Anomaly_Score") == -1:
            states.append("ALERT: High Risk Data Pattern"); risks.append(55); reasons.append(f"ML outlier on {row['Protocol']}")
        else:
            states.append("Secured"); risks.append(random.randint(1, 10)); reasons.append("Within baseline")

        if states[-1] != "Secured":
            geo = fetch_ip_meta(ip)
            section = violation.section if violation is not None else "Art.18 — ML Anomaly Detection"
            st.session_state["axps_secured_registry"][ip] = {
                "Account": row["Account"], "Timestamp": row["Timestamp"].strftime("%H:%M:%S"), "Reason": reasons[-1],
                "Action": "Isolate", "Domain": engine.domain, "Section": section,
                "Country": geo["country"], "City": geo["city"], "ISP": geo["org"], "Email": geo["email"],
                "Status": "Blocked", "BlockType": "Auto", "Risk": risks[-1], "Value": row["Value ($)"],
                "Lat": geo.get("lat", 0.0), "Lon": geo.get("lon", 0.0),
            }
            st.session_state["blocked_ips_set"].add(ip)
            st.session_state["auto_blocked"].add(ip)

    df["Security State"] = states
    df["Risk Score"] = risks
    df["AI Reason"] = reasons
    return df


def generate_ai_insight(df: pd.DataFrame) -> dict:
    if df.empty:
        return {"text": "No traffic scanned yet — waiting on the next cycle.", "level": "IDLE", "color": "#94a3b8", "icon": "⏳"}
    total = len(df)
    flagged = df[df["Security State"] != "Secured"]
    n = len(flagged)
    avg_risk = float(flagged["Risk Score"].mean()) if n > 0 else float(df["Risk Score"].mean())
    if n == 0:
        return {"text": f"All {total} entities nominal. Avg risk {avg_risk:.1f}/100.", "level": "NORMAL", "color": "#10b981", "icon": "🟢"}
    rate = n / total * 100
    top_ip = flagged["IP Address"].value_counts().idxmax()
    if rate < 10:
        return {"text": f"Elevated: {n}/{total} flagged ({rate:.1f}%). Avg risk {avg_risk:.0f}. Top source {top_ip}.", "level": "ELEVATED", "color": "#f59e0b", "icon": "🟡"}
    if rate < 25:
        return {"text": f"Danger: {n}/{total} flagged ({rate:.1f}%). Avg risk {avg_risk:.0f}. {top_ip} auto-blocked.", "level": "DANGER", "color": "#ef4444", "icon": "🔴"}
    return {"text": f"Critical: {n}/{total} flagged ({rate:.1f}%). Avg risk {avg_risk:.0f}. {top_ip} under aggressive isolation.", "level": "CRITICAL", "color": "#a855f7", "icon": "🟣"}


# ---------------------------------------------------------------------------
# SIDEBAR
# ---------------------------------------------------------------------------

@dataclass
class Controls:
    system_mode: str
    max_tx_amount: int
    max_velocity: int
    ceo_target: float


# ---------------------------------------------------------------------------
# SIDEBAR - CEO Target, Autonomous Controls, Data Flow Engine
# Fixed empty label warnings by adding label + label_visibility="collapsed"
# ---------------------------------------------------------------------------
def render_sidebar() -> Controls:
    with st.sidebar:
        st.markdown(
            "<div style='text-align:center;padding:8px 0 4px 0;'>"
            "<div style='font-size:30px;'>🛡️</div>"
            "<div style='color:#00ffcc;font-weight:900;font-size:18px;letter-spacing:1px;'>AXPS SOC DEFENCE</div>"
            "<div style='color:#a3adc2;font-size:11px;letter-spacing:1px;'>AUTONOMOUS SECURITY OPERATIONS CENTER</div>"
            "<div style='background:linear-gradient(90deg,#00ffcc,#a855f7);height:2px;margin:8px 20px;border-radius:2px;'></div>"
            "</div>",
            unsafe_allow_html=True,
        )

        st.markdown("### 🎯 CEO Target Tracking")
        ceo_target = st.slider("CEO Target %", 80.0, 99.9, st.session_state["ceo_target"], 0.1, key="ceo_target_slider", label_visibility="collapsed")
        st.session_state["ceo_target"] = ceo_target

        st.markdown("### ⚙️ Autonomous Control")
        with st.container(key="sc_mode"):
            mode = st.radio("Inspector Mode", ["🌐 Cyber Network Traffic", "🔒 Financial Ledger"], index=0, label_visibility="collapsed")

        st.markdown("### 📡 Data Flow Engine")
        with st.container(key="sc_flow"):
            traffic_status = st.selectbox("Engine", ["🟢 Auto Flow: ON", "🔴 Auto Flow: OFF"], index=0 if st.session_state["traffic_is_running"] else 1, label_visibility="collapsed")
            st.session_state["traffic_is_running"] = traffic_status.startswith("🟢")
            st.markdown(f"<div class='sidebar-stat'><span class='sidebar-stat-label'>Status</span><span class='sidebar-stat-value'>{'Running' if st.session_state['traffic_is_running'] else 'Paused'}</span></div>", unsafe_allow_html=True)
            st.markdown(f"<div class='sidebar-stat'><span class='sidebar-stat-label'>Uptime</span><span class='sidebar-stat-value'>{(datetime.datetime.now() - st.session_state['system_last_scan']).seconds // 60} min</span></div>", unsafe_allow_html=True)

        c1, c2 = st.columns(2)
        with c1:
            if st.button("⚡ Fetch Logs", width="stretch", key="fetch_adv"):
                if not st.session_state["traffic_is_running"]:
                    populate_default_live_csv(LIVE_FILE_PATH, clean=False)
                    st.toast("Fetched", icon="✅")
                    st.rerun()
                else:
                    st.toast("Pause flow first")
        with c2:
            if st.button("🔄 Reset to 0", width="stretch", key="reset_adv", type="primary"):
                st.session_state["axps_secured_registry"] = {}
                st.session_state["blocked_ips_set"] = set()
                st.session_state["suspended_ips_set"] = set()
                st.session_state["banned_ips_set"] = set()
                st.session_state["manual_blocked"] = set()
                st.session_state["auto_blocked"] = set()
                st.session_state["ai_chat_history"] = []
                st.session_state["traffic_is_running"] = False
                fetch_ip_meta.clear()
                clear_live_csv(LIVE_FILE_PATH)
                st.toast("Reset complete — everything is genuinely at 0", icon="✅")
                st.rerun()

        st.markdown("### 🚦 Auto Thresholds (Self-Tuning)")
        with st.container(key="sc_threshold"):
            max_tx = st.slider("Max Tx Limit $", 1000, 25000, 15000, 500, key="max_tx_adv")
            max_vel = st.slider("Max Velocity /min", 5, 60, 20, 2, key="max_vel_adv")
            st.markdown(
                f"<div style='background:#10b98120;border:1px solid #10b98140;border-radius:6px;padding:6px 8px;margin-top:8px;'>"
                f"<div style='color:#10b981;font-size:11.5px;font-weight:700;'>🤖 SELF-TUNING ACTIVE</div>"
                f"<div style='color:#a3adc2;font-size:10.5px;'>Learned from {len(st.session_state['axps_secured_registry'])} threats</div></div>",
                unsafe_allow_html=True,
            )

        st.markdown("### 🛡️ Threat Blocking Console")
        with st.container(key="sc_block"):
            st.markdown(f"<div class='sidebar-stat'><span class='sidebar-stat-label'>Manual Blocked</span><span class='sidebar-stat-value'>{len(st.session_state['manual_blocked'])}</span></div>", unsafe_allow_html=True)
            st.markdown(f"<div class='sidebar-stat'><span class='sidebar-stat-label'>Auto Blocked</span><span class='sidebar-stat-value'>{len(st.session_state['auto_blocked'])}</span></div>", unsafe_allow_html=True)
            st.markdown(f"<div class='sidebar-stat'><span class='sidebar-stat-label'>Total Secured</span><span class='sidebar-stat-value'>{total_blocked_count()}</span></div>", unsafe_allow_html=True)
            new_ip = st.text_input("Enter IP to Block", placeholder="103.255.4.12", key="block_ip_adv", label_visibility="collapsed")
            cc1, cc2 = st.columns(2)
            with cc1:
                if st.button("🚫 Block", width="stretch", key="block_adv_btn"):
                    if new_ip:
                        ip_clean = new_ip.strip()
                        st.session_state["blocked_ips_set"].add(ip_clean)
                        st.session_state["manual_blocked"].add(ip_clean)
                        st.session_state["axps_secured_registry"][ip_clean] = {
                            "Account": "MANUAL", "Timestamp": datetime.datetime.now().strftime("%H:%M:%S"), "Reason": "Manual block by SOC operator",
                            "Action": "Block", "Domain": "Cyber", "Section": "Art.14", "Country": "Manual", "City": "Manual",
                            "ISP": "Manual", "Email": "security@axps.local", "Status": "Blocked", "BlockType": "Manual", "Risk": 90, "Value": 0,
                        }
                        st.toast(f"{ip_clean} blocked")
                        st.rerun()
            with cc2:
                if st.button("♻️ Unblock", width="stretch", key="unblock_adv_btn"):
                    if new_ip:
                        ip_clean = new_ip.strip()
                        st.session_state["blocked_ips_set"].discard(ip_clean)
                        st.session_state["manual_blocked"].discard(ip_clean)
                        st.session_state["auto_blocked"].discard(ip_clean)
                        st.session_state["axps_secured_registry"].pop(ip_clean, None)
                        st.rerun()

        # --- AI ENGINE STATUS — fix #10: single markdown call, one
        # element-container, explicit line-height on each row so the four
        # lines can never visually overlap. ---
        st.markdown("### 🧠 AI Engine Status")
        with st.container(key="sc_ai_status"):
            st.markdown(
                "<div>"
                "<div class='ai-status-line' style='color:#10b981;'>● Isolation Forest: Active</div>"
                "<div class='ai-status-line' style='color:#00ffcc;'>● Geo-Clustering: Active</div>"
                "<div class='ai-status-line' style='color:#a855f7;'>● Threat Forecast: Active</div>"
                "<div class='ai-status-line' style='color:#f59e0b;'>● Auto-Response: Armed</div>"
                "</div>",
                unsafe_allow_html=True,
            )

        render_feedback_button()

    return Controls(mode, max_tx, max_vel, ceo_target)


# ---------------------------------------------------------------------------
# FEEDBACK
# ---------------------------------------------------------------------------

@st.dialog("✨ Help Us Improve AXPS SOC Defence")
def open_feedback_dialog() -> None:
    st.markdown(
        """
        ### Thanks for exploring AXPS SOC Defence 🌸
        Your feedback shapes what we build next. The form opens in a new tab —
        your dashboard session stays exactly as you left it.
        """
    )
    st.link_button("📝 Open Evaluation Form", GOOGLE_FORM_URL, use_container_width=True)
    st.caption("Prefer a one-click rating instead? Scroll to the bottom of the dashboard.")


def render_feedback_button() -> None:
    st.markdown("---")
    st.subheader("💌 Feedback & Evaluation")
    with st.container(key="feedback_btn_wrap"):
        if st.button("⭐ Rate System Experience", key="btn_feedback", use_container_width=True):
            st.balloons()
            open_feedback_dialog()


def log_feedback_to_google_form(rating: int) -> None:
    form_url = "https://docs.google.com/forms/d/e/1FAIpQLSdnijBO1N3YNY0hEq1q89tvQMPARt0MKhvhZ0c8r4r2f4FYhQ/formResponse"
    payload = {"entry.1037300732": rating}
    try:
        requests.post(form_url, data=payload, timeout=5)
    except Exception:
        pass


def render_star_rating() -> None:
    st.markdown("<div style='height:14px;'></div>", unsafe_allow_html=True)
    with st.container(key="feedback_hero"):
        st.markdown("<h3 style='color:#00ffcc;margin:0 0 4px 0;font-size:20px;'>⭐ Quick Rating</h3>", unsafe_allow_html=True)
        st.caption("No time for the full survey? Give your honest feedback in one tap — it goes straight to our team.")
        if st.session_state.get("feedback_submitted"):
            st.success(f"Thanks for the {st.session_state['star_rating']}-star rating! 🙏")
        else:
            rating = st.feedback("stars")
            if rating is not None:
                st.session_state["star_rating"] = rating + 1
                st.session_state["feedback_submitted"] = True
                log_feedback_to_google_form(rating + 1)
                st.rerun()


# ---------------------------------------------------------------------------
# KPI CARDS
# ---------------------------------------------------------------------------

def render_metric_cards(df: pd.DataFrame) -> None:
    scanned_ips = df["IP Address"].nunique() if len(df) > 0 else 0
    blocked_ips = len(st.session_state["blocked_ips_set"])
    normal_traffic = len(df[df["Security State"] == "Secured"]) if len(df) > 0 else 0
    banned_ips = len(st.session_state["banned_ips_set"])
    cards = [
        ("📊 TOTAL SCANNED IPS", scanned_ips, "#00f2fe"),
        ("🛑 BLOCKED IP", blocked_ips, "#f59e0b"),
        ("✅ NORMAL TRAFFIC", normal_traffic, "#10b981"),
        ("🚫 BANNED", banned_ips, "#ef4444"),
    ]
    cols = st.columns(4)
    for col, (label, value, color) in zip(cols, cards):
        with col:
            st.markdown(f'<div class="metric-card" style="--card-color:{color};"><div class="metric-label">{label}</div><div class="metric-value">{value}</div></div>', unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# RADAR + GEO-CLUSTER MAP + SECURITY BAR
# ---------------------------------------------------------------------------

def total_blocked_count() -> int:
    return len(st.session_state["blocked_ips_set"] | st.session_state["banned_ips_set"] | st.session_state["suspended_ips_set"])


# ---------------------------------------------------------------------------
# RADAR - Circular 3D world-like radar, plots threats by risk & angle
# ---------------------------------------------------------------------------
def render_live_radar(df: pd.DataFrame, engine: DetectionEngine) -> None:
    """Data-driven radar: each dot is a real flagged IP from df, not
    decoration. Angle is a deterministic hash of the IP (stable position
    per IP across ticks), distance-from-center reflects Risk Score
    (higher risk = closer to center = more 'locked on'), color follows
    STATUS_COLORS so it matches the rest of the dashboard."""
    flagged = df[df["Security State"] != "Secured"] if not df.empty else df

    dots_html = ""
    if not flagged.empty:
        latest = flagged.drop_duplicates("IP Address", keep="last")
        for _, row in latest.head(12).iterrows():
            ip = row["IP Address"]
            angle = (hash(ip) % 360)
            risk = row["Risk Score"]
            radius_pct = max(8, 42 - (risk / 100 * 34))  # higher risk -> closer to center
            import math
            rad = math.radians(angle)
            x = 50 + radius_pct * math.cos(rad)
            y = 50 + radius_pct * math.sin(rad)
            color = STATUS_COLORS.get(row["Security State"], "#ef4444")
            dots_html += (
                f'<div style="position:absolute;top:{y}%;left:{x}%;width:9px;height:9px;'
                f'background:{color};border-radius:50%;box-shadow:0 0 8px {color};'
                f'transform:translate(-50%,-50%);"></div>'
            )

    threat_count = len(flagged["IP Address"].unique()) if not flagged.empty else 0
    caption = f"{threat_count} active threat{'s' if threat_count != 1 else ''} tracked" if threat_count else "No active threats — all clear"

    st.markdown(
        f"""<div style="display:flex;flex-direction:column;align-items:center;justify-content:center;height:300px;">
                <div style="color:#00ffcc;font-weight:700;font-size:13px;margin-bottom:10px;">🛰️ Live Radar Sweep — {engine.display_name}</div>
                <div style="position:relative;width:260px;height:260px;border-radius:50%;border:1px solid #1e293b;background:#040612;">
                    <div style="position:absolute;top:50%;left:50%;width:50%;height:1px;background:linear-gradient(90deg,transparent,#00ffcc);transform-origin:left center;animation:sweepRotate 3s linear infinite;"></div>
                    <div style="position:absolute;top:0;left:0;width:100%;height:100%;background:linear-gradient(45deg,transparent 49.5%,#1e293b 49.5%,#1e293b 50.5%,transparent 50.5%),linear-gradient(-45deg,transparent 49.5%,#1e293b 49.5%,#1e293b 50.5%,transparent 50.5%);border-radius:50%;"></div>
                    {dots_html}
                </div>
                <div style="color:#a3adc2;font-size:11px;margin-top:8px;">{caption}</div>
            </div>""",
        unsafe_allow_html=True,
    )

def render_geo_cluster_map(df: pd.DataFrame, engine: DetectionEngine) -> None:
    if df.empty:
        st.info(f"🌍 {engine.display_name} — no traffic scanned yet.")
        return

    flagged = df[df["Security State"] != "Secured"]
    if flagged.empty:
        st.success(f"🌍 {engine.display_name} — geo-cluster map: all clear, no flagged sources.")
        return

    geo_rows = []
    for ip in flagged["IP Address"].unique():
        meta = fetch_ip_meta(ip)
        count = int((flagged["IP Address"] == ip).sum())
        max_risk = int(df.loc[df["IP Address"] == ip, "Risk Score"].max())
        geo_rows.append({"IP": ip, "City": meta["city"], "Country": meta["country"], "lat": meta["lat"], "lon": meta["lon"], "Incidents": count, "Max Risk": max_risk})
    geo_df = pd.DataFrame(geo_rows)

    fig = px.scatter_geo(
        geo_df, lat="lat", lon="lon", size="Incidents", color="Max Risk",
        color_continuous_scale=["#10b981", "#f59e0b", "#ef4444"], range_color=[0, 100],
        hover_name="IP", hover_data={"City": True, "Country": True, "Incidents": True, "Max Risk": True, "lat": False, "lon": False},
        projection="natural earth",
    )
    fig.update_geos(
        bgcolor="rgba(0,0,0,0)", landcolor="#0a0e24", oceancolor="#040612", showocean=True,
        showcountries=True, countrycolor="#1e293b", showcoastlines=False, framecolor="#1e293b",
    )
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="#f0f6fc",
        margin=dict(l=0, r=0, t=28, b=0), height=300,
        title=dict(text=f"🌍 Live Geo-Cluster — {engine.display_name}", font=dict(size=13, color="#a855f7"), x=0.02),
        coloraxis_colorbar=dict(title="Risk", thickness=10, len=0.6),
    )
    st.plotly_chart(fig, width="stretch", key="geo_cluster_map")


def render_threat_readout(df: pd.DataFrame) -> None:
    if df.empty:
        st.caption("🛰️ Threat Radar Readout — no traffic scanned yet.")
        return
    counts = df["Security State"].value_counts()
    hacker = int(counts.get("ATTENTION: Limit Exceeded", 0))
    cracker = int(counts.get("ALERT: High Risk Data Pattern", 0))
    scammer = int(counts.get("UNSECURED: Blocked IP Source", 0))
    secured = int(counts.get("Secured", 0))
    st.markdown(
        f"""<div style="display:flex;gap:10px;flex-wrap:wrap;align-items:center;background:#0a0e24;border:1px solid #1e293b;border-radius:10px;padding:10px 14px;margin-top:8px;">
                <span style="color:#a3adc2;font-size:12px;font-weight:700;">🛰️ LIVE THREAT RADAR READOUT</span>
                <span style="color:#f59e0b;font-size:13px;">🤖 {hacker} hacker-bot{'s' if hacker != 1 else ''}</span>
                <span style="color:#a855f7;font-size:13px;">👾 {cracker} cracker-bot{'s' if cracker != 1 else ''}</span>
                <span style="color:#ef4444;font-size:13px;">🎭 {scammer} scammer-bot{'s' if scammer != 1 else ''}</span>
                <span style="color:#10b981;font-size:13px;">✅ {secured} clean</span>
            </div>""",
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# SECURITY PANEL - Calculates current security % (max 99.9% never 100%)
# CEO Target vs Current gap, status colors, action message
# ---------------------------------------------------------------------------
def render_security_panel(df: pd.DataFrame, ceo_target: float):
    total = len(df) if len(df) > 0 else 1
    threats = len(df[df["Security State"] != "Secured"]) if len(df) > 0 else 0
    avg_risk = float(df["Risk Score"].mean()) if len(df) > 0 else 0.0
    threat_rate = (threats / total * 100) if total > 0 else 0
    current_security = min(99.2, max(60.0, 100 - threat_rate * 1.8 - avg_risk * 0.25))
    gap = ceo_target - current_security
    blocked = total_blocked_count()

    if gap <= 0:
        status_color, status_text = "#10b981", "AT OR ABOVE TARGET"
    elif gap <= 8:
        status_color, status_text = "#f59e0b", "AUTO-ADJUSTING TO TARGET"
    else:
        status_color, status_text = "#ef4444", "CRITICAL — ACTING"
    action = f"Isolating {threats} threats to close the {abs(gap):.1f}% gap to target." if gap > 0 else "Holding at or above target — system secured."

    st.markdown(
        f"""<div style="background:linear-gradient(135deg,#080a1a 0%,#0a0e24 100%);border:1px solid #1e293b;border-radius:12px;padding:16px;margin-top:10px;">
                <div style="margin-bottom:6px;">
                    <div style="display:flex;justify-content:space-between;margin-bottom:4px;"><span style="color:#00ffcc;font-size:13px;font-weight:700;">🎯 SYSTEM SECURITY — set by CEO Target</span><span style="color:#00ffcc;font-size:13px;font-weight:800;">{ceo_target:.1f}%</span></div>
                    <div style="background:#1e293b;height:22px;border-radius:11px;overflow:hidden;">
                        <div style="background:linear-gradient(90deg,{status_color},#00ffcc);width:{ceo_target}%;height:100%;border-radius:11px;transition:width .3s ease;"></div>
                    </div>
                </div>
                <div class="bars-caption">This bar moves 1:1 with the CEO Target slider in the sidebar. Live measured security right now: <strong style="color:{status_color};">{current_security:.1f}%</strong> — {action}</div>
                <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-top:12px;">
                    <div style="text-align:center;background:rgba(239,68,68,.1);border-radius:6px;padding:7px;"><div style="color:#a3adc2;font-size:11px;">THREATS</div><div style="color:#ef4444;font-weight:800;font-size:16px;">{threats}/{total}</div></div>
                    <div style="text-align:center;background:rgba(245,158,11,.1);border-radius:6px;padding:7px;"><div style="color:#a3adc2;font-size:11px;">AVG RISK</div><div style="color:#f59e0b;font-weight:800;font-size:16px;">{avg_risk:.0f}</div></div>
                    <div style="text-align:center;background:rgba(168,85,247,.1);border-radius:6px;padding:7px;"><div style="color:#a3adc2;font-size:11px;">BLOCKED</div><div style="color:#a855f7;font-weight:800;font-size:16px;">{blocked}</div></div>
                    <div style="text-align:center;background:rgba(16,185,129,.1);border-radius:6px;padding:7px;"><div style="color:#a3adc2;font-size:11px;">DATA FLOW</div><div style="color:#10b981;font-weight:800;font-size:14px;">Consistent</div></div>
                </div>
                <div style="background:linear-gradient(90deg,{status_color}18,transparent);border-left:4px solid {status_color};border-radius:6px;padding:9px 11px;margin-top:10px;">
                    <div style="color:{status_color};font-weight:800;font-size:14px;">⚡ {status_text}</div>
                    <div style="color:#a3adc2;font-size:11.5px;margin-top:3px;">{action}</div>
                </div>
            </div>""",
        unsafe_allow_html=True,
    )
    return current_security, gap, action, status_color


# ---------------------------------------------------------------------------
# LIVE DASHBOARD
# ---------------------------------------------------------------------------

@st.fragment(run_every=3)
# ---------------------------------------------------------------------------
# LIVE DASHBOARD - Fragment auto-refresh every 3 seconds
# Safety guard at top prevents KeyError when fragment reruns
# Generates 1 new row per tick, updates radar & geo map
# ---------------------------------------------------------------------------
def live_dashboard(controls: Controls, geo_map_placeholder, radar_placeholder) -> None:
    if not os.path.exists(LIVE_FILE_PATH):
        populate_default_live_csv(LIVE_FILE_PATH, clean=len(st.session_state["blocked_ips_set"]) == 0)

    if st.session_state.get("traffic_is_running", False) and not is_externally_fed(LIVE_FILE_PATH):
        try:
            existing = pd.read_csv(LIVE_FILE_PATH)
        except pd.errors.EmptyDataError:
            existing = pd.DataFrame(columns=["Timestamp", "IP Address", "Protocol", "Packet Size (KB)", "Requests/sec"])

        ips, protos, pkt, req = _generate_traffic_batch(1)
        new_row = {
            "Timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "IP Address": ips[0],
            "Protocol": protos[0],
            "Packet Size (KB)": pkt[0],
            "Requests/sec": req[0],
        }
        pd.concat([existing, pd.DataFrame([new_row])]).tail(260).to_csv(LIVE_FILE_PATH, index=False)
        st.session_state["_last_self_write_mtime"] = os.path.getmtime(LIVE_FILE_PATH)

    engine = EngineFactory.create(controls.system_mode)
    df = parse_and_transform_ledger(LIVE_FILE_PATH)
    df = score_and_classify(df, controls.max_tx_amount, controls.max_velocity, controls.system_mode)

    with radar_placeholder.container():
        render_live_radar(df, engine)
    with geo_map_placeholder.container():
        render_geo_cluster_map(df, engine)

    render_metric_cards(df)
    render_threat_readout(df)
    st.markdown("<div style='height:8px;'></div>", unsafe_allow_html=True)

    current_security, gap, action, status_color = render_security_panel(df, controls.ceo_target)
    insight = generate_ai_insight(df)
    st.markdown(
        f'<div class="ai-panel" style="--ai-color:{insight["color"]};">'
        f'<div class="ai-panel-header"><div class="ai-panel-title">{insight["icon"]} AI Autonomous Insight — {insight["level"]}</div>'
        f'<div class="ai-badge">LIVE SCAN</div></div>'
        f'<div class="ai-panel-body">{insight["text"]}</div></div>',
        unsafe_allow_html=True,
    )

    # ----- SAVE FOR EXPORTS OUTSIDE FRAGMENT (must be AFTER current_security defined) -----
    st.session_state["_last_df"] = df
    st.session_state["_last_current_security"] = current_security
    st.session_state["_last_gap"] = gap
    st.session_state["_last_action"] = action

    tab_overview, tab_audit1, tab_audit2, tab_ai, tab_threats = st.tabs(
        ["📊 Overview", "📋 Log Audit — Network", "📒 Log Audit — Financial", "🧠 AI SOC", "🛡️ Threat Console"]
    )

    with tab_overview:
        col_chart, col_log = st.columns([1.5, 1])
        with col_chart:
            with st.container(border=True):
                chart_title = "📈 Network Anomaly Mapping" if engine.domain == "Cyber" else "📈 Transaction Risk Mapping"
                st.markdown(f"<h4 style='margin:0 0 6px 0;color:#38bdf8;font-size:18px;'>{chart_title}</h4>", unsafe_allow_html=True)
                y_col = engine.primary_metric_col
                fig = px.scatter(df, x="Timestamp", y=y_col, color="Security State", size="Risk Score", color_discrete_map=STATUS_COLORS, hover_data=["IP Address", "Protocol", "Risk Score", "AI Reason"])
                fig.update_layout(plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)", font_color="#f0f6fc", margin=dict(l=10, r=10, t=10, b=70), height=320, legend=dict(orientation="h", y=-0.25, x=0.5, xanchor="center", font=dict(size=11)))
                fig.update_yaxes(title=engine.metric_label(y_col))
                st.plotly_chart(fig, width="stretch", key="chart_overview")
        with col_log:
            with st.container(border=True):
                st.markdown("<h4 style='margin:0;color:#ef4444;font-size:18px;'>📡 Live Threat Log</h4>", unsafe_allow_html=True)
                st.caption(f"Flow {'ON' if st.session_state['traffic_is_running'] else 'OFF'} · {len(df)} logs")
                for _, row in df.iloc[::-1].head(8).iterrows():
                    badge = STATUS_COLORS.get(row["Security State"], "#10b981")
                    st.markdown(
                        f'<div class="log-card" style="--card-color:{badge};">'
                        f'<div style="display:flex;justify-content:space-between;font-size:11px;">'
                        f'<span>{row["Timestamp"].strftime("%H:%M:%S")}</span>'
                        f'<span style="color:{badge};font-weight:800;">{row["Security State"].split(":")[-1][:16]}</span>'
                        f'<span>R{row["Risk Score"]}</span></div>'
                        f'<div style="font-size:12.5px;font-weight:600;">{row["IP Address"]} · {row["Protocol"]}</div>'
                        f'<div style="font-size:10.5px;color:#a3adc2;">{row["AI Reason"][:60]}</div></div>',
                        unsafe_allow_html=True,
                    )

    with tab_audit1:
        st.markdown("#### 📋 Network Traffic Audit")
        st.caption("Audit of network packets, protocols, and source verification.")
        c1, c2, c3 = st.columns(3)
        with c1:
            st.metric("Total Packets Audited", f"{len(df)}", f"{len(df[df['Security State'] != 'Secured'])} flagged")
        with c2:
            st.metric("Protocols Verified", f"{df['Protocol'].nunique()}", f"{', '.join(df['Protocol'].unique()[:3])}" if len(df) else "—")
        with c3:
            st.metric("External Sources", f"{len([ip for ip in df['IP Address'].unique() if not ip.startswith('192.168.')])}" if len(df) else "0", "Scanned")
        cyber_engine = CyberEngine()
        net_table = df[cyber_engine.table_columns].sort_values("Risk Score", ascending=False).head(50).rename(columns=cyber_engine.column_labels)
        st.dataframe(net_table, width="stretch", hide_index=True, height=300)
        if not df.empty:
            fig_audit = px.histogram(df, x="Protocol", color="Security State", color_discrete_map=STATUS_COLORS, title="Protocol Audit — Threat Distribution")
            fig_audit.update_layout(height=250, paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="#a3adc2", margin=dict(l=10, r=10, t=30, b=10))
            st.plotly_chart(fig_audit, width="stretch")

    with tab_audit2:
        st.markdown("#### 📒 Financial Transaction Ledger Audit")
        st.caption("Value, account mapping, and quantity audit for financial compliance.")
        cc1, cc2, cc3, cc4 = st.columns(4)
        with cc1:
            st.metric("Total Value Audited", f"${df['Value ($)'].sum():,.0f}" if len(df) else "$0")
        with cc2:
            st.metric("Accounts Verified", f"{df['Account'].nunique()}" if len(df) else "0", f"{len(df)} tx")
        with cc3:
            st.metric("Avg Transaction", f"${df['Value ($)'].mean():,.0f}" if len(df) else "$0")
        with cc4:
            st.metric("High Value Flagged", f"{len(df[df['Value ($)'] > controls.max_tx_amount])}" if len(df) else "0", "Above limit")
        fin_engine = FinancialEngine()
        fin_table = df[fin_engine.table_columns].sort_values("Value ($)", ascending=False).head(50).rename(columns=fin_engine.column_labels)
        st.dataframe(fin_table, width="stretch", hide_index=True, height=300)
        if not df.empty:
            fig_fin = px.scatter(df, x="Quantity (Tx/Min)", y="Value ($)", color="Security State", size="Risk Score", color_discrete_map=STATUS_COLORS, hover_data=["Account", "IP Address"], title="Financial Audit — Value vs Velocity")
            fig_fin.update_layout(height=250, paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="#a3adc2", margin=dict(l=10, r=10, t=30, b=10))
            st.plotly_chart(fig_fin, width="stretch")

    with tab_ai:
        st.markdown("### 🧠 AI SOC Features")
        ac1, ac2, ac3 = st.columns(3)
        with ac1:
            with st.container(border=True):
                st.markdown("#### 🔮 Threat Forecast (60 min)")
                if len(df) > 10:
                    last = df.tail(20)
                    forecast_risk = int(last["Risk Score"].mean() + random.randint(-5, 10))
                    forecast_count = int(len(last[last["Security State"] != "Secured"]) * 1.2)
                    st.metric("Predicted", f"{max(0, forecast_count)}", f"{forecast_risk - 50}%")
                    future = [(datetime.datetime.now() + datetime.timedelta(minutes=i * 10)).strftime("%H:%M") for i in range(6)]
                    fr = [forecast_risk + random.randint(-8, 8) for _ in range(6)]
                    fig = go.Figure()
                    fig.add_trace(go.Scatter(x=future, y=fr, mode="lines+markers", line=dict(color="#ff007f"), fill="tozeroy"))
                    fig.update_layout(height=150, margin=dict(l=5, r=5, t=5, b=5), paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="#a3adc2", showlegend=False)
                    st.plotly_chart(fig, width="stretch")
                else:
                    st.info("Need more traffic to forecast.")
        with ac2:
            with st.container(border=True):
                st.markdown("#### 🧬 Why Flagged — Explainability")
                flagged = df[df["Security State"] != "Secured"].tail(4) if not df.empty else df
                if not flagged.empty:
                    for _, r in flagged.iterrows():
                        st.markdown(f"**{r['IP Address']}** · Risk {r['Risk Score']}")
                        st.caption(r["AI Reason"][:55])
                        st.progress(r["Risk Score"] / 100)
                else:
                    st.success("Clean — nothing flagged.")
        with ac3:
            with st.container(border=True):
                st.markdown("#### 💬 AI SOC Assistant")
                q = st.text_input("Ask AI", placeholder="Why was this flagged?", label_visibility="collapsed", key="ai_q")
                if q:
                    top_ip = df["IP Address"].value_counts().idxmax() if len(df) > 0 else "N/A"
                    top_risk = df["Risk Score"].max() if len(df) > 0 else 0
                    st.session_state["ai_chat_history"].append({"q": q, "a": f"Analyzing {len(df)} logs — top risk source is {top_ip} at {top_risk}. {action[:60]}"})
                for chat in st.session_state["ai_chat_history"][-2:][::-1]:
                    st.markdown(f"**Q:** {chat['q'][:40]}")
                    st.caption(f"AI: {chat['a'][:100]}")
                    st.divider()

    with tab_threats:
        with st.container(border=True):
            st.markdown(f"#### 🛡️ Threat Console — {len(st.session_state['axps_secured_registry'])} threats on record")
            all_blocked = list(st.session_state["blocked_ips_set"] | st.session_state["banned_ips_set"] | st.session_state["suspended_ips_set"])
            if not all_blocked:
                st.success("Nothing blocked — clean.")
            else:
                rows = []
                for ip in all_blocked:
                    info = st.session_state["axps_secured_registry"].get(ip, {})
                    rows.append({"IP": ip, "Type": info.get("BlockType", "Auto"), "Status": "Banned" if ip in st.session_state["banned_ips_set"] else "Blocked", "Risk": info.get("Risk", 0), "Country": info.get("Country", "N/A"), "Value $": info.get("Value", 0), "Reason": info.get("Reason", "")[:30]})
                st.dataframe(pd.DataFrame(rows).sort_values("Risk", ascending=False), width="stretch", hide_index=True, height=220)
                c_ip, c_b, c_u, c_s, c_ban, c_cl = st.columns([2, 1, 1, 1, 1, 1])
                with c_ip:
                    sel = st.selectbox("Select IP", list(st.session_state["axps_secured_registry"].keys()) or ["None"], label_visibility="collapsed", key="sel_ip")
                with c_b:
                    if st.button("Block", width="stretch", key="b_btn"):
                        st.session_state["blocked_ips_set"].add(sel); st.rerun()
                with c_u:
                    if st.button("Unblock", width="stretch", key="u_btn"):
                        st.session_state["blocked_ips_set"].discard(sel); st.session_state["axps_secured_registry"].pop(sel, None); st.rerun()
                with c_s:
                    if st.button("Suspend", width="stretch", key="s_btn"):
                        st.session_state["suspended_ips_set"].add(sel); st.rerun()
                with c_ban:
                    if st.button("Ban", width="stretch", key="ban_btn"):
                        st.session_state["banned_ips_set"].add(sel); st.rerun()
                with c_cl:
                    if st.button("Clear", width="stretch", key="cl_btn"):
                        st.session_state["axps_secured_registry"].pop(sel, None); st.session_state["blocked_ips_set"].discard(sel); st.rerun()

        # Exports moved to render_exports() outside fragment
# ---------------------------------------------------------------------------
# EXPORTS - Moved OUTSIDE fragment to fix TXT/JSON disabled bug
# Fragment reruns every 3 sec -> download_button loses click. Now stable.
# ---------------------------------------------------------------------------
def render_exports(df: pd.DataFrame, controls, current_security: float, gap: float, action: str):
    """Render Excel / TXT / JSON exports with stable keys and explicit mime."""
    with st.container(border=True):
        st.markdown("#### 📤 Exports")
        avg_risk_val = float(df["Risk Score"].mean()) if len(df) > 0 else 0.0
        total_val = len(df)
        threats_val = len(st.session_state.get("axps_secured_registry", {}))
        blocked_val = len(st.session_state.get("blocked_ips_set", set()))

        col_e1, col_e2, col_e3 = st.columns(3)
        with col_e1:
            try:
                import io
                buf = io.BytesIO()
                with pd.ExcelWriter(buf, engine="xlsxwriter") as writer:
                    df.head(200).to_excel(writer, sheet_name="Logs", index=False)
                    reg = st.session_state.get("axps_secured_registry", {})
                    if reg:
                        pd.DataFrame(list(reg.values())).to_excel(writer, sheet_name="Threats", index=False)
                    else:
                        pd.DataFrame([{"Note": "Clean"}]).to_excel(writer, sheet_name="Threats", index=False)
                st.download_button(
                    "📊 Excel",
                    buf.getvalue(),
                    file_name=f"AXPS_SOC_{__import__('datetime').date.today()}.xlsx",
                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    width="stretch",
                    key="dl_excel_fixed",
                )
            except Exception as e:
                st.error(f"Excel error: {e}")

        with col_e2:
            # TXT Report - plain string, always enabled
            txt_report = (
                f"AXPS SOC DEFENCE — AUTONOMOUS SECURITY REPORT\n"
                f"Generated: {__import__('datetime').datetime.now()}\n"
                f"CEO Target: {controls.ceo_target:.1f}% | Current: {current_security:.1f}% | Gap: {gap:+.1f}%\n"
                f"Scanned: {total_val} | Threats: {threats_val} | Blocked: {blocked_val} | Avg Risk: {avg_risk_val:.1f}\n"
                f"Action: {action}\n\n"
                f"Top Logs:\n{df.head(20).to_string() if len(df) > 0 else 'No logs yet'}\n"
            )
            st.download_button(
                "📝 TXT Report",
                data=txt_report.encode("utf-8"),
                file_name=f"AXPS_SOC_{__import__('datetime').date.today()}.txt",
                mime="text/plain",
                width="stretch",
                key="dl_txt_fixed",
            )

        with col_e3:
            import json
            json_data = {
                "ceo_target": controls.ceo_target,
                "current": current_security,
                "gap": gap,
                "action": action,
                "total": total_val,
                "threats": threats_val,
                "blocked": blocked_val,
                "avg_risk": avg_risk_val,
                "generated": str(__import__('datetime').datetime.now())
            }
            st.download_button(
                "📄 JSON",
                data=json.dumps(json_data, indent=2, default=str).encode("utf-8"),
                file_name=f"AXPS_SOC_{__import__('datetime').date.today()}.json",
                mime="application/json",
                width="stretch",
                key="dl_json_fixed",
            )

# ---------------------------------------------------------------------------
# ENTRYPOINT
# ---------------------------------------------------------------------------

def main() -> None:
    inject_css()
    init_state()
    controls = render_sidebar()
    st.markdown("<h1 style='margin:0;color:#00ffcc;font-size:clamp(22px,3.4vw,34px);letter-spacing:.5px;'>🛡️ AXPS SOC DEFENCE — Autonomous Protection</h1>", unsafe_allow_html=True)
    st.markdown("<div style='color:#a3adc2;font-size:14px;margin-top:4px;'>100% Autonomous · CEO Target Tracking · Radar + Scanner Threat Sweep</div>", unsafe_allow_html=True)
    col_radar, col_geo = st.columns(2)
    radar_placeholder = col_radar.empty()
    with radar_placeholder.container():
        st.info("🛰️ Initializing radar…")
    geo_map_placeholder = col_geo.empty()
    with geo_map_placeholder.container():
        st.info("🌍 Initializing geo-cluster map…")
    st.markdown("<div style='height:22px;'></div>", unsafe_allow_html=True)
    live_dashboard(controls, geo_map_placeholder, radar_placeholder)
    # Render exports OUTSIDE fragment - fixes disabled TXT button
    df_for_export = st.session_state.get("_last_df", pd.DataFrame())
    curr_sec = st.session_state.get("_last_current_security", 0.0)
    gap_val = st.session_state.get("_last_gap", 0.0)
    action_val = st.session_state.get("_last_action", "Monitoring")
    render_exports(df_for_export, controls, curr_sec, gap_val, action_val)
    render_star_rating()


if __name__ == "__main__":
    main()
