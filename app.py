from __future__ import annotations
import datetime, io, os, time, json, csv
from dataclasses import dataclass
import numpy as np
import pandas as pd
import plotly.express as px
import requests
import streamlit as st
from sklearn.ensemble import IsolationForest

st.html('<head><meta name="google-site-verification" content="F_e_RoVbDiO3ilDO3" /></head>')
st.set_page_config(page_title="AXPS Inspector", page_icon="🛡", layout="wide", initial_sidebar_state="expanded")
LIVE_FILE_PATH = "live_network_logs.csv"
FEEDBACK_CSV = "feedback_log.csv"
GOOGLE_FORM_URL = "https://docs.google.com/forms/d/e/1FAIpQLScs8sK9BMGPe-aiXoCvs0B367u0nu8xr-v7llGXnnzCkjDU_g/viewform?usp=dialog"
STATUS_COLORS = {"Secured":"#10b981","ALERT: High Risk Data Pattern":"#f59e0b","ATTENTION: Limit Exceeded":"#ef4444","UNSECURED: Blocked IP Source":"#a855f7"}

def inject_css():
    st.markdown("""
    <style>
    :root{--bg:#040612;--border:#1e293b;--cyan:#00ffcc;--muted:#94a3b8;}
    [data-testid="stAppViewContainer"]{background:var(--bg)!important;}
    [data-testid="stHeader"]{background:transparent!important;height:2.5rem!important;}
    .block-container{padding-top:0.5rem!important;max-width:100%!important;}
    /* SIDEBAR FIX - NO CRASH WHEN SHRINK */
    section[data-testid="stSidebar"]{background:#070919!important;border-right:1px solid var(--border)!important;}
    section[data-testid="stSidebar"] > div{padding-top:0.5rem!important;}
    .metric-card{border-radius:12px;padding:14px 16px;border:1.5px solid var(--card-color);border-top:5px solid var(--card-color);background:linear-gradient(135deg,color-mix(in srgb,var(--card-color) 14%,#030612) 0%,#030612 100%);height:110px;display:flex;flex-direction:column;justify-content:space-between;}
    .metric-label{color:var(--muted);font-size:10.5px;text-transform:uppercase;font-weight:700;letter-spacing:1px;min-height:26px;display:flex;align-items:flex-start;line-height:1.3;}
    .metric-value{font-size:30px;font-weight:800;color:var(--card-color);line-height:1;}
    .ai-panel{border-radius:12px;padding:0;border:1px solid var(--border);border-left:6px solid var(--ai-color);background:linear-gradient(135deg, color-mix(in srgb, var(--ai-color) 18%, #0a0a18) 0%, #060312 100%);margin:12px 0 16px 0;overflow:hidden;}
    .ai-panel-header{display:flex;align-items:center;justify-content:space-between;padding:9px 14px;background: color-mix(in srgb, var(--ai-color) 14%, transparent);}
    .ai-panel-title{color:var(--ai-color);font-weight:800;font-size:12.5px;letter-spacing:0.8px;text-transform:uppercase;}
    .ai-badge{padding:3px 10px;border-radius:20px;font-size:11px;font-weight:800;color:#000;background:var(--ai-color);}
    .ai-panel-body{color:#f1f5f9;font-size:14px;line-height:1.6;padding:12px 14px;}
    .log-card{border-radius:8px;padding:10px 14px;margin-bottom:8px;border:1px solid var(--card-color);border-left:5px solid var(--card-color);background:linear-gradient(135deg,color-mix(in srgb,var(--card-color) 14%,#060314) 0%,#030108 100%);}
    </style>
    """, unsafe_allow_html=True)

def init_state():
    for k,v in {"axps_secured_registry":{},"traffic_is_running":True,"blocked_ips_set":set(),"suspended_ips_set":set(),"banned_ips_set":set(),"manual_blocked":set(),"auto_blocked":set(),"star_rating":0,"feedback_submitted":False}.items():
        st.session_state.setdefault(k,v)

@st.cache_data(ttl=3600, show_spinner=False)
def fetch_ip_meta(ip):
    if ip.startswith(("192.168.","10.","127.")): return {"country":"Local","org":"AXPS Lab","email":f"admin@{ip}.internal"}
    try:
        r=requests.get(f"http://ip-api.com/json/{ip}?fields=country,org,status",timeout=1.5)
        if r.status_code==200 and r.json().get("status")=="success":
            org=r.json().get("org","Unknown"); return {"country":r.json().get("country","Unknown"),"org":org,"email":f"abuse@{org.split()[0].lower()}.com"}
    except: pass
    return {"country":"Unknown","org":"Dynamic ISP","email":"abuse@ip-route.net"}

def populate_default_live_csv(path, clean=False):
    np.random.seed(int(time.time())%10000)
    ts=[(datetime.datetime.now()-datetime.timedelta(seconds=i*12)).strftime("%Y-%m-%d %H:%M:%S") for i in range(120)][::-1]
    if clean:
        ips=[f"192.168.1.{np.random.randint(10,50)}" for _ in range(120)]; protos=["HTTPS"]*120; pkt=np.full(120,500.0); req=np.full(120,12.0)
    else:
        pool=["8.8.8.8","1.1.1.1","104.244.42.1","140.82.112.4","192.168.1.99","103.255.4.12","172.16.0.5"]
        ips=[np.random.choice(pool) if np.random.rand()>0.5 else f"10.0.0.{np.random.randint(1,254)}" for _ in range(120)]
        protos=np.random.choice(["TCP","UDP","HTTP","HTTPS"],size=120); pkt=np.random.uniform(80,4800,size=120); req=np.random.uniform(5,450,size=120)
    pd.DataFrame({"Timestamp":ts,"IP Address":ips,"Protocol":protos,"Packet Size (KB)":pkt,"Requests/sec":req}).to_csv(path,index=False)
    st.session_state["_last_self_write_mtime"]=os.path.getmtime(path)

def is_externally_fed(p):
    if not os.path.exists(p): return False
    cur=os.path.getmtime(p); last=st.session_state.get("_last_self_write_mtime")
    if last is None: return (time.time()-cur)<8
    return cur!=last

def parse_and_transform_ledger(p,max_rows=200):
    if not os.path.exists(p): populate_default_live_csv(p,clean=False)
    raw=pd.read_csv(p)
    if raw.empty: populate_default_live_csv(p,clean=False); raw=pd.read_csv(p)
    if len(raw)>max_rows: raw=raw.tail(max_rows).reset_index(drop=True)
    df=pd.DataFrame()
    df["Timestamp"]=pd.to_datetime(raw["Timestamp"]); df["IP Address"]=raw["IP Address"]; df["Protocol"]=raw["Protocol"]
    df["Packet Size (KB)"]=raw["Packet Size (KB)"].round(2); df["Requests/sec"]=raw["Requests/sec"].round(1)
    ip_to_acc={ip:f"ACC-{np.random.randint(10000,99999)}" for ip in raw["IP Address"].unique()}
    df["Account"]=raw["IP Address"].map(ip_to_acc); df["Value ($)"]=(raw["Packet Size (KB)"]*5.5).round(2)
    df["Quantity (Tx/Min)"]=(raw["Requests/sec"]/10).round(1)
    df["Quality Segment"]=raw["Protocol"].map({"TCP":"WIRE TRANSFER","UDP":"ATM WITHDRAWAL","HTTP":"MERCHANT CHARGE","HTTPS":"ONLINE TRANSFER"}).fillna("ONLINE TRANSFER")
    return df

def score_and_classify(df,max_tx,max_vel,mode):
    if df.empty or len(df)<2: df["Security State"]="Secured"; return df
    is_zero=len(st.session_state["blocked_ips_set"])==0 and len(st.session_state["axps_secured_registry"])==0 and df["Packet Size (KB)"].nunique()==1
    if is_zero: df["Security State"]="Secured"; return df
    df=df.sort_values("Timestamp").reset_index(drop=True)
    clf=IsolationForest(contamination=0.06,random_state=42)
    df["Anomaly_Score"]=clf.fit_predict(df[["Value ($)","Quantity (Tx/Min)"]])
    states=[]
    for _,row in df.iterrows():
        ip=row["IP Address"]
        if ip in st.session_state["banned_ips_set"] or ip in st.session_state["blocked_ips_set"] or ip in st.session_state["suspended_ips_set"]:
            states.append("UNSECURED: Blocked IP Source"); continue
        over=row["Value ($)"]>max_tx; high=row["Quantity (Tx/Min)"]>max_vel
        if over or high:
            states.append("ATTENTION: Limit Exceeded")
            geo=fetch_ip_meta(ip)
            st.session_state["axps_secured_registry"][ip]={"Account":row["Account"],"Timestamp":row["Timestamp"].strftime("%H:%M:%S"),"Reason":f"{'Packet '+str(row['Packet Size (KB)'])+' KB' if over else ''} {'Rate '+str(row['Requests/sec'])+' req/s' if high else ''}".strip(),"Action":"Isolate","Domain":"Cyber" if mode.startswith("🌐") else "Financial","Section":"Art.14","Country":geo["country"],"ISP":geo["org"],"Email":geo["email"],"Status":"Blocked","BlockType":"Auto"}
            st.session_state["blocked_ips_set"].add(ip); st.session_state["auto_blocked"].add(ip)
        elif row.get("Anomaly_Score")==-1: states.append("ALERT: High Risk Data Pattern")
        else: states.append("Secured")
    df["Security State"]=states; return df

def generate_ai_insight_colored(df):
    if df.empty: return {"text":"Waiting for logs...","level":"LOADING","color":"#94a3b8","icon":"⏳"}
    total=len(df); flagged=df[df["Security State"]!="Secured"]; n=len(flagged)
    if n==0: return {"text":f"All {total} entities nominal. System compliant and secure.","level":"NORMAL","color":"#10b981","icon":"🟢"}
    rate=n/total*100; top_ip=flagged["IP Address"].value_counts().idxmax() if n>0 else "N/A"; hits=int(flagged["IP Address"].value_counts().max()) if n>0 else 0
    top_state=flagged["Security State"].value_counts().idxmax()
    if rate<10: return {"text":f"Elevated risk - {n}/{total} ({rate:.1f}%) as {top_state.split(':')[-1].strip()}. Top {top_ip} ({hits}).","level":"ELEVATED","color":"#f59e0b","icon":"🟡"}
    elif rate<25: return {"text":f"Danger - {n}/{total} ({rate:.1f}%) isolated. {top_state.split(':')[-1].strip()} from {top_ip}.","level":"DANGER","color":"#ef4444","icon":"🔴"}
    else: return {"text":f"CRITICAL - {n}/{total} ({rate:.1f}%) compromised. {top_ip} aggressive ({hits}).","level":"CRITICAL","color":"#a855f7","icon":"🟣"}

@dataclass
class Controls:
    system_mode:str; max_tx_amount:int; max_velocity:int

def render_sidebar():
    st.sidebar.markdown("<h2 style='color:#00ffcc;font-weight:800;margin:0;'>🛡️ AXPS INSPECTOR</h2>",unsafe_allow_html=True)
    st.sidebar.caption("Cyber & Financial Security Console v4.8")
    st.sidebar.divider()
    system_mode=st.sidebar.radio("Inspector Mode",["🌐 Cyber Network Traffic Inspector","🔒 Financial Data Security Ledger"],index=0)
    st.sidebar.divider()
    st.sidebar.markdown("### ⚙️ Operations Control")
    traffic_status=st.sidebar.selectbox("📡 Live Traffic Engine",["🟢 Traffic: ON (Running)","🔴 Traffic: OFF (Paused)"],index=0 if st.session_state["traffic_is_running"] else 1)
    st.session_state["traffic_is_running"]=traffic_status.startswith("🟢")
    if st.sidebar.button("⚡ Fetch Latest Cyber Logs", width='stretch'):
        if st.session_state["traffic_is_running"]: st.sidebar.warning("Pause traffic first.")
        else:
            with st.spinner("Fetching..."): populate_default_live_csv(LIVE_FILE_PATH,clean=False); time.sleep(0.5)
            st.toast("Live logs loaded",icon="✅"); st.rerun()
    if st.sidebar.button("🔄 Reset System State - Set 0 All", type="primary", width='stretch'):
        st.session_state["axps_secured_registry"]={}; st.session_state["blocked_ips_set"]=set(); st.session_state["suspended_ips_set"]=set(); st.session_state["banned_ips_set"]=set(); st.session_state["manual_blocked"]=set(); st.session_state["auto_blocked"]=set()
        fetch_ip_meta.clear()
        if os.path.exists(LIVE_FILE_PATH): os.remove(LIVE_FILE_PATH)
        populate_default_live_csv(LIVE_FILE_PATH,clean=True)
        st.toast("Hard-reset to 0",icon="✅"); time.sleep(0.3); st.rerun()
    st.sidebar.divider()
    st.sidebar.markdown("### 🚦 Thresholds")
    max_tx=st.sidebar.slider("Max Transaction Limit",1000,25000,15000,1000)
    max_vel=st.sidebar.slider("Max Velocity (Req/Min)",5,50,20,5)
    st.sidebar.divider()
    st.sidebar.markdown("### 🛡️ Blocked IPs Control")
    new_ip=st.sidebar.text_input("Enter IP to Block", placeholder="103.255.4.12", key="block_ip_input_main")
    c1,c2=st.sidebar.columns(2)
    with c1:
        if st.button("🚫 Block", width='stretch', key="btn_block_main"):
            if new_ip:
                ip_clean=new_ip.strip()
                st.session_state["blocked_ips_set"].add(ip_clean); st.session_state["manual_blocked"].add(ip_clean)
                st.session_state["axps_secured_registry"][ip_clean]={"Account":"MANUAL","Timestamp":datetime.datetime.now().strftime("%H:%M:%S"),"Reason":"Manual Block","Action":"Block","Domain":"Cyber","Section":"Art.14","Country":"Manual","ISP":"Manual","Email":"security@axps.local","Status":"Blocked","BlockType":"Manual"}
                st.toast(f"{ip_clean} Manual Blocked"); st.rerun()
    with c2:
        if st.button("♻️ Unblock", width='stretch', key="btn_unblock_main"):
            if new_ip:
                ip_clean=new_ip.strip()
                st.session_state["blocked_ips_set"].discard(ip_clean); st.session_state["manual_blocked"].discard(ip_clean); st.session_state["auto_blocked"].discard(ip_clean); st.session_state["axps_secured_registry"].pop(ip_clean,None); st.rerun()
    st.sidebar.info(f"Manual: {len(st.session_state['manual_blocked'])} | Auto: {len(st.session_state['auto_blocked'])} | Total: {len(st.session_state['blocked_ips_set']|st.session_state['banned_ips_set'])}")
    return Controls(system_mode,max_tx,max_vel)

def render_header():
    st.markdown(f"<h1 style='margin:0;color:#00ffcc;font-size:34px;'>AXPS INSPECTOR</h1>",unsafe_allow_html=True)
    st.caption("Unified cyber traffic & financial transaction security monitoring - v4.8")

def render_metric_cards(df):
    anomalies=df[df["Security State"]!="Secured"]
    cards=[("📊 SCANNED LOG ENTITIES",len(df),"#00f2fe"),("⚠ ANOMALIES ISOLATED",len(anomalies),"#ff007f"),("🛑 BLOCKED IP SOURCES",len(st.session_state["blocked_ips_set"]|st.session_state["banned_ips_set"]|st.session_state["suspended_ips_set"]),"#f59e0b"),("⚖ TREATY DIRECTIVES (ICCCL)",len(st.session_state["axps_secured_registry"]),"#a855f7")]
    cols=st.columns(4)
    for col,(label,value,color) in zip(cols,cards):
        with col: st.markdown(f'<div class="metric-card" style="--card-color:{color};"><div class="metric-label">{label}</div><div class="metric-value">{value}</div></div>',unsafe_allow_html=True)

def render_chart(df,mode):
    is_cyber=mode.startswith("🌐"); y_col,size_col=("Requests/sec","Packet Size (KB)") if is_cyber else ("Value ($)","Quantity (Tx/Min)"); hover=["IP Address","Protocol"] if is_cyber else ["Account","Quality Segment"]
    fig=px.scatter(df,x="Timestamp",y=y_col,color="Security State",size=size_col,color_discrete_map=STATUS_COLORS,hover_data=hover)
    fig.update_layout(plot_bgcolor="rgba(0,0,0,0)",paper_bgcolor="rgba(0,0,0,0)",font_color="#f0f6fc",margin=dict(l=10,r=10,t=10,b=120),height=400,uirevision="keep-zoom",legend=dict(orientation="h",yanchor="bottom",y=-0.35,xanchor="center",x=0.5,bgcolor="rgba(10,14,36,0.9)",bordercolor="#1e293b",borderwidth=1,font=dict(size=11, color="#f1f5f9"),title_text="Security State"),xaxis=dict(title="Timestamp", showgrid=True, gridcolor="#1e293b"),yaxis=dict(showgrid=True, gridcolor="#1e293b"))
    return fig

def render_live_log(df,mode):
    if df.empty: st.info("No data."); return
    is_cyber=mode.startswith("🌐"); card_color="#ff007f" if is_cyber else "#00ffcc"
    for _,row in df.iloc[::-1].head(12).iterrows():
        badge=STATUS_COLORS.get(row["Security State"],"#10b981")
        identity=f"Src IP: <code style='color:#38bdf8;'>{row['IP Address']}</code> ➔ {row['Protocol']}" if is_cyber else f"Account: <code style='color:#38bdf8;'>{row['Account']}</code>"
        metric=f"Packet: <strong>{row['Packet Size (KB)']:,} KB</strong> | Rate: <strong>{row['Requests/sec']:.0f}</strong>" if is_cyber else f"Amt: <strong>${row['Value ($)']:,}</strong>"
        st.markdown(f'<div class="log-card" style="--card-color:{card_color};"><div style="display:flex;justify-content:space-between;font-size:10px;"><span style="color:#94a3b8;">{row["Timestamp"].strftime("%H:%M:%S")}</span><span style="color:{badge};font-weight:bold;">{row["Security State"]}</span></div><div style="font-size:13px;margin-top:4px;font-weight:700;">{identity}</div><div style="font-size:11px;color:#e2e8f0;">{metric}</div></div>',unsafe_allow_html=True)

def render_blocked_ips_table_main():
    with st.container(border=True):
        st.markdown("<h3 style='color:#f59e0b;margin:0 0 10px 0;'>🛡️ Blocked IPs Management - Manual & Auto</h3>",unsafe_allow_html=True)
        all_blocked = list(st.session_state["blocked_ips_set"]|st.session_state["banned_ips_set"]|st.session_state["suspended_ips_set"])
        if not all_blocked:
            st.success("🟢 No blocked IPs - System clean at 0")
            return
        rows=[]
        for ip in all_blocked:
            info = st.session_state["axps_secured_registry"].get(ip, {})
            block_type = info.get("BlockType","Manual" if ip in st.session_state["manual_blocked"] else "Auto")
            status="Banned" if ip in st.session_state["banned_ips_set"] else "Suspended" if ip in st.session_state["suspended_ips_set"] else "Blocked"
            domain = info.get("Domain","Cyber")
            rows.append({"IP Address":ip,"Block Type":block_type,"Status":status,"Domain":domain,"Account":info.get("Account","N/A"),"Reason":info.get("Reason","Manual Block")[:40],"Timestamp":info.get("Timestamp","N/A")})
        df_blocked = pd.DataFrame(rows)
        c1,c2,c3 = st.columns(3)
        with c1: filter_type = st.selectbox("Filter by Block Type", ["All","Manual","Auto"], key="f_type")
        with c2: filter_status = st.selectbox("Filter by Status", ["All","Blocked","Suspended","Banned"], key="f_status")
        with c3: filter_domain = st.selectbox("Filter by Inspector Mode", ["All","Cyber","Financial"], key="f_domain")
        if filter_type!="All": df_blocked = df_blocked[df_blocked["Block Type"]==filter_type]
        if filter_status!="All": df_blocked = df_blocked[df_blocked["Status"]==filter_status]
        if filter_domain!="All": df_blocked = df_blocked[df_blocked["Domain"]==filter_domain]
        st.dataframe(df_blocked, width='stretch', hide_index=True)
        st.caption(f"Showing {len(df_blocked)} of {len(all_blocked)} blocked IPs | Manual: {len(st.session_state['manual_blocked'])} | Auto: {len(st.session_state['auto_blocked'])}")

def render_registry_and_exports(df,mode):
    current_domain="Cyber" if mode.startswith("🌐") else "Financial"
    with st.container(border=True):
        col_title,col_btns = st.columns([5,3])
        with col_title:
            st.markdown(f'<h3 style="color:#00ffcc;margin:0;">🛡️ Legal Action & Threat Enforcement Console</h3>',unsafe_allow_html=True)
            st.caption(f"Domain: {current_domain} | Total threats: {len(st.session_state['axps_secured_registry'])}")
        with col_btns:
            export_df = df.copy()
            threats_list=[]
            for ip,info in st.session_state["axps_secured_registry"].items():
                threats_list.append({"Threat_IP":ip,"Account":info.get("Account"),"Reason":info.get("Reason"),"Country":info.get("Country"),"Status":info.get("Status","Blocked"),"BlockType":info.get("BlockType","Auto"),"Timestamp":info.get("Timestamp")})
            threats_df = pd.DataFrame(threats_list) if threats_list else pd.DataFrame([{"Note":"No threats"}])
            buf_xlsx = io.BytesIO()
            try:
                with pd.ExcelWriter(buf_xlsx, engine="xlsxwriter") as writer:
                    export_df.to_excel(writer, sheet_name="Network_Logs", index=False)
                    threats_df.to_excel(writer, sheet_name="Threat_Registry", index=False)
                xlsx_data = buf_xlsx.getvalue(); xlsx_ok=True
            except: xlsx_data=b""; xlsx_ok=False
            json_data={"summary":{"total_scanned":len(df),"threats":len(st.session_state["axps_secured_registry"]),"blocked":len(st.session_state["blocked_ips_set"])},"logs":export_df.head(100).to_dict(orient="records"),"threat_registry":threats_list}
            json_str=json.dumps(json_data, indent=2, default=str)
            txt_report=f"""AXPS COMPLIANCE REPORT
Generated: {datetime.datetime.now()}
Mode: {current_domain}
Scanned: {len(df)} | Threats: {len(st.session_state['axps_secured_registry'])} | Blocked: {len(st.session_state['blocked_ips_set'])}
{export_df.head(20).to_string()}
{threats_df.to_string()}
"""
            b1,b2,b3 = st.columns(3)
            with b1:
                if xlsx_ok: st.download_button("📊 Excel", xlsx_data, file_name=f"AXPS_{datetime.date.today()}.xlsx", width='stretch')
            with b2: st.download_button("📄 JSON", json_str, file_name=f"AXPS_{datetime.date.today()}.json", width='stretch')
            with b3: st.download_button("📝 TXT", txt_report, file_name=f"AXPS_{datetime.date.today()}.txt", width='stretch')
        registry=st.session_state["axps_secured_registry"]
        visible={ip:info for ip,info in registry.items() if True}
        if not visible:
            st.success(f"🟢 No discovered {current_domain.lower()} threats — system compliant at 0.")
            return
        rows=[]
        for ip,info in visible.items():
            status=info.get("Status","Blocked")
            if ip in st.session_state["banned_ips_set"]: status="Banned"
            elif ip in st.session_state["suspended_ips_set"]: status="Suspended"
            elif ip in st.session_state["blocked_ips_set"]: status="Blocked"
            rows.append({"IP":ip,"Account":info.get("Account","N/A"),"Reason":info.get("Reason","N/A")[:45],"Block Type":info.get("BlockType","Auto"),"Status":status})
        st.dataframe(pd.DataFrame(rows), width='stretch', hide_index=True)
        st.markdown("**Take Action:**")
        c_ip,c_block,c_unblock,c_suspend,c_ban,c_clear = st.columns([3,1,1,1,1,1])
        with c_ip: selected_ip=st.selectbox("Select IP", list(visible.keys()), label_visibility="collapsed", key="select_ip_action_main")
        with c_block:
            if st.button("🚫 Block", width='stretch', key="act_block_main"):
                st.session_state["blocked_ips_set"].add(selected_ip); st.session_state["suspended_ips_set"].discard(selected_ip); st.session_state["banned_ips_set"].discard(selected_ip); st.session_state["manual_blocked"].add(selected_ip); st.toast(f"{selected_ip} Blocked"); st.rerun()
        with c_unblock:
            if st.button("✅ Unblock", width='stretch', key="act_unblock_main"):
                st.session_state["blocked_ips_set"].discard(selected_ip); st.session_state["suspended_ips_set"].discard(selected_ip); st.session_state["banned_ips_set"].discard(selected_ip); st.session_state["manual_blocked"].discard(selected_ip); st.session_state["auto_blocked"].discard(selected_ip); st.session_state["axps_secured_registry"].pop(selected_ip,None); st.toast(f"{selected_ip} Unblocked"); st.rerun()
        with c_suspend:
            if st.button("⏸️ Suspend", width='stretch', key="act_suspend_main"):
                st.session_state["suspended_ips_set"].add(selected_ip); st.session_state["blocked_ips_set"].discard(selected_ip); st.toast(f"{selected_ip} Suspended"); st.rerun()
        with c_ban:
            if st.button("⛔ Ban", width='stretch', key="act_ban_main"):
                st.session_state["banned_ips_set"].add(selected_ip); st.session_state["blocked_ips_set"].discard(selected_ip); st.toast(f"{selected_ip} Banned"); st.rerun()
        with c_clear:
            if st.button("🗑️ Clear", width='stretch', key="act_clear_main"):
                st.session_state["axps_secured_registry"].pop(selected_ip,None); st.session_state["blocked_ips_set"].discard(selected_ip); st.session_state["suspended_ips_set"].discard(selected_ip); st.session_state["banned_ips_set"].discard(selected_ip); st.session_state["manual_blocked"].discard(selected_ip); st.session_state["auto_blocked"].discard(selected_ip); st.toast(f"Cleared {selected_ip}"); st.rerun()

@st.dialog("✨ Help Us Improve AXPS - Feedback")
def open_feedback_dialog():
    st.markdown("### Thanks for exploring AXPS Inspector 🌸")
    st.markdown("Please fill 2-minute survey:")
    st.link_button("📝 Open Evaluation Form - Google Survey", GOOGLE_FORM_URL, width='stretch', type="primary")
    st.divider()
    st.markdown("#### ⭐ Quick In-App Feedback")
    with st.form("in_app_feedback_dialog"):
        name=st.text_input("Your Name")
        msg=st.text_area("Your Feedback")
        # FIXED - STAR RATING NOT SLIDER
        rating=st.feedback("stars")
        submitted=st.form_submit_button("Submit Feedback")
        if submitted:
            stars = rating+1 if rating is not None else 5
            with open(FEEDBACK_CSV,"a",newline="",encoding="utf-8") as f:
                csv.writer(f).writerow([datetime.datetime.now(),name,msg,stars])
            st.success("Thank you! Feedback saved")

@st.fragment(run_every=3)
def live_dashboard(controls):
    if not os.path.exists(LIVE_FILE_PATH): populate_default_live_csv(LIVE_FILE_PATH,clean=len(st.session_state["blocked_ips_set"])==0)
    if st.session_state["traffic_is_running"] and not is_externally_fed(LIVE_FILE_PATH):
        if np.random.rand() > 0.7:
            existing=pd.read_csv(LIVE_FILE_PATH)
            new_row={"Timestamp":datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),"IP Address":np.random.choice(["8.8.8.8","1.1.1.1","103.255.4.12",f"192.168.1.{np.random.randint(10,254)}"]),"Protocol":np.random.choice(["TCP","UDP","HTTP","HTTPS"]),"Packet Size (KB)":np.random.uniform(100,5000),"Requests/sec":np.random.uniform(5,500)}
            pd.concat([existing, pd.DataFrame([new_row])]).tail(200).to_csv(LIVE_FILE_PATH,index=False)
            st.session_state["_last_self_write_mtime"]=os.path.getmtime(LIVE_FILE_PATH)
    df=parse_and_transform_ledger(LIVE_FILE_PATH)
    df=score_and_classify(df,controls.max_tx_amount,controls.max_velocity,controls.system_mode)
    render_metric_cards(df)
    insight=generate_ai_insight_colored(df)
    st.markdown(f'<div class="ai-panel" style="--ai-color:{insight["color"]};"><div class="ai-panel-header"><div class="ai-panel-title">{insight["icon"]} AI SECURITY INSIGHT - STATE: {insight["level"]}</div><div class="ai-badge">{insight["level"]}</div></div><div class="ai-panel-body">{insight["text"]}</div></div>', unsafe_allow_html=True)
    col_chart,col_log=st.columns([12,8])
    with col_chart:
        with st.container(border=True):
            title="System Network Anomaly Mapping" if controls.system_mode.startswith("🌐") else "Financial Transaction Risk Analysis"
            st.markdown(f"<h3 style='margin:0 0 8px 0;color:#38bdf8;font-size:18px;'>📈 {title}</h3>",unsafe_allow_html=True)
            st.plotly_chart(render_chart(df,controls.system_mode), width='stretch', key="main_chart_v48")
    with col_log:
        with st.container(border=True):
            st.markdown("<h3 style='margin:0 0 4px 0;color:#ef4444;font-size:18px;'>📡 Live Threat Log Pipeline - LIVE</h3>",unsafe_allow_html=True)
            st.caption(f"Engine: {'ON' if st.session_state['traffic_is_running'] else 'OFF'}")
            with st.container(height=380): render_live_log(df,controls.system_mode)
    render_blocked_ips_table_main()
    render_registry_and_exports(df,controls.system_mode)

def main():
    inject_css(); init_state()
    controls=render_sidebar()
    render_header()
    live_dashboard(controls)
    st.divider()
    # FEEDBACK WITH STARS NOT LINE BAR
    with st.container(border=True):
        st.markdown("<h3 style='color:#00ffcc;margin-top:0;'>💌 Feedback & Evaluation - Survey + 5 Star Rating</h3>",unsafe_allow_html=True)
        c1,c2 = st.columns([2,1])
        with c1:
            st.markdown("**Help us improve AXPS Inspector**")
            if st.button("⭐ Rate System Experience - Open Survey Form", key="btn_feedback_main_page", width='stretch'):
                open_feedback_dialog()
            st.link_button("📝 Open Google Survey Form Directly", GOOGLE_FORM_URL, width='stretch')
        with c2:
            st.markdown("**Quick 5-Star Rating:**")
            if st.session_state.get("feedback_submitted"):
                st.success(f"Thanks for {st.session_state['star_rating']} stars! 🙏")
            else:
                rating=st.feedback("stars")
                if rating is not None:
                    st.session_state["star_rating"]=rating+1; st.session_state["feedback_submitted"]=True
                    with open(FEEDBACK_CSV,"a",newline="",encoding="utf-8") as f:
                        csv.writer(f).writerow([datetime.datetime.now(),"main_page_star",f"{rating+1} stars",rating+1])
                    st.balloons(); st.rerun()

if __name__=="__main__": main()
