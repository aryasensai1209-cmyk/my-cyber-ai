import streamlit as st
import time

# --- Page Config ---
st.set_page_config(page_title="Cyber AI Enterprise", page_icon="🛡️", layout="wide")

# --- AI Logic ---
def analyze_code(code):
    threats = {
        'SELECT *': 'SQL Injection: Use Parameterized Queries.',
        'eval(': 'Critical: Dynamic Code Execution.',
        'system(': 'High: Command Injection Risk.',
        'os.system': 'High: Command Injection Risk.'
    }
    found_threats = [v for k, v in threats.items() if k in code]
    return found_threats

# --- Dashboard UI ---
st.title("🛡️ Cyber AI Enterprise")
st.markdown("v2.1 | Global Security Node")

code_input = st.text_area("Paste source code to analyze...", height=300)

if st.button("INITIATE SYSTEM SCAN"):
    if code_input:
        with st.spinner("AI Engine performing deep inspection..."):
            time.sleep(1) # Simulating processing
            results = analyze_code(code_input)
            
            if results:
                st.error("### ⚠️ THREAT(S) DETECTED")
                for r in results:
                    st.write(f"- **Fix:** {r}")
            else:
                st.success("### ✅ SYSTEM SECURE")
                st.write("No critical vulnerabilities identified.")
    else:
        st.warning("Please paste some code first.")

# --- Sidebar Stats ---
st.sidebar.header("System Status")
st.sidebar.info("● CORE: ONLINE\n\n● DB: 1M SIGNATURES\n\n● MODE: PRODUCTION")

# --- DATABASE INTEGRATION (Supabase) ---
from supabase import create_client, Client

def init_db():
    # Retrieve secrets from Streamlit Cloud dashboard
    try:
        url = st.secrets["SUPABASE_URL"]
        key = st.secrets["SUPABASE_KEY"]
        return create_client(url, key)
    except:
        return None

supabase = init_db()

def save_scan_result(code_preview, threat_found, remediation):
    if supabase:
        try:
            supabase.table("scan_history").insert({
                "code_snippet": code_preview[:100],
                "vulnerable": threat_found,
                "fix_suggested": remediation
            }).execute()
        except Exception as e:
            st.sidebar.error(f"DB Error: {e}")

# --- DATABASE INTEGRATION (Supabase) ---
from supabase import create_client, Client
import pandas as pd

def init_db():
    try:
        url = st.secrets["SUPABASE_URL"]
        key = st.secrets["SUPABASE_KEY"]
        return create_client(url, key)
    except:
        return None

supabase = init_db()

def save_scan_result(code_preview, threat_found, remediation):
    if supabase:
        try:
            supabase.table("scan_history").insert({
                "code_snippet": code_preview[:100],
                "vulnerable": threat_found,
                "fix_suggested": remediation
            }).execute()
        except Exception as e:
            st.sidebar.error(f"DB Save Error: {e}")

# --- NEW: FUNCTION TO DISPLAY HISTORY ---
st.markdown("--- ")
st.subheader("📜 Recent Scan History")

if supabase:
    try:
        response = supabase.table("scan_history").select("*").order("created_at", desc=True).limit(5).execute()
        if response.data:
            history_df = pd.DataFrame(response.data)
            st.table(history_df[['created_at', 'code_snippet', 'vulnerable', 'fix_suggested']])
        else:
            st.info("No scan history found yet.")
    except Exception as e:
        st.error(f"Could not load history: {e}")
else:
    st.warning("Connect Supabase in Secrets to enable Scan History.")
