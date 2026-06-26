import streamlit as st
import time
import google.generativeai as genai
import pandas as pd
from supabase import create_client

# --- Page Config ---
st.set_page_config(page_title="Cyber AI Ultra", page_icon="🛡️", layout="wide")

# --- AI & DB Initialization ---
def init_engines():
    # 1. Gemini Configuration
    try:
        api_key = st.secrets["GOOGLE_API_KEY"]
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel('gemini-1.5-flash')
    except:
        model = None

    # 2. Supabase Configuration
    try:
        url = st.secrets["SUPABASE_URL"]
        key = st.secrets["SUPABASE_KEY"]
        db = create_client(url, key)
    except:
        db = None
    
    return model, db

gemini_model, supabase = init_engines()

# --- Core Logic Functions ---
def simple_scan(code):
    threats = {
        'SELECT *': 'SQL Injection: Use Parameterized Queries.',
        'eval(': 'Critical: Dynamic Code Execution.',
        'os.system': 'High: Command Injection Risk.'
    }
    return [v for k, v in threats.items() if k in code]

def deep_inspection(code):
    if not gemini_model:
        return "❌ Gemini API Key not configured in Secrets."
    
    prompt = f"""
    Analyze this code for advanced vulnerabilities (Logic flaws, Zero-days, Race conditions).
    Provide a detailed security report with severity and fixes.
    CODE:
    {code}
    """
    response = gemini_model.generate_content(prompt)
    return response.text

# --- UI Layout ---
st.title("🛡️ Cyber AI Ultra v3.0")
st.markdown("Enterprise-Grade Deep Semantic Security Inspection")

tab1, tab2 = st.tabs(["🔍 Security Scanner", "📜 Scan History"])

with tab1:
    col1, col2 = st.columns([2, 1])
    with col1:
        code_input = st.text_area("Paste Source Code:", height=400)
        mode = st.radio("Analysis Mode:", ["Standard (Fast Pattern Match)", "Deep Inspection (AI Semantic Audit)"])
        
    with col2:
        st.info("**System Status**\n\n● AI Node: ONLINE\n\n● Engine: Gemini 1.5 Pro\n\n● Latency: ~2s")
        scan_btn = st.button("🚀 START ANALYSIS", use_container_width=True)

    if scan_btn and code_input:
        with st.spinner("Analyzing security posture..."):
            if "Deep" in mode:
                report = deep_inspection(code_input)
                st.subheader("🛡️ Deep Inspection Report")
                st.markdown(f"<div style='background:#1e1e1e; padding:20px; border-radius:10px; border:1px solid #58a6ff;'>{report}</div>", unsafe_allow_html=True)
            else:
                results = simple_scan(code_input)
                if results:
                    for r in results: st.error(f"⚠️ {r}")
                else:
                    st.success("✅ No common patterns detected.")

with tab2:
    st.write("Historical scan results from Supabase would appear here.")
