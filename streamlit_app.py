import streamlit as st
import re
import time
import pandas as pd
import numpy as np
import json
import os

st.set_page_config(page_title='Cyber AI Extreme v18.0', page_icon='🦾', layout='wide')

DB_PATH = 'custom_signatures.json'

class GodLevelSecurityEngine:
    def __init__(self):
        self.vulnerability_map = {
            '1. Injection': [
                {'name': 'Advanced SQLi', 'pattern': r'(SELECT|INSERT|UPDATE|DELETE|UNION|DROP|EXEC|CAST|CONVERT).*?([\\s\\+\\$\\%{]).*?[\\x27\\x22]', 'explanation': 'Dynamic query building detected.', 'fix': 'Enforce strictly parameterized queries.', 'severity': 'CRITICAL'},
                {'name': 'NoSQL Operator Injection', 'pattern': r'(\\$where|\\$ne|\\$gt|\\$regex|\\$exists)', 'explanation': 'Untrusted data modifying NoSQL logic.', 'fix': 'Sanitize keys using schema validation.', 'severity': 'HIGH'}
            ],
            '2. Command & Shell': [
                {'name': 'OS Command Injection', 'pattern': r'(os\\.system|subprocess|exec|system|popen|shutil|spawn)\\(.*?([+\\%]|f[\\"\\x27\\\\\\\\]).+?\\)', 'explanation': 'Execution of system commands with variable inputs.', 'fix': 'Pass arguments as a list with shell=False.', 'severity': 'CRITICAL'}
            ]
        }
        self.load_custom_signatures()

    def load_custom_signatures(self):
        if os.path.exists(DB_PATH):
            try:
                with open(DB_PATH, 'r') as f:
                    custom_data = json.load(f)
                    for cat, rules in custom_data.items():
                        if cat not in self.vulnerability_map:
                            self.vulnerability_map[cat] = []
                        self.vulnerability_map[cat].extend(rules)
            except Exception as e:
                st.sidebar.error(f"Persistence Error: {e}")

    def save_custom_signature(self, cat, rule):
        custom_data = {}
        if os.path.exists(DB_PATH):
            with open(DB_PATH, 'r') as f:
                custom_data = json.load(f)
        if cat not in custom_data: custom_data[cat] = []
        custom_data[cat].append(rule)
        with open(DB_PATH, 'w') as f:
            json.dump(custom_data, f, indent=4)

    def scan(self, code):
        findings = []
        start = time.perf_counter()
        for category, rules in self.vulnerability_map.items():
            for rule in rules:
                match = re.search(rule['pattern'], code, re.IGNORECASE | re.DOTALL)
                if match:
                    findings.append({'Vector': category, 'Snippet': match.group(0), **rule})
        latency = time.perf_counter() - start
        risk_score = min(len(findings) * 20, 100)
        return findings, latency, risk_score

if 'engine' not in st.session_state: st.session_state.engine = GodLevelSecurityEngine()
if 'history' not in st.session_state: st.session_state.history = []

st.title('🦾 Cyber AI Extreme: HEURISTIC MODE v18.0')

tab1, tab2, tab3, tab4, tab5 = st.tabs(['🔍 Scanner', '📊 Analytics', '📋 Remediation', '🧠 AI Learning', '🧪 Debugger'])

with tab1:
    code_input = st.text_area('Input Code:', height=300)
    if st.button('INITIATE HEURISTIC AUDIT'):
        if code_input:
            results, latency, risk = st.session_state.engine.scan(code_input)
            st.session_state.results = results
            st.session_state.risk = risk
            st.session_state.history.append(latency)
            if results: st.error(f'Threats Identified: {len(results)} | Risk: {risk}/100')
            else: st.success('System Secure.')

with tab2:
    st.subheader('Security Telemetry')
    if 'risk' in st.session_state:
        m1, m2 = st.columns(2)
        m1.metric('Risk Score', f"{st.session_state.risk}/100")
        m2.metric('Engine Latency', f"{st.session_state.history[-1]:.6f}s")
        st.line_chart(st.session_state.history)
    else: st.info('Run a scan to view metrics.')

with tab3:
    st.subheader('Remediation Dashboard')
    if 'results' in st.session_state and st.session_state.results:
        for res in st.session_state.results:
            with st.expander(f"[{res['severity']}] {res['name']}"):
                st.write(f"**Pattern Signature:** `{res['pattern']}`")
                st.write(f"**Reason:** {res['explanation']}")
                st.success(f"**Automated Fix:** {res['fix']}")
    else: st.info('No threats detected.')

with tab4:
    st.subheader('AI Learning - Integrated Signature Injection')
    with st.form('learn'):
        c, n, p, f = st.text_input('Category'), st.text_input('Name'), st.text_input('Regex'), st.text_input('Fix')
        if st.form_submit_button('INTEGRATE INTO CORE'):
            rule = {'name': n, 'pattern': p, 'explanation': 'Custom learned signature.', 'fix': f, 'severity': 'HIGH'}
            st.session_state.engine.vulnerability_map.setdefault(c, []).append(rule)
            st.session_state.engine.save_custom_signature(c, rule)
            st.success('Signature learned and persisted.')

with tab5:
    st.subheader('Regex Debugger')
    t_f, t_r = st.text_input('Test Snippet'), st.text_input('Test Regex', value='SELECT')
    if st.button('VALIDATE'):
        m = re.search(t_r, t_f, re.I | re.S)
        if m: st.error(f'MATCH: {m.group(0)}')
        else: st.success('NO MATCH')