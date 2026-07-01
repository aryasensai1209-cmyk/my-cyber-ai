import streamlit as st
import re
import time
import pandas as pd
import numpy as np
import json
import os

st.set_page_config(page_title='Cyber AI v18: God-Mode', page_icon='⁁', layout='wide')

DB_PATH = 'custom_signatures.json'

class GodLevelSecurityEngine:
    def __init__(self):
        self.vulnerability_map = {
            '1. Advanced Injection': [
                {'name': 'Complex SQLi', 'pattern': r'(SELECT|INSERT|UPDATE|DELETE|UNION|DROP|EXEC|CAST|CONVERT).*?([\\s\\+\\$\\%{]).*?[\\x27\\x22]', 'explanation': 'Dynamic query building with string concatenation detected.', 'fix': 'Enforce strictly parameterized queries using bind variables.', 'severity': 'CRITICAL'},
                {'name': 'NoSQL Operator Injection', 'pattern': r'(\\$where|\\$ne|\\$gt|\\$regex|\\$exists)', 'explanation': 'Untrusted data modifying NoSQL logical operators.', 'fix': 'Sanitize keys using schema validation.', 'severity': 'HIGH'}
            ],
            '2. Shell & Command': [
                {'name': 'OS Command Injection', 'pattern': r'(os\\.system|subprocess|exec|system|popen|shutil|spawn)\\(.*?([+\\%]|f[\\"\\x27\\\\\\\\]).+?\\])', 'explanation': 'Execution of system commands with variable inputs.', 'fix': 'Pass arguments as a list with shell=False.', 'severity': 'CRITICAL'}
            ],
            '4. Authentication': [
                {'name': 'Hardcoded Credentials', 'pattern': r'(?:password|secret|token|pass|key)\\s*[:=]\\s*[\\x27\\x22][a-zA-Z0-9_\\-]{5,}[\\x27\\x22]', 'explanation': 'Sensitive secrets found in source code.', 'fix': 'Use secret managers or environment variables.', 'severity': 'CRITICAL'}
            ],
            '10. Path & File Handling': [
                {'name': 'Path Traversal', 'pattern': r'(\\.\\./|\\.\\.\\\\|/etc/passwd|/proc/|/windows/win\\.ini)', 'explanation': 'Accessing files outside application root.', 'fix': 'Use os.path.basename().', 'severity': 'HIGH'}
            ]
        }
        self.load_custom_signatures()

    def load_custom_signatures(self):
        if os.path.exists(DB_PATH):
            try:
                with open(DB_PATH, 'r') as f:
                    custom_data = json.load(f)
                    for cat, rules in custom_data.items():
                        self.vulnerability_map.setdefault(cat, []).extend(rules)
            except Exception: pass

    def scan(self, code):
        findings = []
        start = time.perf_counter()
        for category, rules in self.vulnerability_map.items():
            for rule in rules:
                # UPGRADED: Global search to capture ALL occurrences in file
                matches = re.finditer(rule['pattern'], code, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    findings.append({
                        'Vector': category,
                        'Snippet': match.group(0),
                        'Regex_Signature': rule['pattern'],
                        **rule
                    })
        latency = time.perf_counter() - start
        risk_score = min(len(findings) * 5, 100)
        return findings, latency, risk_score

if 'engine' not in st.session_state: st.session_state.engine = GodLevelSecurityEngine()
if 'history' not in st.session_state: st.session_state.history = []

st.title('⁁ Cyber AI v18: God-Mode')

t1, t2, t3, t4, t5 = st.tabs(['ሃ Scan', 'ህ Analytics', 'ሆ Remediation', 'ሇ AI Learning', 'ለ Test'])

with t1:
    c_type = st.radio("Input Source", ["Manual Paste", "File Upload"])
    code_in = ""
    if c_type == "Manual Paste":
        code_in = st.text_area('Source Code Input:', height=350, placeholder="Paste high-volume code here for global audit...")
    else:
        uploaded_file = st.file_uploader("Choose a source file", type=['py', 'js', 'sql', 'php', 'c', 'cpp', 'txt'])
        if uploaded_file is not None:
            code_in = uploaded_file.read().decode("utf-8")
            st.text_area("File Preview", code_in, height=150)

    if st.button('INITIATE GOD-MODE AUDIT'):
        if code_in:
            results, latency, risk = st.session_state.engine.scan(code_in)
            st.session_state.results = results
            st.session_state.risk = risk
            st.session_state.history.append(latency)
            if results: st.error(f'Threats Identified: {len(results)} | Risk Score: {risk}')
            else: st.success('System Secure Across All Vectors.')

with t3:
    st.subheader('Architectural Remediation Dashboard')
    if 'results' in st.session_state and st.session_state.results:
        for res in st.session_state.results:
            with st.expander(f"[{res['severity']}] {res['name']} - Vector: {res['Vector']}"):
                st.info(f"**Trigger Snippet:** `{res['Snippet']}`")
                st.markdown(f"**Regex Signature:** `{res['Regex_Signature']}`")
                st.success(f"**Secure Patch:** {res['fix']}")
    else: st.info("No scan results available.")