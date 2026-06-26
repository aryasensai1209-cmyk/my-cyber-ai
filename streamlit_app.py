
import streamlit as st
import time
import re
import pandas as pd
import numpy as np

# Paste fixed engine class here for the app
class EnterpriseLogicEngine:
    def __init__(self):
        self.vulnerability_map = {
            '1. Injection & Input': [
                {'name': 'SQLi', 'pattern': r"(SELECT|INSERT|UPDATE|DELETE|UNION|DROP).*?(['\"\$]|OR|AND)", 'explanation': 'SQL injection via concatenation.', 'fix': 'Use Parameterized Queries.', 'severity': 'CRITICAL'},
                {'name': 'Command Injection', 'pattern': r"(os\.system|subprocess|exec|eval|system|popen)\(.*?([\+]).*?\)", 'explanation': 'Unsanitized input in shell execution.', 'fix': 'Avoid shell=True.', 'severity': 'CRITICAL'}
            ],
            '2. Web App Flaws': [
                {'name': 'XSS', 'pattern': r"(\.(innerHTML|outerHTML)\s*=|document\.write\(|alert\()", 'explanation': 'Script execution in browser context.', 'fix': 'Use .textContent.', 'severity': 'HIGH'}
            ]
        }
    def scan(self, code):
        findings = []
        start = time.perf_counter()
        for category, rules in self.vulnerability_map.items():
            for rule in rules:
                if re.search(rule['pattern'], code, re.IGNORECASE | re.DOTALL):
                    findings.append({'category': category, **rule})
        return findings, time.perf_counter() - start

st.set_page_config(page_title='Cyber AI Pro', layout='wide')
st.title('🛡️ Cyber AI Enterprise v8.3')

if 'engine' not in st.session_state:
    st.session_state.engine = EnterpriseLogicEngine()

tab1, tab2 = st.tabs(['Scanner', 'Metrics'])

with tab1:
    code_input = st.text_area('Input Source Code:', height=250)
    if st.button('RUN ANALYSIS'):
        if code_input:
            results, latency = st.session_state.engine.scan(code_input)
            st.session_state.last_latency = latency
            if results:
                st.error(f'Threats Detected: {len(results)}')
                for res in results:
                    with st.expander(f"[{res['severity']}] {res['name']}"):
                        st.write(f"**Explanation:** {res['explanation']}")
                        st.success(f"**Fix:** {res['fix']}")
            else:
                st.success('No vulnerabilities found.')

with tab2:
    st.subheader('System Performance Metrics')
    if 'last_latency' in st.session_state:
        m1, m2 = st.columns(2)
        m1.metric('Scan Latency', f"{st.session_state.last_latency:.6f}s")
        m2.metric('Throughput', f"{1/(st.session_state.last_latency + 1e-9):,.0f} ops/sec")
    else:
        st.info('Run a scan to see performance meters.')
