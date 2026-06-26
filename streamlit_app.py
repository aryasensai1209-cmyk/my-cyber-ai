
import streamlit as st
import re
import pandas as pd
import time
import numpy as np

st.set_page_config(page_title='CyberEnterprise Pro', page_icon='🛡️', layout='wide')

class EnterpriseLogicEngine:
    def __init__(self):
        self.vulnerability_map = {
            '1. Injection & Input': [
                {'name': 'SQLi', 'pattern': r'(SELECT|INSERT|UPDATE|DELETE|UNION|DROP).*?(\+|\$|%|\{).*?[\'\"]', 'explanation': 'SQL injection via concatenation.', 'fix': 'Use Parameterized Queries.', 'severity': 'CRITICAL'},
                {'name': 'Command Injection', 'pattern': r'(os\\.system|subprocess|exec|eval|system|popen)\\(.*?(\\+|%).*?\\)', 'explanation': 'Unsanitized input in shell execution.', 'fix': 'Avoid shell=True.', 'severity': 'CRITICAL'}
            ],
            '2. Web App Flaws': [
                {'name': 'XSS', 'pattern': r'(\\.(innerHTML|outerHTML)\\s*=|document\\.write\\(|alert\\()', 'explanation': 'Script execution in browser context.', 'fix': 'Use .textContent.', 'severity': 'HIGH'}
            ],
            '3. Auth & Session': [
                {'name': 'Hardcoded Creds', 'pattern': r'(password|passwd|secret|token|apikey)\\s*[:=]\\s*[\'\"]\\w{5,}[\'\"]', 'explanation': 'Plaintext credentials in code.', 'fix': 'Use Environment Variables.', 'severity': 'CRITICAL'}
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

st.title('🛡️ CyberEnterprise Pro v9.2')

if 'engine' not in st.session_state:
    st.session_state.engine = EnterpriseLogicEngine()

code_input = st.text_area('Source Code:', height=300)
if st.button('INITIATE SECURITY SCAN'):
    if code_input:
        results, latency = st.session_state.engine.scan(code_input)
        if results:
            st.error(f'Vulnerabilities Found: {len(results)}')
            for res in results:
                with st.expander(f"{res['name']} - {res['severity']}"):
                    st.write(res['explanation'])
                    st.success(f"Fix: {res['fix']}")
        else:
            st.success('Clean Scan.')
