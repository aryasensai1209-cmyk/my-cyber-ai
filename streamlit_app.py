import streamlit as st
import re
import time
import pandas as pd
import numpy as np
import json
import os

st.set_page_config(page_title='Cyber AI v18: God-Mode', page_icon='🛡️', layout='wide')

DB_PATH = 'custom_signatures.json'

class GodLevelSecurityEngine:
    def __init__(self):
        self.vulnerability_map = {
            '1. Injection': [
                {'name': 'Advanced SQLi', 'pattern': r'(SELECT|INSERT|UPDATE|DELETE|UNION|DROP|EXEC|CAST|CONVERT).*?([\\s\\+\\$\\%{]).*?[\\x27\\x22]', 'explanation': 'Dynamic query building detected.', 'fix': 'Enforce strictly parameterized queries.', 'severity': 'CRITICAL'},
                {'name': 'NoSQL Operator Injection', 'pattern': r'(\\$where|\\$ne|\\$gt|\\$regex|\\$exists)', 'explanation': 'Untrusted data modifying NoSQL logic.', 'fix': 'Sanitize keys using schema validation.', 'severity': 'HIGH'}
            ],
            '2. Shell & Command': [
                {'name': 'OS Command Injection', 'pattern': r'(os\\.system|subprocess|exec|system|popen|shutil|spawn)\\(.*?([+\\%]|f[\\"\\x27\\\\\\\\]).+?\\\)', 'explanation': 'Execution of system commands with variable inputs.', 'fix': 'Pass arguments as a list with shell=False.', 'severity': 'CRITICAL'}
            ],
            '3. Cross-Site Scripting': [
                {'name': 'DOM-Based XSS', 'pattern': r'(\\.(innerHTML|outerHTML|srcdoc)\\s*=|document\\.write\\(|alert\\(|eval\\(.*?location)', 'explanation': 'Injecting user input into the browser DOM.', 'fix': 'Use .textContent or .innerText.', 'severity': 'HIGH'}
            ],
            '4. Authentication': [
                {'name': 'Hardcoded Credentials', 'pattern': r'(password|passwd|secret|token|apikey|aws_key|private_key)\\s*[:=]\\s*[\\x27\\x22][a-zA-Z0-9_\\-]{5,}[\\x27\\x22]', 'explanation': 'Sensitive secrets found in source code.', 'fix': 'Use secret managers or environment variables.', 'severity': 'CRITICAL'}
            ],
            '5. AI Safety': [
                {'name': 'Insecure Deserialization', 'pattern': r'(pickle\\.load\\(|joblib\\.load\\(|yaml\\.load\\(.*?Loader=)', 'explanation': 'Loading untrusted data into objects.', 'fix': 'Use safe loaders like json.loads().', 'severity': 'HIGH'}
            ],
            '6. Cloud Infrastructure': [
                {'name': 'Metadata Leakage', 'pattern': r'(169\\.254\\.169\\.254|s3://.*?/|\\.s3\\.amazonaws\\.com)', 'explanation': 'Exposure of cloud provider metadata.', 'fix': 'Enforce IMDSv2.', 'severity': 'HIGH'}
            ],
            '7. Cryptography': [
                {'name': 'Weak Primitives', 'pattern': r'(hashlib\\.md5|hashlib\\.sha1|DES|RC4|blowfish)', 'explanation': 'Use of compromised algorithms.', 'fix': 'Upgrade to SHA-256 or AES-GCM.', 'severity': 'HIGH'}
            ],
            '8. Memory Safety': [
                {'name': 'Buffer Operations', 'pattern': r'(strcpy|strcat|sprintf|gets|memcpy|malloc)\\(', 'explanation': 'Unsafe memory operations.', 'fix': 'Use bounds-checked functions.', 'severity': 'MEDIUM'}
            ],
            '9. API Security': [
                {'name': 'JWT Misconfig', 'pattern': r'(jwt\\.decode\\(.*?verify=False|algorithm=[\\"\\x27]none[\\"\\x27])', 'explanation': 'Bypassing signature verification.', 'fix': 'Enforce signature verification.', 'severity': 'CRITICAL'}
            ],
            '10. Supply Chain': [
                {'name': 'Insecure Dependency', 'pattern': r'(curl.*?\\|.*?bash|pip install.*?--extra-index-url)', 'explanation': 'Downloading unverified packages.', 'fix': 'Use pinned versions with hashes.', 'severity': 'HIGH'}
            ],
            '11. PII Compliance': [
                {'name': 'PII Data Exposure', 'pattern': r'(email|ssn|phone|credit_card|social_security)\\s*[:=]', 'explanation': 'Unmasked handling of PII.', 'fix': 'Implement encryption at rest.', 'severity': 'MEDIUM'}
            ],
            '12. Business Logic': [
                {'name': 'Race Conditions', 'pattern': r'(threading\\.Thread|asyncio\\.create_task).*?(\\+=|\\-=)', 'explanation': 'Concurrent updates without atomicity.', 'fix': 'Implement Mutex/Locks.', 'severity': 'MEDIUM'}
            ],
            '13. Path Handling': [
                {'name': 'Path Traversal', 'pattern': r'(\\.\\./|\\.\\.\\\\|/etc/passwd|/proc/|/windows/win\\.ini)', 'explanation': 'Accessing files outside application root.', 'fix': 'Use os.path.basename().', 'severity': 'HIGH'}
            ],
            '14. Container Security': [
                {'name': 'Privileged Flag', 'pattern': r'(privileged:\\s*true|hostNetwork:\\s*true)', 'explanation': 'Container exposing host kernel.', 'fix': 'Run as non-root user.', 'severity': 'HIGH'}
            ],
            '15. Blockchain': [
                {'name': 'Reentrancy Logic', 'pattern': r'(msg\\.sender\\.call|transfer\\(|lock_state).*?(\\-=|\\+=)', 'explanation': 'External calls before state updates.', 'fix': 'Follow Checks-Effects-Interactions pattern.', 'severity': 'CRITICAL'}
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
            except: pass

    def save_custom_signature(self, cat, rule):
        custom_data = {}
        if os.path.exists(DB_PATH):
            try:
                with open(DB_PATH, 'r') as f:
                    custom_data = json.load(f)
            except: pass
        custom_data.setdefault(cat, []).append(rule)
        with open(DB_PATH, 'w') as f:
            json.dump(custom_data, f, indent=4)

    def scan(self, code):
        findings = []
        start = time.perf_counter()
        for category, rules in self.vulnerability_map.items():
            for rule in rules:
                matches = re.finditer(rule['pattern'], code, re.IGNORECASE | re.MULTILINE | re.DOTALL)
                for match in matches:
                    findings.append({'Vector': category, 'Snippet': match.group(0), **rule})
        latency = time.perf_counter() - start
        risk_score = min(len(findings) * 15, 100)
        return findings, latency, risk_score

if 'engine' not in st.session_state: st.session_state.engine = GodLevelSecurityEngine()
if 'history' not in st.session_state: st.session_state.history = []
if 'results' not in st.session_state: st.session_state.results = []
if 'risk' not in st.session_state: st.session_state.risk = 0

st.title('🦾 Cyber AI v18: God-Mode (Fixed)')

t1, t2, t3, t4, t5 = st.tabs(['🔍 Scan', '📊 Analytics', '📋 Remediation', '🧠 Learning', '🧪 Debugger'])

with t1:
    code_in = st.text_area('Input Code:', height=300)
    if st.button('INITIATE AUDIT'):
        if code_in:
            results, latency, risk = st.session_state.engine.scan(code_in)
            st.session_state.results = results
            st.session_state.risk = risk
            st.session_state.history.append(latency)
            if results: st.error(f'Threats: {len(results)} | Risk: {risk}/100')
            else: st.success('System Secure.')

with t2:
    st.subheader('Security Telemetry')
    if st.session_state.history:
        c1, c2 = st.columns(2)
        c1.metric('Risk Rating', f"{st.session_state.risk}/100")
        c2.metric('Engine Latency', f"{st.session_state.history[-1]:.6f}s")
        st.line_chart(st.session_state.history)
    else: st.info('No metrics available yet.')

with t3:
    if st.session_state.results:
        for res in st.session_state.results:
            with st.expander(f"[{res['severity']}] {res['name']} - {res['Vector']}"):
                st.warning(f"Snippet: `{res['Snippet']}`")
                st.write(f"Fix: {res['fix']}")
    else: st.info('No vulnerabilities found.')

with t4:
    with st.form('learn_form'):
        cat = st.text_input('Category')
        name = st.text_input('Name')
        pat = st.text_input('Regex')
        fix = st.text_input('Fix')
        if st.form_submit_button('LEARN SIGNATURE'):
            new_rule = {'name': name, 'pattern': pat, 'explanation': 'Learned.', 'fix': fix, 'severity': 'HIGH'}
            st.session_state.engine.vulnerability_map.setdefault(cat, []).append(new_rule)
            st.session_state.engine.save_custom_signature(cat, new_rule)
            st.success('Signature persisted.')

with t5:
    t_s = st.text_input('Test Snippet')
    t_r = st.text_input('Test Regex', value='SELECT')
    if st.button('VALIDATE'):
        m = re.search(t_r, t_s, re.I | re.S)
        if m: st.error(f'MATCH: {m.group(0)}')
        else: st.success('CLEAR')