import streamlit as st
import re
import time
import pandas as pd
import numpy as np
import json
import os

st.set_page_config(page_title='Cyber AI v18 Pro', page_icon='🛡️', layout='wide')

class CyberEngineV18:
    def __init__(self):
        self.vulnerability_map = {
            '1. Injection': [
                {'name': 'Advanced SQLi', 'pattern': r'(SELECT|INSERT|UPDATE|DELETE|UNION|DROP|EXEC|CAST|CONVERT).*?([\\s\\+\\\\%{]).*?[\\x27\\x22]', 'explanation': 'Dynamic query building detected.', 'fix': 'Enforce strictly parameterized queries.', 'severity': 'CRITICAL'},
                {'name': 'NoSQL Injection', 'pattern': r'(\\\\$where|\\\\$ne|\\\\$gt|\\\\$regex|\\\\$exists)', 'explanation': 'Untrusted data modifying NoSQL logic.', 'fix': 'Sanitize keys using schema validation.', 'severity': 'HIGH'}
            ],
            '2. Command & Shell': [
                {'name': 'OS Command Injection', 'pattern': r'(os\\.system|subprocess|exec|system|popen|shutil|spawn)\\(.*?([+\\\\%]|f[\\"\\x27\\\\\\\\]).+?\\\)', 'explanation': 'Execution of system commands with variable inputs.', 'fix': 'Pass arguments as a list with shell=False.', 'severity': 'CRITICAL'}
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
                {'name': 'Race Conditions', 'pattern': r'(threading\\.Thread|asyncio\\.create_task).*?(\\\\+=|\\\\-=)', 'explanation': 'Concurrent updates without atomicity.', 'fix': 'Implement Mutex/Locks.', 'severity': 'MEDIUM'}
            ],
            '13. Path Handling': [
                {'name': 'Path Traversal', 'pattern': r'(\\\\.\\\\./|\\\\.\\\\\\\\.|/etc/passwd|/proc/|/windows/win\\\\.ini)', 'explanation': 'Accessing files outside application root.', 'fix': 'Use os.path.basename().', 'severity': 'HIGH'}
            ],
            '14. Container Security': [
                {'name': 'Privileged Flag', 'pattern': r'(privileged:\\s*true|hostNetwork:\\s*true)', 'explanation': 'Container exposing host kernel.', 'fix': 'Run as non-root user.', 'severity': 'HIGH'}
            ],
            '15. Blockchain': [
                {'name': 'Reentrancy Logic', 'pattern': r'(msg\\.sender\\.call|transfer\\(|lock_state).*?(\\\\-=|\\\\+=)', 'explanation': 'External calls before state updates.', 'fix': 'Follow Checks-Effects-Interactions pattern.', 'severity': 'CRITICAL'}
            ]
        }

    def scan(self, code):
        findings = []
        seen_signatures = set()
        start = time.perf_counter()
        for category, rules in self.vulnerability_map.items():
            for rule in rules:
                matches = re.finditer(rule['pattern'], code, re.IGNORECASE | re.MULTILINE | re.DOTALL)
                for match in matches:
                    snippet = match.group(0).strip()
                    sig = f"{rule['name']}:{snippet}"
                    if sig not in seen_signatures:
                        findings.append({'Vector': category, 'Snippet': snippet, **rule})
                        seen_signatures.add(sig)
        latency = time.perf_counter() - start
        risk_score = min(len(findings) * 15, 100)
        return findings, latency, risk_score

if 'engine' not in st.session_state: st.session_state.engine = CyberEngineV18()
if 'history' not in st.session_state: st.session_state.history = []

st.title('🛡️ Cyber AI v18: Unified Production Build')

t1, t2, t3, t4, t5 = st.tabs(['🔍 Scanner', '📊 Analysis', '📋 Remediation', '🧠 Learning', '🧪 Debugger'])

with t1:
    code_in = st.text_area('Input Source Code:', height=350)
    if st.button('INITIATE SECURITY AUDIT'):
        if code_in:
            results, latency, risk = st.session_state.engine.scan(code_in)
            st.session_state.results = results
            st.session_state.risk = risk
            st.session_state.latency = latency
            st.session_state.history.append({'time': time.strftime('%H:%M:%S'), 'latency': latency, 'risk': risk})
            if results: st.error(f'Unique Threats Identified: {len(results)} | Risk Level: {risk}/100')
            else: st.success('System Secure Across All 15 Vectors.')

with t2:
    st.subheader('Security Analytics Dashboard')
    if 'results' in st.session_state:
        c1, c2 = st.columns(2)
        df_hist = pd.DataFrame(st.session_state.history)
        c1.metric('Current Risk Rating', f"{st.session_state.risk}/100")
        c2.metric('Engine Latency', f"{st.session_state.latency:.6f}s")
        
        st.markdown('### Threat Severity Distribution')
        severity_data = pd.DataFrame(st.session_state.results)['severity'].value_counts()
        st.bar_chart(severity_data)
        
        st.markdown('### Engine Performance Trend')
        st.line_chart(df_hist.set_index('time')['latency'])
    else: st.info('Perform a scan to populate analytics.')

with t3:
    st.subheader('Unified Remediation Engine')
    if 'results' in st.session_state and st.session_state.results:
        for res in st.session_state.results:
            with st.expander(f"[{res['severity']}] {res['name']} - {res['Vector']}"):
                st.warning(f"**Logic Violation:** `{res['Snippet']}`")
                st.info(f"**Regex Signature:** `{res['pattern']}`")
                st.write(f"**Risk Explanation:** {res['explanation']}")
                st.success(f"**Security Patch:** {res['fix']}")
    else: st.info('No vulnerabilities detected.')

with t4:
    st.subheader('AI Model Training')
    with st.form('learn'):
        cat, name, pat, fix = st.text_input('Category'), st.text_input('Threat Name'), st.text_input('Regex Pattern'), st.text_area('Remediation Step')
        if st.form_submit_button('INTEGRATE SIGNATURE'):
            new_rule = {'name': name, 'pattern': pat, 'explanation': 'Custom signature.', 'fix': fix, 'severity': 'HIGH'}
            st.session_state.engine.vulnerability_map.setdefault(cat, []).append(new_rule)
            st.success('Kernel Updated Successfully.')

with t5:
    st.subheader('Regex Lab')
    t_s, t_r = st.text_input('Test Code Snippet'), st.text_input('Test Pattern', 'SELECT')
    if st.button('VALIDATE'):
        try:
            m = re.search(t_r, t_s, re.I | re.S)
            if m: st.error(f'MATCHED: {m.group(0)}')
            else: st.success('NO MATCH')
        except Exception as e: st.warning(f'Pattern Error: {e}')