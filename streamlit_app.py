import streamlit as st
import re
import time
import pandas as pd
import numpy as np
import sqlite3
import os

st.set_page_config(page_title='Cyber AI v18.1 Pro', page_icon='🛡️', layout='wide')

# --- Database Persistence Layer ---
def init_db():
    conn = sqlite3.connect('cyber_vault.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS custom_sigs
                 (category TEXT, name TEXT, pattern TEXT, explanation TEXT, fix TEXT, severity TEXT)''')
    conn.commit()
    return conn

# --- Full Enterprise Engine v18.1 ---
class CyberEngineV18:
    def __init__(self):
        self.vulnerability_map = {
            '1. Injection & Input': [
                {'name': 'Advanced SQLi', 'pattern': r'(SELECT|INSERT|UPDATE|DELETE|UNION|DROP|EXEC|CAST|CONVERT).*?([\s\+\\%{]).*?[\x27\x22]', 'explanation': 'Complex SQL injection vectors via string concatenation.', 'fix': 'Enforce strictly parameterized queries.', 'severity': 'CRITICAL'},
                {'name': 'NoSQL Injection', 'pattern': r'(\$where|\$ne|\$gt|\$regex|\$exists)', 'explanation': 'Untrusted data modifying NoSQL logical operators.', 'fix': 'Sanitize keys using schema validation.', 'severity': 'HIGH'}
            ],
            '2. Command & Shell': [
                {'name': 'OS Command Injection', 'pattern': r'(os\.system|subprocess|exec|system|popen|shutil|spawn)\(.*?([+\\%]|f[\"\x27\\\\]).+?\)', 'explanation': 'Execution of system commands with variable inputs.', 'fix': 'Pass arguments as a list with shell=False.', 'severity': 'CRITICAL'}
            ],
            '3. Cross-Site Scripting': [
                {'name': 'DOM-Based XSS', 'pattern': r'(\.(innerHTML|outerHTML|srcdoc)\s*=|document\.write\(|alert\(|eval\(.*?location)', 'explanation': 'Injecting user input into the browser DOM.', 'fix': 'Use .textContent or .innerText.', 'severity': 'HIGH'}
            ],
            '4. Authentication': [
                {'name': 'Hardcoded Credentials', 'pattern': r'(password|passwd|secret|token|apikey|aws_key|private_key)\s*[:=]\s*[\x27\x22][a-zA-Z0-9_\-]{5,}[\x27\x22]', 'explanation': 'Sensitive secrets found in source code.', 'fix': 'Use secret managers or environment variables.', 'severity': 'CRITICAL'}
            ],
            '5. AI & Data Safety': [
                {'name': 'Insecure Deserialization', 'pattern': r'(pickle\.load\(|joblib\.load\(|yaml\.load\(.*?Loader=)', 'explanation': 'Loading untrusted data into objects.', 'fix': 'Use safe loaders like json.loads().', 'severity': 'HIGH'}
            ],
            '6. Cloud Infrastructure': [
                {'name': 'Metadata Leakage', 'pattern': r'(169\.254\.169\.254|s3://.*?/|\.s3\.amazonaws\.com)', 'explanation': 'Exposure of cloud provider metadata.', 'fix': 'Enforce IMDSv2.', 'severity': 'HIGH'}
            ],
            '7. Cryptography': [
                {'name': 'Weak Primitives', 'pattern': r'(hashlib\.md5|hashlib\.sha1|DES|RC4|blowfish)', 'explanation': 'Use of compromised algorithms.', 'fix': 'Upgrade to SHA-256 or AES-GCM.', 'severity': 'HIGH'}
            ],
            '8. Memory Safety': [
                {'name': 'Buffer Operations', 'pattern': r'(strcpy|strcat|sprintf|gets|memcpy|malloc)\(', 'explanation': 'Unsafe memory operations.', 'fix': 'Use bounds-checked functions.', 'severity': 'MEDIUM'}
            ],
            '9. API Security': [
                {'name': 'JWT Misconfig', 'pattern': r'(jwt\.decode\(.*?verify=False|algorithm=[\"\x27]none[\"\x27])', 'explanation': 'Bypassing signature verification.', 'fix': 'Enforce signature verification.', 'severity': 'CRITICAL'}
            ],
            '10. Supply Chain': [
                {'name': 'Insecure Dependency', 'pattern': r'(curl.*?\|.*?bash|pip install.*?--extra-index-url)', 'explanation': 'Downloading unverified packages.', 'fix': 'Use pinned versions with hashes.', 'severity': 'HIGH'}
            ],
            '11. PII Compliance': [
                {'name': 'PII Data Exposure', 'pattern': r'(email|ssn|phone|credit_card|social_security)\s*[:=]', 'explanation': 'Unmasked handling of PII.', 'fix': 'Implement encryption at rest.', 'severity': 'MEDIUM'}
            ],
            '12. Business Logic': [
                {'name': 'Race Conditions', 'pattern': r'(threading\.Thread|asyncio\.create_task).*?(\+=|\-=)', 'explanation': 'Concurrent updates without atomicity.', 'fix': 'Implement Mutex/Locks.', 'severity': 'MEDIUM'}
            ],
            '13. Path Handling': [
                {'name': 'Path Traversal', 'pattern': r'(\.\./|\.\.\\|/etc/passwd|/proc/|/windows/win\.ini)', 'explanation': 'Accessing files outside application root.', 'fix': 'Use os.path.basename().', 'severity': 'HIGH'}
            ],
            '14. Container Security': [
                {'name': 'Privileged Flag', 'pattern': r'(privileged:\s*true|hostNetwork:\s*true)', 'explanation': 'Container exposing host kernel.', 'fix': 'Run as non-root user.', 'severity': 'HIGH'}
            ],
            '15. Blockchain Logic': [
                {'name': 'Reentrancy Attack', 'pattern': r'(msg\.sender\.call|transfer\(|lock_state).*?(\-=|\+=)', 'explanation': 'External calls before state updates.', 'fix': 'Follow Checks-Effects-Interactions pattern.', 'severity': 'CRITICAL'}
            ]
        }

    def scan(self, code):
        findings = []
        seen_signatures = set()
        start = time.perf_counter()
        # Core Scan
        for category, rules in self.vulnerability_map.items():
            for rule in rules:
                try:
                    matches = re.finditer(rule['pattern'], code, re.IGNORECASE | re.MULTILINE | re.DOTALL)
                    for match in matches:
                        snippet = match.group(0).strip()
                        sig = f"{rule['name']}:{snippet}"
                        if sig not in seen_signatures:
                            findings.append({'Vector': category, 'Snippet': snippet, **rule})
                            seen_signatures.add(sig)
                except: continue
        # Persistence Scan
        try:
            conn = sqlite3.connect('cyber_vault.db')
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM custom_sigs")
            for row in cursor.fetchall():
                if re.search(row[2], code, re.I | re.S):
                    findings.append({'Vector': row[0], 'Snippet': 'Custom Match', 'name': row[1], 'pattern': row[2], 'explanation': row[3], 'fix': row[4], 'severity': row[5]})
            conn.close()
        except: pass

        latency = time.perf_counter() - start
        risk_score = min(len(findings) * 15, 100)
        return findings, latency, risk_score

init_db()
if 'engine' not in st.session_state: st.session_state.engine = CyberEngineV18()
if 'history' not in st.session_state: st.session_state.history = []

st.title('🛡️ Cyber AI v18.1 Pro: Global Security Node')

t1, t2, t3, t4, t5 = st.tabs(['🔍 Deep Scanner', '📊 Analytics Dashboard', '📋 Remediation Core', '🧠 AI Learning', '🧪 Kernel Debugger'])

with t1:
    code_in = st.text_area('Input Code Logic:', height=350, placeholder="Paste source code here for multi-vector audit...")
    if st.button('INITIATE DEEP SYSTEM AUDIT'):
        if code_in:
            results, latency, risk = st.session_state.engine.scan(code_in)
            st.session_state.results = results
            st.session_state.risk = risk
            st.session_state.latency = latency
            st.session_state.history.append(latency)
            if results: st.error(f'Unique Threats Identified: {len(results)} | Risk Level: {risk}/100')
            else: st.success('System Secure Across All 15 Vectors.')

with t2:
    st.subheader('Enterprise Security Analytics')
    if 'results' in st.session_state:
        c1, c2 = st.columns(2)
        c1.metric('Risk Rating', f"{st.session_state.risk}/100")
        c2.metric('Engine Latency', f"{st.session_state.latency:.6f}s")
        st.markdown('### Severity Breakdown')
        st.bar_chart(pd.DataFrame(st.session_state.results)['severity'].value_counts())

with t3:
    st.subheader('Architectural Remediation Dashboard')
    if 'results' in st.session_state and st.session_state.results:
        for res in st.session_state.results:
            with st.expander(f"[{res['severity']}] {res['name']} - Vector: {res['Vector']}"):
                st.error(f"**Trigger Snippet:** `{res['Snippet']}`")
                st.info(f"**Regex Signature:** `{res['pattern']}`")
                st.write(f"**Logic Flaw:** {res['explanation']}")
                st.success(f"**Secure Patch:** {res['fix']}")

with t4:
    st.subheader('AI Learning Core')
    with st.form('learn'):
        cat, name, pat, exp, fix, sev = st.text_input('Vector Category'), st.text_input('Threat Name'), st.text_input('Regex Signature'), st.text_area('Explanation'), st.text_area('Patch Instructions'), st.selectbox('Severity', ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'])
        if st.form_submit_button('INTEGRATE INTO KERNEL'):
            conn = sqlite3.connect('cyber_vault.db')
            cursor = conn.cursor()
            cursor.execute("INSERT INTO custom_sigs VALUES (?,?,?,?,?,?)", (cat, name, pat, exp, fix, sev))
            conn.commit()
            conn.close()
            st.success('Kernel Heuristics Updated and Persisted.')

with t5:
    st.subheader('Regex Lab Debugger')
    t_code = st.text_area('Test Snippet')
    t_reg = st.text_input('Test Regex', value='SELECT')
    if st.button('VALIDATE'):
        try:
            m = re.search(t_reg, t_code, re.I | re.S)
            if m: st.error(f'MATCH: {m.group(0)}')
            else: st.success('NO MATCH')
        except Exception as e: st.warning(f'Pattern Error: {e}')

st.sidebar.info("● CORE: ONLINE\n● VECTORS: 15 ACTIVE\n● PERSISTENCE: SQLITE ACTIVE\n● MODE: PRO v18.1")
