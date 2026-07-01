import streamlit as st
import pandas as pd
import numpy as np
import re
import time
import sqlite3
import json
import os

# --- System Configuration ---
st.set_page_config(page_title='Cyber AI v18.1 Pro', page_icon='🛡️', layout='wide')

# --- Database Persistence Layer ---
def init_db():
    conn = sqlite3.connect('cyber_vault.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS custom_sigs 
                 (category TEXT, name TEXT, pattern TEXT, explanation TEXT, fix TEXT, severity TEXT)''')
    conn.commit()
    return conn

# --- Enterprise Engine v18.1 ---
class ProSecurityEngine:
    def __init__(self):
        self.core_vectors = {
            '1. Injection': [
                {'name': 'Advanced SQLi', 'pattern': r'(SELECT|INSERT|UPDATE|DELETE|UNION|DROP|EXEC|CAST|CONVERT).*?([\\s\\+\\\\%{]).*?[\\x27\\x22]', 'explanation': 'Complex SQL injection via string concatenation.', 'fix': 'Use parameterized queries (bind variables).', 'severity': 'CRITICAL'},
                {'name': 'NoSQL Injection', 'pattern': r'(\\$where|\\$ne|\\$gt|\\$regex|\\$exists)', 'explanation': 'NoSQL operator manipulation detected.', 'fix': 'Sanitize keys using schema validation.', 'severity': 'HIGH'}
            ],
            '2. Command & Shell': [
                {'name': 'OS Command Injection', 'pattern': r'(os\\.system|subprocess|exec|system|popen|shutil|spawn)\\(.*?([+\\\\%]|f[\\"\\x27\\\\\\\\]).+?\\)', 'explanation': 'Execution of system commands with variable inputs.', 'fix': 'Use subprocess.run(args, shell=False).', 'severity': 'CRITICAL'}
            ],
            '3. Cross-Site Scripting': [
                {'name': 'DOM-Based XSS', 'pattern': r'(\\.(innerHTML|outerHTML|srcdoc)\\s*=|document\\.write\\(|alert\\(|eval\\(.*?location)', 'explanation': 'Unsafe rendering of user input into the browser DOM.', 'fix': 'Use .textContent or .innerText.', 'severity': 'HIGH'}
            ],
            '4. Authentication': [
                {'name': 'Hardcoded Secrets', 'pattern': r'(password|passwd|secret|token|apikey|aws_key|private_key)\\s*[:=]\\s*[\\x27\\x22][a-zA-Z0-9_\\-]{5,}[\\x27\\x22]', 'explanation': 'Sensitive credentials hardcoded in source.', 'fix': 'Utilize environment variables or KMS.', 'severity': 'CRITICAL'}
            ],
            '5. AI Safety': [
                {'name': 'Insecure Deserialization', 'pattern': r'(pickle\\.load\\(|joblib\\.load\\(|yaml\\.load\\(.*?Loader=)', 'explanation': 'Loading untrusted data into Python objects.', 'fix': 'Use safe JSON-based loaders.', 'severity': 'HIGH'}
            ],
            '6. Cloud Infrastructure': [
                {'name': 'IMDS Metadata Leak', 'pattern': r'(169\\.254\\.169\\.254|s3://.*?/|\\.s3\\.amazonaws\\.com)', 'explanation': 'Exposure of internal cloud metadata endpoints.', 'fix': 'Enforce IMDSv2.', 'severity': 'HIGH'}
            ],
            '7. Cryptography': [
                {'name': 'Weak Primitives', 'pattern': r'(hashlib\\.md5|hashlib\\.sha1|DES|RC4|blowfish)', 'explanation': 'Use of compromised or legacy algorithms.', 'fix': 'Upgrade to SHA-256 or AES-GCM.', 'severity': 'HIGH'}
            ],
            '8. Memory Safety': [
                {'name': 'Unsafe Buffer Ops', 'pattern': r'(strcpy|strcat|sprintf|gets|memcpy|malloc)\\(', 'explanation': 'Functions susceptible to buffer overflows.', 'fix': 'Use bounds-checked equivalents.', 'severity': 'MEDIUM'}
            ],
            '9. API Security': [
                {'name': 'JWT Verify Bypass', 'pattern': r'(jwt\\.decode\\(.*?verify=False|algorithm=[\\"\\x27]none[\\"\\x27])', 'explanation': 'Accepting tokens without signature validation.', 'fix': 'Always enforce algorithm verification.', 'severity': 'CRITICAL'}
            ],
            '10. Supply Chain': [
                {'name': 'Unverified Fetch', 'pattern': r'(curl.*?\\|.*?bash|pip install.*?--extra-index-url)', 'explanation': 'Downloading packages from unverified indices.', 'fix': 'Use pinned versions with sha256 hashes.', 'severity': 'HIGH'}
            ],
            '11. PII Compliance': [
                {'name': 'PII Data Leak', 'pattern': r'(email|ssn|phone|credit_card|social_security)\\s*[:=]', 'explanation': 'Processing PII in unmasked formats.', 'fix': 'Implement encryption at rest/transit.', 'severity': 'MEDIUM'}
            ],
            '12. Business Logic': [
                {'name': 'Race Condition', 'pattern': r'(threading\\.Thread|asyncio\\.create_task).*?(\\+=|\\-=)', 'explanation': 'Concurrent state updates without atomicity.', 'fix': 'Implement Mutex/Locks.', 'severity': 'MEDIUM'}
            ],
            '13. Path Handling': [
                {'name': 'LFI/Path Traversal', 'pattern': r'(\\.\\./|\\.\\\\\\.|/etc/passwd|/proc/|/windows/win\\.ini)', 'explanation': 'Accessing files outside application scope.', 'fix': 'Use os.path.basename().', 'severity': 'HIGH'}
            ],
            '14. Container Security': [
                {'name': 'Privileged Flag', 'pattern': r'(privileged:\\s*true|hostNetwork:\\s*true)', 'explanation': 'Container has direct host kernel access.', 'fix': 'Run as non-root user.', 'severity': 'HIGH'}
            ],
            '15. Blockchain': [
                {'name': 'Reentrancy Logic', 'pattern': r'(msg\\.sender\\.call|transfer\\(|lock_state).*?(\\-=|\\+=)', 'explanation': 'External call before internal state update.', 'fix': 'Follow Checks-Effects-Interactions.', 'severity': 'CRITICAL'}
            ]
        }

    def scan(self, code):
        findings = []
        seen = set()
        start = time.perf_counter()
        
        # Check Core Vectors
        for cat, rules in self.core_vectors.items():
            for rule in rules:
                matches = re.finditer(rule['pattern'], code, re.M | re.S | re.I)
                for m in matches:
                    snippet = m.group(0).strip()
                    sig_id = f"{rule['name']}:{snippet}"
                    if sig_id not in seen:
                        findings.append({'Vector': cat, 'Snippet': snippet, **rule})
                        seen.add(sig_id)
        
        # Check Custom Signatures from DB
        try:
            conn = sqlite3.connect('cyber_vault.db')
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM custom_sigs")
            for row in cursor.fetchall():
                if re.search(row[2], code, re.I | re.S):
                    findings.append({
                        'Vector': row[0], 'name': row[1], 'pattern': row[2],
                        'explanation': row[3], 'fix': row[4], 'severity': row[5], 'Snippet': 'Custom Match'
                    })
            conn.close()
        except: pass

        latency = time.perf_counter() - start
        risk = min(len(findings) * 12, 100)
        return findings, latency, risk

# --- App Logic ---
if 'engine' not in st.session_state: st.session_state.engine = ProSecurityEngine()
if 'audit_results' not in st.session_state: st.session_state.audit_results = []

init_db()

st.title('🛡️ Cyber AI v18.1 Pro: Enterprise Node')

t1, t2, t3, t4, t5 = st.tabs(['🔍 AI Scanner', '📊 Security Analytics', '📋 Remediation Engine', '🧠 Learning Core', '🧪 Debugger'])

with t1:
    src = st.text_area('Input Source Code:', height=350, placeholder='Paste code for 15-vector deep inspection...')
    if st.button('INITIATE SECURITY AUDIT', use_container_width=True):
        if src:
            results, latency, risk = st.session_state.engine.scan(src)
            st.session_state.audit_results = results
            st.session_state.risk = risk
            st.session_state.latency = latency
            if results:
                st.error(f"THREATS DETECTED: {len(results)} | RISK SCORE: {risk}/100")
            else:
                st.success("SYSTEM SECURE ACROSS ALL CORE VECTORS.")

with t2:
    st.subheader("Enterprise Analytics Dashboard")
    if st.session_state.audit_results:
        df = pd.DataFrame(st.session_state.audit_results)
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("**Severity Distribution**")
            st.bar_chart(df['severity'].value_counts())
        with col2:
            st.markdown("**Vector Distribution**")
            st.table(df['Vector'].value_counts())
        st.metric("Analysis Latency", f"{st.session_state.latency:.6f}s")
    else: st.info("Execute a scan to generate telemetry.")

with t3:
    st.subheader("Remediation & Patch Core")
    if st.session_state.audit_results:
        for item in st.session_state.audit_results:
            with st.expander(f"[{item['severity']}] {item['name']}"):
                st.error(f"**Trigger Snippet:** `{item['Snippet']}`")
                st.info(f"**Regex Signature:** `{item['pattern']}`")
                st.write(f"**Reasoning:** {item['explanation']}")
                st.success(f"**Recommended Fix:** {item['fix']}")
    else: st.info("No active threats to remediate.")

with t4:
    st.subheader("AI Knowledge Integration")
    with st.form("learn"):
        c1, c2 = st.columns(2)
        l_cat = c1.text_input('Vector Category')
        l_name = c2.text_input('Vulnerability Name')
        l_pat = st.text_input('Regex Pattern')
        l_exp = st.text_area('Explanation')
        l_fix = st.text_area('Secure Patch')
        l_sev = st.selectbox('Severity', ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'])
        
        if st.form_submit_button("COMMIT TO KERNEL"):
            conn = sqlite3.connect('cyber_vault.db')
            cursor = conn.cursor()
            cursor.execute("INSERT INTO custom_sigs VALUES (?,?,?,?,?,?)", (l_cat, l_name, l_pat, l_exp, l_fix, l_sev))
            conn.commit()
            conn.close()
            st.success("Kernel Memory Updated.")

with t5:
    st.subheader("Regex Signature Lab")
    test_s = st.text_area("Test Snippet")
    test_p = st.text_input("Regex Pattern", value="SELECT")
    if st.button("VALIDATE PATTERN"):
        m = re.search(test_p, test_s, re.I | re.S)
        if m: st.error(f"MATCH FOUND: {m.group(0)}")
        else: st.success("NO MATCH DETECTED")

st.sidebar.markdown(f"""
**Node Status:** ONLINE  
**Core Version:** 18.1 Pro  
**Vectors:** 15 Active  
**Persistence:** SQLite Active
""")
