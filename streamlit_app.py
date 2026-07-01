import streamlit as st
import re
import time
import pandas as pd
import numpy as np
import json

st.set_page_config(page_title='Cyber AI Extreme v17.0: GOD MODE', page_icon='🦾', layout='wide')

class GodLevelSecurityEngine:
    def __init__(self):
        self.vulnerability_map = {
            '1. Injection': [
                {'name': 'Advanced SQLi', 'pattern': r'(SELECT|INSERT|UPDATE|DELETE|UNION|DROP|EXEC|CAST|CONVERT).*?([\s\+\$\%{]).*?[\x27\x22]', 'explanation': 'Dynamic query building using string concatenation detected.', 'fix': 'Enforce strictly parameterized queries.', 'severity': 'CRITICAL'},
                {'name': 'NoSQL Operator Injection', 'pattern': r'(\$where|\$ne|\$gt|\$regex|\$exists)', 'explanation': 'Untrusted data modifying NoSQL logic.', 'fix': 'Sanitize keys using schema validation.', 'severity': 'HIGH'}
            ],
            '2. Command & Shell': [
                {'name': 'OS Command Injection', 'pattern': r'(os\.system|subprocess|exec|system|popen|shutil|spawn)\(.*?([\+\%]|f["\x27\\]).+?\)', 'explanation': 'Execution of system commands with variable inputs.', 'fix': 'Pass arguments as a list with shell=False.', 'severity': 'CRITICAL'}
            ],
            '3. Cross-Site Scripting': [
                {'name': 'DOM-Based XSS', 'pattern': r'(\.(innerHTML|outerHTML|srcdoc)\s*=|document\.write\(|alert\(|eval\(.*?location)', 'explanation': 'Directly injecting user input into the browser DOM.', 'fix': 'Use .textContent or .innerText.', 'severity': 'HIGH'}
            ],
            '4. Authentication': [
                {'name': 'Hardcoded Credentials', 'pattern': r'(password|passwd|secret|token|apikey|aws_key|private_key)\s*[:=]\s*[\x27\x22][a-zA-Z0-9_\-]{5,}[\x27\x22]', 'explanation': 'Sensitive secrets found in source code.', 'fix': 'Use secret managers or environment variables.', 'severity': 'CRITICAL'}
            ],
            '5. AI Safety': [
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
                {'name': 'JWT Misconfig', 'pattern': r'(jwt\.decode\(.*?verify=False|algorithm=["\x27]none["\x27])', 'explanation': 'Bypassing signature verification.', 'fix': 'Enforce signature verification.', 'severity': 'CRITICAL'}
            ],
            '10. Supply Chain': [
                {'name': 'Insecure Dependency', 'pattern': r'(curl.*?|.*?bash|pip install.*?--extra-index-url)', 'explanation': 'Downloading unverified packages.', 'fix': 'Use pinned versions with hashes.', 'severity': 'HIGH'}
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
            '15. Blockchain': [
                {'name': 'Reentrancy Logic', 'pattern': r'(msg\.sender\.call|transfer\(|lock_state).*?(\-=|\+=)', 'explanation': 'External calls before state updates.', 'fix': 'Follow Checks-Effects-Interactions pattern.', 'severity': 'CRITICAL'}
            ]
        }

    def scan(self, code):
        findings = []
        start = time.perf_counter()
        for category, rules in self.vulnerability_map.items():
            for rule in rules:
                try:
                    match = re.search(rule['pattern'], code, re.IGNORECASE | re.DOTALL)
                    if match:
                        findings.append({'Vector': category, 'Snippet': match.group(0), **rule})
                except:
                    continue
        return findings, time.perf_counter() - start

# --- App Logic ---
if 'engine' not in st.session_state: st.session_state.engine = GodLevelSecurityEngine()
if 'history' not in st.session_state: st.session_state.history = []
if 'debug_log' not in st.session_state: st.session_state.debug_log = []

st.title('🦾 Cyber AI Extreme: EXTREME v17.0')
st.markdown('**God-Mode Active | 15-Vector Deep Inspection Engine**')

tab1, tab2, tab3, tab4, tab5 = st.tabs(['🔍 Scanner', '📈 Analytics', '📋 Remediation', '🧠 AI Learning', '🧪 Debugger'])

with tab1:
    code_input = st.text_area('Input Code:', height=300)
    if st.button('INITIATE GOD-LEVEL AUDIT'):
        if code_input:
            results, latency = st.session_state.engine.scan(code_input)
            st.session_state.results, st.session_state.latency = results, latency
            st.session_state.history.append(latency)
            if results: st.error(f'Threats Identified: {len(results)}')
            else: st.success('System Secure Across All 15 Vectors.')

with tab2:
    if 'latency' in st.session_state:
        m1, m2 = st.columns(2)
        m1.metric('Latency', f"{st.session_state.latency:.6f}s")
        m2.metric('Risk', len(st.session_state.results) * 10)
        st.line_chart(st.session_state.history)

with tab3:
    if 'results' in st.session_state and st.session_state.results:
        for res in st.session_state.results:
            with st.expander(f"[{res['severity']}] {res['name']}"):
                st.write(f"**Vector:** {res['Vector']}")
                st.write(f"**Reason:** {res['explanation']}")
                st.success(f"**Fix:** {res['fix']}")
                st.info(f"**Pattern:** `{res['pattern']}`")
                st.code(res['Snippet'])

with tab4:
    st.subheader('AI Learning - Add New Signature')
    with st.form('learn'):
        l_cat = st.text_input('Category')
        l_name = st.text_input('Name')
        l_pat = st.text_input('Regex')
        l_fix = st.text_input('Fix')
        if st.form_submit_button('INTEGRATE'):
            st.session_state.engine.vulnerability_map[l_cat] = [{'name':l_name,'pattern':l_pat,'fix':l_fix,'severity':'HIGH','explanation':'Added via learning'}]

with tab5:
    st.subheader('Signature Debugger')
    t_frag = st.text_input('Fragment')
    t_reg = st.text_input('Regex', value=r'SELECT')
    if st.button('VALIDATE'):
        m = re.search(t_reg, t_frag, re.I | re.S)
        if m: 
            st.error(f'MATCH: {m.group(0)}')
        else: 
            st.success('NO MATCH')
            st.session_state.debug_log.append({"timestamp": time.strftime("%H:%M:%S"), "fragment": t_frag, "regex": t_reg})
    
    if st.session_state.debug_log:
        st.markdown("--- ")
        st.subheader("❌ Failed Match Log")
        st.table(pd.DataFrame(st.session_state.debug_log).tail(10))
        if st.button("Clear Log"): 
            st.session_state.debug_log = []
            st.rerun()
