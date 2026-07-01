
import streamlit as st
import re
import time
import json
import pandas as pd

st.set_page_config(page_title='CyberEnterprise Master Class v15.0', page_icon='🛡️', layout='wide')

class EnterpriseLogicEngine:
    def __init__(self):
        # 15-Vector Security Map - Fixed Regex Patterns
        self.vulnerability_map = {
            '1. Injection': [
                {'name': 'Advanced SQLi', 'pattern': r'(SELECT|INSERT|UPDATE|DELETE|UNION|DROP|EXEC|CAST|CONVERT).*?([\s\+\$\%{]).*?[\x27\x22]', 'explanation': 'SQL injection via string concatenation.', 'fix': 'Enforce parameterized queries.', 'severity': 'CRITICAL'},
                {'name': 'Shell Command Injection', 'pattern': r'(os\.system|subprocess|exec|eval|system|popen|shutil|spawn)\(.*?([\+\%]|f[\"\x27\\\\]).+?\)', 'explanation': 'Shell-level execution vulnerabilities.', 'fix': 'Avoid shell=True; use list-based arguments.', 'severity': 'CRITICAL'}
            ],
            '2. Web Logic': [
                {'name': 'XSS (DOM/Reflected)', 'pattern': r'(\.(innerHTML|outerHTML|srcdoc)\s*=|document\.write\(|alert\(|eval\(.*?location)', 'explanation': 'Untrusted data rendered as HTML.', 'fix': 'Utilize .textContent.', 'severity': 'HIGH'}
            ],
            '3. Auth': [
                {'name': 'Hardcoded Credentials', 'pattern': r'(password|passwd|secret|token|apikey|aws_key|private_key)\s*[:=]\s*[\x27\x22][a-zA-Z0-9_\-]{5,}[\x27\x22]', 'explanation': 'Plaintext secrets detected.', 'fix': 'Migrate secrets to environment variables.', 'severity': 'CRITICAL'}
            ],
            '4. AI Safety': [
                {'name': 'Insecure Deserialization', 'pattern': r'(pickle\.load\(|joblib\.load\(|yaml\.load\(.*?Loader=)', 'explanation': 'Loading untrusted data into objects.', 'fix': 'Use safe loaders (json.loads).', 'severity': 'HIGH'}
            ],
            '5. Cloud': [
                {'name': 'Metadata Leakage', 'pattern': r'(169\.254\.169\.254|s3://.*?/|\.s3\.amazonaws\.com)', 'explanation': 'Exposure of cloud provider metadata.', 'fix': 'Enforce IMDSv2.', 'severity': 'HIGH'}
            ],
            '6. Crypto': [
                {'name': 'Weak Primitives', 'pattern': r'(hashlib\.md5|hashlib\.sha1|DES|RC4|blowfish)', 'explanation': 'Use of compromised algorithms.', 'fix': 'Upgrade to SHA-256/3.', 'severity': 'HIGH'}
            ],
            '7. Memory': [
                {'name': 'Buffer Operations', 'pattern': r'(strcpy|strcat|sprintf|gets|memcpy|malloc)\(', 'explanation': 'Unsafe memory operations.', 'fix': 'Use bounds-checked functions.', 'severity': 'MEDIUM'}
            ],
            '8. API': [
                {'name': 'JWT Misconfig', 'pattern': r'(jwt\.decode\(.*?verify=False|algorithm=[\"\x27]none[\"\x27])', 'explanation': 'Bypassing signature verification.', 'fix': 'Enforce signature verification.', 'severity': 'CRITICAL'}
            ],
            '9. Supply Chain': [
                {'name': 'Insecure Dependency', 'pattern': r'(curl.*?\|.*?bash|pip install.*?--extra-index-url)', 'explanation': 'Downloading unverified packages.', 'fix': 'Use pinned versions with hashes.', 'severity': 'HIGH'}
            ],
            '10. PII': [
                {'name': 'Data Exposure', 'pattern': r'(email|ssn|phone|credit_card|social_security)\s*[:=]', 'explanation': 'Unmasked handling of PII.', 'fix': 'Implement encryption.', 'severity': 'MEDIUM'}
            ],
            '11. NoSQL': [
                {'name': 'Operator Injection', 'pattern': r'(\$where|\$ne|\$gt|\$regex|\$exists)', 'explanation': 'Injecting NoSQL logical operators.', 'fix': 'Sanitize input for NoSQL query operators.', 'severity': 'HIGH'}
            ],
            '12. Business': [
                {'name': 'Race Conditions', 'pattern': r'(threading\.Thread|asyncio\.create_task).*?(\+=|\-=)', 'explanation': 'Concurrent state updates without atomicity.', 'fix': 'Implement threading.Lock().', 'severity': 'MEDIUM'}
            ],
            '13. Paths': [
                {'name': 'LFI/Traversal', 'pattern': r'(\.\./|\.\.\\|/etc/passwd|/proc/|/windows/win\.ini)', 'explanation': 'Accessing files outside application root.', 'fix': 'Use os.path.basename().', 'severity': 'HIGH'}
            ],
            '14. Container': [
                {'name': 'Privileged Flag', 'pattern': r'(privileged:\s*true|hostNetwork:\s*true)', 'explanation': 'Container configs exposing host kernel.', 'fix': 'Run as non-root.', 'severity': 'HIGH'}
            ],
            '15. Blockchain': [
                {'name': 'Reentrancy', 'pattern': r'(msg\.sender\.call|transfer\(|lock_state).*?(\-=|\+=)', 'explanation': 'External calls before state updates.', 'fix': 'Follow Checks-Effects-Interactions.', 'severity': 'CRITICAL'}
            ]
        }

    def scan(self, code):
        findings = []
        start = time.perf_counter()
        for category, rules in self.vulnerability_map.items():
            for rule in rules:
                if re.search(rule['pattern'], code, re.IGNORECASE | re.DOTALL):
                    findings.append({'VectorID': category.split('.')[0], 'Category': category, **rule})
        return findings, time.perf_counter() - start

if 'engine' not in st.session_state:
    st.session_state.engine = EnterpriseLogicEngine()

st.title('🛡️ CyberEnterprise Master Class')
st.markdown("v15.0 | Stable Deployment Build")

tab1, tab2, tab3, tab4 = st.tabs(['🔍 Scanner', '📊 Analytics', '📋 Remediation (JSON)', '🧪 Precision Debugger'])

with tab1:
    code_input = st.text_area('Input Code:', height=300, placeholder='Paste code for 15-vector deep inspection...')
    if st.button('INITIATE DEEP SCAN'):
        if code_input:
            results, latency = st.session_state.engine.scan(code_input)
            st.session_state.results = results
            st.session_state.latency = latency
            if results: st.error(f'Threats Detected: {len(results)}')
            else: st.success('System Secure Across All 15 Vectors.')

with tab2:
    if 'latency' in st.session_state:
        st.subheader('System Performance Metrics')
        m1, m2 = st.columns(2)
        m1.metric('Scan Latency', f"{st.session_state.latency:.6f}s")
        m2.metric('Peak Throughput', f"{1/(st.session_state.latency + 1e-9):,.0f} sigs/sec")

with tab3:
    st.subheader('Precision Remediation Report')
    if 'results' in st.session_state and st.session_state.results:
        st.json(st.session_state.results)
    else: st.info('Perform a scan to generate a structured JSON report.')

with tab4:
    st.subheader('🧪 Precision Signature Debugger')
    test_line = st.text_input('Fragment:', placeholder='e.g. query = "SELECT * FROM..." + id')
    test_regex = st.text_input('Signature:', value=r'(SELECT|INSERT|UPDATE|DELETE).*?([\s\+\$\%{]).*?[\x27\x22]')
    if st.button('VALIDATE'):
        if test_line and test_regex:
            try:
                match = re.search(test_regex, test_line, re.IGNORECASE | re.DOTALL)
                if match:
                    st.error('🚨 SIGNATURE MATCH')
                    st.code(f'Matched Fragment: {match.group(0)}')
                else: st.success('✅ NO MATCH')
            except Exception as e: st.warning(f'Regex Error: {e}')
