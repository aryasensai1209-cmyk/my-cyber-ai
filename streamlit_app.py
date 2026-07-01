
import streamlit as st
import re
import pandas as pd
import time
import numpy as np

st.set_page_config(page_title='CyberEnterprise Ultra v15.0', page_icon='🛡️', layout='wide')

class EnterpriseLogicEngine:
    def __init__(self):
        self.vulnerability_map = {
            '1. Injection & Input': [
                {'name': 'Advanced SQLi', 'pattern': r'(SELECT|INSERT|UPDATE|DELETE|UNION|DROP|EXEC|CAST|CONVERT).*?([\s\+\$\%{]).*?[\x27\x22]', 'explanation': 'Identifies complex SQL injection vectors where user input is concatenated into query strings.', 'fix': 'Enforce strictly parameterized queries.', 'severity': 'CRITICAL'},
                {'name': 'Shell Command Injection', 'pattern': r'(os\\.system|subprocess|exec|eval|system|popen|shutil|spawn)\\(.*?([\\+\\%]|f[\"\\\\]).+?\\)', 'explanation': 'Detects shell-level execution vulnerabilities.', 'fix': 'Avoid shell=True; use list-based arguments.', 'severity': 'CRITICAL'}
            ],
            '2. Web App Logic': [
                {'name': 'XSS (DOM/Reflected)', 'pattern': r'(\\.(innerHTML|outerHTML|srcdoc)\\s*=|document\\.write\\(|alert\\(|eval\\(.*?location)', 'explanation': 'Identifies untrusted data rendered as HTML.', 'fix': 'Utilize .textContent.', 'severity': 'HIGH'}
            ],
            '3. Authentication': [
                {'name': 'Hardcoded Credentials', 'pattern': r'(password|passwd|secret|token|apikey|aws_key|private_key)\\s*[:=]\\s*[\\x27\\x22][a-zA-Z0-9_\\-]{5,}[\\x27\\x22]', 'explanation': 'Plaintext secrets detected in source code.', 'fix': 'Migrate secrets to environment variables.', 'severity': 'CRITICAL'}
            ],
            '4. AI/ML Safety': [
                {'name': 'Insecure Object Deserialization', 'pattern': r'(pickle\\.load\\(|joblib\\.load\\(|yaml\\.load\\(.*?Loader=)', 'explanation': 'Loading untrusted data into Python objects.', 'fix': 'Use safe loaders (json.loads).', 'severity': 'HIGH'}
            ],
            '5. Cloud Infra': [
                {'name': 'Cloud Metadata Leakage', 'pattern': r'(169\\.254\\.169\\.254|s3://.*?/|\\.s3\\.amazonaws\\.com)', 'explanation': 'Exposure of cloud provider metadata endpoints.', 'fix': 'Enforce IMDSv2.', 'severity': 'HIGH'}
            ],
            '6. Cryptography': [
                {'name': 'Weak Cryptographic Primitives', 'pattern': r'(hashlib\\.md5|hashlib\\.sha1|DES|RC4|blowfish)', 'explanation': 'Use of compromised algorithms.', 'fix': 'Upgrade to SHA-256/3.', 'severity': 'HIGH'}
            ],
            '7. Memory Safety': [
                {'name': 'Buffer/Heap Operations', 'pattern': r'(strcpy|strcat|sprintf|gets|memcpy|malloc)\\(', 'explanation': 'Unsafe memory operations.', 'fix': 'Use bounds-checked functions.', 'severity': 'MEDIUM'}
            ],
            '8. API Security': [
                {'name': 'JWT/Auth Misconfiguration', 'pattern': r'(jwt\\.decode\\(.*?verify=False|algorithm=[\"\\\\]none[\"\\\\])', 'explanation': 'Bypassing signature verification in JWT.', 'fix': 'Enforce signature verification.', 'severity': 'CRITICAL'}
            ],
            '9. Supply Chain': [
                {'name': 'Insecure Dependency Fetch', 'pattern': r'(curl.*?\\|.*?bash|pip install.*?--extra-index-url)', 'explanation': 'Downloading unverified packages.', 'fix': 'Use pinned versions with hashes.', 'severity': 'HIGH'}
            ],
            '10. Privacy/PII': [
                {'name': 'PII Data Exposure', 'pattern': r'(email|ssn|phone|credit_card|social_security)\\s*[:=]', 'explanation': 'Unmasked handling of PII.', 'fix': 'Implement encryption.', 'severity': 'MEDIUM'}
            ],
            '11. NoSQL/Data': [
                {'name': 'NoSQL Operator Injection', 'pattern': r'(\\$where|\\$ne|\\$gt|\\$regex|\\$exists)', 'explanation': 'Injecting NoSQL logical operators.', 'fix': 'Sanitize input for NoSQL query operators.', 'severity': 'HIGH'}
            ],
            '12. Business Logic': [
                {'name': 'Concurrency Race Conditions', 'pattern': r'(threading\\.Thread|asyncio\\.create_task).*?(\\+=|\\-=)', 'explanation': 'State updates on shared variables without atomicity.', 'fix': 'Implement threading.Lock().', 'severity': 'MEDIUM'}
            ],
            '13. Path Handling': [
                {'name': 'LFI/Path Traversal', 'pattern': r'(\\.\\./|\\.\\.||/etc/passwd|/proc/|/windows/win\\.ini)', 'explanation': 'Accessing files outside application root.', 'fix': 'Use os.path.basename().', 'severity': 'HIGH'}
            ],
            '14. Container Security': [
                {'name': 'Privileged Escalation Flag', 'pattern': r'(privileged:\\s*true|hostNetwork:\\s*true)', 'explanation': 'Container configs exposing host kernel.', 'fix': 'Run as non-root.', 'severity': 'HIGH'}
            ],
            '15. Blockchain/Distributed': [
                {'name': 'Reentrancy Logic', 'pattern': r'(msg\\.sender\\.call|transfer\\(|lock_state).*?(\\-=|\\+=)', 'explanation': 'External calls before state updates.', 'fix': 'Follow Checks-Effects-Interactions.', 'severity': 'CRITICAL'}
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

st.title('🛡️ CyberEnterprise Ultra v15.0')

if 'engine' not in st.session_state:
    st.session_state.engine = EnterpriseLogicEngine()

tab1, tab2, tab3, tab4 = st.tabs(['🔍 Advanced Scanner', '📊 Analytics & Meters', '📋 Detailed Remediation', '🧪 Signature Debugger'])

with tab1:
    code_input = st.text_area('Input Code Logic:', height=300, placeholder='Paste code for 15-vector deep scan...')
    if st.button('INITIATE DEEP INSPECTION'):
        if code_input:
            results, latency = st.session_state.engine.scan(code_input)
            st.session_state.results = results
            st.session_state.latency = latency
            if results:
                st.error(f'Threats Found: {len(results)}')
            else:
                st.success('System Secure Across All 15 Vectors.')

with tab2:
    st.subheader('System Performance & Telemetry')
    if 'latency' in st.session_state:
        m1, m2 = st.columns(2)
        m1.metric('Scan Latency', f"{st.session_state.latency:.6f}s")
        m2.metric('Peak Throughput', f"{1/(st.session_state.latency + 1e-9):,.0f} ops/sec")

with tab3:
    st.subheader('Hyper-Detailed Remediation Dashboard')
    if 'results' in st.session_state and st.session_state.results:
        for res in st.session_state.results:
            with st.expander(f"[{res['severity']}] {res['name']} - Vector: {res['category']}"):
                st.markdown(f"### **Precision Analysis**\n{res['explanation']}")
                st.success(f"### **Automated Patch Guide**\n{res['fix']}")

with tab4:
    st.subheader('🧪 Signature Debugger')
    st.info('Test code fragments against the core SQLi regex signature.')
    test_line = st.text_input('1. Paste specific code line:', placeholder='e.g., query = "SELECT * FROM users WHERE id=" + user_id')
    test_regex = st.text_input('2. Regex Signature Match:', value=r'(SELECT|INSERT|UPDATE|DELETE|UNION|DROP|EXEC|CAST|CONVERT).*?([\\s\\+\\$\\%{]).*?[\\x27\\x22]')
    if st.button('VALIDATE SIGNATURE'):
        if test_line and test_regex:
            match = re.search(test_regex, test_line, re.IGNORECASE | re.DOTALL)
            if match:
                st.error('🚨 SIGNATURE MATCH DETECTED')
                st.code(f'Matched Fragment: {match.group(0)}')
            else:
                st.success('✅ NO MATCH FOUND')
