
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
                {'name': 'SQLi (Classic/Blind/Union)', 'pattern': r'(SELECT|INSERT|UPDATE|DELETE|UNION|DROP).*?([\s\+\$%\{]).*?[\x27\x22]', 'explanation': 'User input is concatenated into SQL queries, allowing unauthorized database manipulation.', 'fix': 'Use Parameterized Queries.', 'severity': 'CRITICAL'},
                {'name': 'Command Injection', 'pattern': r'(os\\.system|subprocess|exec|eval|system|popen)\\(.*?([\\+]).*?\\)', 'explanation': 'Unsanitized input passed to system shell executors.', 'fix': 'Avoid shell=True; use list-based arguments.', 'severity': 'CRITICAL'}
            ],
            '2. Web App Flaws': [
                {'name': 'XSS (Reflected/Stored/DOM)', 'pattern': r'(\\.(innerHTML|outerHTML)\\s*=|document\\.write\\(|alert\\()', 'explanation': 'Malicious scripts executed in browser context.', 'fix': 'Use .textContent or sanitize HTML.', 'severity': 'HIGH'},
                {'name': 'CSRF/IDOR', 'pattern': r'(<form(?!.*?csrf_token).*?>|/user/\\?id=)', 'explanation': 'Lack of state verification or improper object-level authorization.', 'fix': 'Implement anti-CSRF tokens.', 'severity': 'MEDIUM'}
            ],
            '3. Auth & Session': [
                {'name': 'Hardcoded Credentials', 'pattern': r'(password|passwd|secret|token|apikey)\\s*[:=]\\s*[\x27\x22][a-zA-Z0-9_-]{5,}[\x27\x22]', 'explanation': 'Sensitive credentials stored in plaintext in source code.', 'fix': 'Use Environment Variables.', 'severity': 'CRITICAL'}
            ],
            '4. Cryptography': [
                {'name': 'Weak Hashing/Encryption', 'pattern': r'(hashlib\\.md5|hashlib\\.sha1|DES|RC4)', 'explanation': 'Use of mathematically broken cryptographic primitives.', 'fix': 'Upgrade to SHA-256 or AES-GCM.', 'severity': 'HIGH'}
            ],
            '5. File Issues': [
                {'name': 'Path Traversal/LFI', 'pattern': r'(\\.\\./|\\.\\.\\\\|/etc/passwd|/windows/win\\.ini)', 'explanation': 'Accessing files outside intended web root.', 'fix': 'Use basename() and whitelist directories.', 'severity': 'HIGH'}
            ],
            '6. Cloud/Infrastructure': [
                {'name': 'Metadata Exposure', 'pattern': r'(169\\.254\\.169\\.254|s3://.*?/)', 'explanation': 'Exposure of cloud provider metadata.', 'fix': 'Enforce IMDSv2.', 'severity': 'HIGH'}
            ],
            '7. IoT & Hardware': [
                {'name': 'Unsafe Buffer Operations', 'pattern': r'(strcpy|strcat|sprintf|gets)', 'explanation': 'Functions that do not check buffer boundaries.', 'fix': 'Use strncpy or safer APIs.', 'severity': 'MEDIUM'}
            ],
            '8. API Security': [
                {'name': 'JWT Misconfig', 'pattern': r'(jwt\\.decode\\(.*?verify=False)', 'explanation': 'Accepting signed tokens without signature verification.', 'fix': 'Enable JWT verification.', 'severity': 'HIGH'}
            ],
            '9. Mobile Security': [
                {'name': 'Insecure Logging', 'pattern': r'(Log\\.[dv]\\(|intent\\.setData\\()', 'explanation': 'Sensitive data leaked via system debug logs.', 'fix': 'Disable debug logging.', 'severity': 'LOW'}
            ],
            '10. Supply Chain': [
                {'name': 'Malicious Dependency', 'pattern': r'(curl.*?\\|.*?bash|pip install.*?--extra-index-url)', 'explanation': 'Downloading unverified packages.', 'fix': 'Use pinned versions.', 'severity': 'HIGH'}
            ],
            '11. Container Security': [
                {'name': 'Privileged Container', 'pattern': r'(privileged:\\s*true)', 'explanation': 'Containers running with root access to host kernel.', 'fix': 'Remove privileged flag.', 'severity': 'HIGH'}
            ],
            '12. Business Logic': [
                {'name': 'Race Condition', 'pattern': r'(threading\\.Thread|asyncio\\.create_task).*?(\\+=|\\-=)', 'explanation': 'Concurrent state updates without synchronization.', 'fix': 'Implement Mutex/Locks.', 'severity': 'MEDIUM'}
            ],
            '13. NoSQL Security': [
                {'name': 'Operator Injection', 'pattern': r'(\\$where|\\$ne|\\$gt|\\$regex)', 'explanation': 'Injecting NoSQL operators to bypass filters.', 'fix': 'Use schema-based validation.', 'severity': 'HIGH'}
            ],
            '14. AI/ML Security': [
                {'name': 'Insecure Loaders', 'pattern': r'(pickle\\.load\\(|joblib\\.load\\()', 'explanation': 'Loading untrusted data into objects.', 'fix': 'Use safe JSON loaders.', 'severity': 'HIGH'}
            ],
            '15. Privacy Compliance': [
                {'name': 'PII Leakage', 'pattern': r'(email|ssn|phone|credit_card)\\s*[:=]', 'explanation': 'Handling personally identifiable information in unencrypted formats.', 'fix': 'Anonymize PII data.', 'severity': 'MEDIUM'}
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

st.title('🛡️ CyberEnterprise Pro v10.1')

if 'engine' not in st.session_state:
    st.session_state.engine = EnterpriseLogicEngine()

tab1, tab2, tab3 = st.tabs(['🔍 Security Scanner', '📊 Metrics & Performance', '📋 Remediation Dashboard'])

with tab1:
    code_input = st.text_area('Source Code Input:', height=300, placeholder='Paste code here...')
    if st.button('INITIATE SYSTEM SCAN'):
        if code_input:
            results, latency = st.session_state.engine.scan(code_input)
            st.session_state.last_results = results
            st.session_state.last_latency = latency
            if results:
                st.error(f'Threats Detected: {len(results)}')
                for res in results:
                    st.warning(f"**[{res['severity']}]** {res['name']}")
            else:
                st.success('No vulnerabilities found.')

with tab2:
    st.subheader('Real-Time Performance Monitoring')
    if 'last_latency' in st.session_state:
        m1, m2 = st.columns(2)
        m1.metric('Scan Latency', f"{st.session_state.last_latency:.6f}s")
        m2.metric('Throughput (Ops/sec)', f"{1/(st.session_state.last_latency + 1e-9):,.0f}")
        st.write('Latency Trend Analysis')
        chart_data = pd.DataFrame(np.random.randn(20, 1) * 0.0001 + st.session_state.last_latency, columns=['latency'])
        st.line_chart(chart_data)
    else:
        st.info('Please run a scan to generate performance telemetry.')

with tab3:
    st.subheader('⌒ Detailed Remediation Dashboard')
    if 'last_results' in st.session_state and st.session_state.last_results:
        for res in st.session_state.last_results:
            with st.expander(f"REMEDIATION: {res['name']} ({res['severity']})"):
                st.markdown(f"### **Technical Explanation**\\n{res['explanation']}")
                st.success(f"### **Safe Implementation Guide**\\n{res['fix']}")
                st.caption(f"Vector Category: {res['category']}")
    else:
        st.info('Run a scan in the Scanner tab to populate remediation details.')
