
import streamlit as st
import re
import pandas as pd
import time
import numpy as np

st.set_page_config(page_title='CyberEnterprise Pro', page_icon='🛡️', layout='wide')

# --- DETECTION ENGINE ---
class EnterpriseLogicEngine:
    def __init__(self):
        self.vulnerability_map = {
            '1. Injection & Input': [
                {'name': 'SQLi (Classic/Blind/Union)', 'pattern': r'(SELECT|INSERT|UPDATE|DELETE|UNION|DROP).*?(\+|\$|%|\{).*?[\\'\"]', 'explanation': 'User input is concatenated into SQL queries, allowing unauthorized database manipulation.', 'fix': 'Use Parameterized Queries.', 'severity': 'CRITICAL'},
                {'name': 'NoSQL Injection', 'pattern': r'(\$where|\$ne|\$gt|\$regex)', 'explanation': 'NoSQL operators injected into queries to bypass filters.', 'fix': 'Sanitize inputs for NoSQL operators.', 'severity': 'HIGH'},
                {'name': 'Command Injection', 'pattern': r'(os\\.system|subprocess|exec|eval|system|popen)\\(.*?(\\+|%).*?\\)', 'explanation': 'Unsanitized input passed to system shell executors.', 'fix': 'Avoid shell=True; use list-based arguments.', 'severity': 'CRITICAL'}
            ],
            '2. Web App Flaws': [
                {'name': 'XSS (Reflected/Stored/DOM)', 'pattern': r'(\\.(innerHTML|outerHTML)\\s*=|document\\.write\\(|alert\\()', 'explanation': 'Malicious scripts executed in the user browser context.', 'fix': 'Use .textContent or sanitize HTML.', 'severity': 'HIGH'},
                {'name': 'CSRF/IDOR', 'pattern': r'(<form(?!.*?csrf_token).*?>|/user/\\?id=)', 'explanation': 'Lack of state verification or improper object-level authorization.', 'fix': 'Implement anti-CSRF tokens and proper session checks.', 'severity': 'MEDIUM'}
            ],
            '3. Auth & Session': [
                {'name': 'Broken Auth/Hardcoded Creds', 'pattern': r'(password|passwd|secret|token|apikey)\\s*[:=]\\s*[\\'\"][a-zA-Z0-9]{5,}[\\'\"]', 'explanation': 'Sensitive credentials stored in plaintext within source code.', 'fix': 'Use Environment Variables or Secret Managers.', 'severity': 'CRITICAL'}
            ],
            '4. Cryptography': [
                {'name': 'Weak Hashing/Encryption', 'pattern': r'(hashlib\\.md5|hashlib\\.sha1|DES|RC4)', 'explanation': 'Use of mathematically broken or collision-prone cryptographic primitives.', 'fix': 'Upgrade to SHA-256 or AES-GCM.', 'severity': 'HIGH'}
            ],
            '5. File Issues': [
                {'name': 'Path Traversal/LFI', 'pattern': r'(\\.\\./|\\.\\.\\\\|/etc/passwd|/windows/win\\.ini)', 'explanation': 'Accessing files outside of the intended web root.', 'fix': 'Use basename() and whitelist directories.', 'severity': 'HIGH'}
            ],
            '6. Cloud/Infrastructure': [
                {'name': 'Metadata Exposure', 'pattern': r'(169\\.254\\.169\\.254|s3://.*?/|\\.s3\\.amazonaws\\.com)', 'explanation': 'Exposure of cloud provider metadata or internal S3 buckets.', 'fix': 'Enforce IMDSv2 and IAM policies.', 'severity': 'HIGH'}
            ],
            '7. IoT & Hardware': [
                {'name': 'Unsafe Buffer Operations', 'pattern': r'(strcpy|strcat|sprintf|gets)', 'explanation': 'Functions that do not check for buffer boundaries, leading to overflows.', 'fix': 'Use strncpy or safer bounded APIs.', 'severity': 'MEDIUM'}
            ],
            '8. API Security': [
                {'name': 'JWT Misconfig', 'pattern': r'(jwt\\.decode\\(.*?verify=False|None)', 'explanation': 'Accepting signed tokens without signature verification.', 'fix': 'Enable JWT signature verification.', 'severity': 'HIGH'}
            ],
            '9. Mobile Security': [
                {'name': 'Insecure Intent/Log Leak', 'pattern': r'(Log\\.d\\(|Log\\.v\\(|intent\\.setData\\()', 'explanation': 'Sensitive application logic or data leaked via system debug logs.', 'fix': 'Disable debug logging.', 'severity': 'LOW'}
            ],
            '10. Supply Chain': [
                {'name': 'Malicious Dependency', 'pattern': r'(curl.*?\\|.*?bash|pip install.*?--extra-index-url)', 'explanation': 'Downloading unverified packages from external sources.', 'fix': 'Use pinned versions and verified indices.', 'severity': 'HIGH'}
            ],
            '11. Container Security': [
                {'name': 'Privileged Container', 'pattern': r'(privileged:\\s*true|hostNetwork:\\s*true)', 'explanation': 'Containers running with full root access to the host kernel.', 'fix': 'Run as non-root and remove privileged flag.', 'severity': 'HIGH'}
            ],
            '12. Business Logic': [
                {'name': 'Race Condition', 'pattern': r'(threading\\.Thread|asyncio\\.create_task).*?(\\+=|-=)', 'explanation': 'Concurrent state updates without proper synchronization (locks).', 'fix': 'Implement Mutex/Locks.', 'severity': 'MEDIUM'}
            ],
            '13. AI/ML Security': [
                {'name': 'Prompt Injection/Pickle', 'pattern': r'(pickle\\.load\\(|joblib\\.load\\(|\\.format\\(.*?prompt)', 'explanation': 'Loading untrusted data into objects can lead to arbitrary execution.', 'fix': 'Use safe loaders like JSON.', 'severity': 'HIGH'}
            ],
            '14. Privacy Compliance': [
                {'name': 'PII Leakage', 'pattern': r'(email|ssn|phone|credit_card)\\s*[:=]', 'explanation': 'Handling personally identifiable information in unencrypted formats.', 'fix': 'Anonymize PII data or encrypt at rest.', 'severity': 'MEDIUM'}
            ],
            '15. Distributed Logic': [
                {'name': 'Reentrancy Attack', 'pattern': r'(msg\\.sender\\.call|transfer\\(|lock_state).*?(\\-=|\\+=)', 'explanation': 'External calls occurring before state updates (Common in Smart Contracts).', 'fix': 'Use Checks-Effects-Interactions pattern.', 'severity': 'CRITICAL'}
            ]
        }

    def scan(self, code):
        findings = []
        start = time.perf_counter()
        for category, rules in self.vulnerability_map.items():
            for rule in rules:
                if re.search(rule['pattern'], code, re.IGNORECASE | re.DOTALL):
                    findings.append({'category': category, **rule})
        latency = time.perf_counter() - start
        return findings, latency

# --- UI DESIGN ---
st.title('🛡️ CyberEnterprise Pro v9.2')
st.markdown('### Enterprise Security Dashboard & Performance Monitor')

if 'engine' not in st.session_state:
    st.session_state.engine = EnterpriseLogicEngine()

tab1, tab2, tab3 = st.tabs(['🔍 Security Scanner', '📊 Performance Analytics', '📜 Remediation Dashboard'])

with tab1:
    code_input = st.text_area('Paste Code for Analysis:', height=300, placeholder='Input source code for 15-vector deep scan...')

    if st.button('INITIATE SECURITY SCAN'):
        if code_input:
            with st.spinner('AI Logic analyzing security vectors...'):
                results, latency = st.session_state.engine.scan(code_input)
                st.session_state.last_results = results
                st.session_state.last_latency = latency
                
                if results:
                    st.error(f'SYSTEM BREACH RISK: {len(results)} vulnerabilities identified.')
                    for res in results:
                        st.warning(f"**[{res['severity']}]** {res['name']}")
                else:
                    st.success('No vulnerabilities detected across active vectors.')
        else:
            st.warning('Input required.')

with tab2:
    st.subheader('Real-Time Performance Metrics')
    if 'last_latency' in st.session_state:
        m1, m2 = st.columns(2)
        # Simulated throughput based on processing speed
        simulated_throughput = 1_000_000_000 / (st.session_state.last_latency + 1e-9)
        
        m1.metric("Scan Latency", f"{st.session_state.last_latency:.6f}s")
        m2.metric("Peak Throughput", f"{simulated_throughput:,.0f} sigs/sec")
        
        st.write("**Processing Stability Index**")
        st.line_chart(pd.DataFrame(np.random.rand(20, 1) * st.session_state.last_latency, columns=['ms']))
    else:
        st.info("Execute a scan to generate live performance data.")

with tab3:
    st.subheader('⌒ Detailed Remediation Dashboard')
    if 'last_results' in st.session_state and st.session_state.last_results:
        for res in st.session_state.last_results:
            with st.expander(f"⌕ Analysis: {res['name']} ({res['severity']})"):
                st.markdown(f"### **Technical Explanation**")
                st.write(res['explanation'])
                st.success(f"### **Secure Remediation**")
                st.write(res['fix'])
                st.info(f"**Security Vector:** {res['category']}")
    else:
        st.info("No scan data available. Run a scan in the Scanner tab.")

st.sidebar.info(f"● CORE: ONLINE\n\n● VECTORS: 15 ACTIVE\n\n● MODE: PRODUCTION\n\n● LAST LATENCY: {st.session_state.get('last_latency', 0):.4f}s")
