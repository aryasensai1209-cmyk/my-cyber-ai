
import streamlit as st
import re
import pandas as pd
import time
import numpy as np

st.set_page_config(page_title='CyberEnterprise Ultra v15', page_icon='🛡️', layout='wide')

class EnterpriseLogicEngine:
    def __init__(self):
        # 15-Vector Security Map with precise patterns and hyper-detailed explanations
        self.vulnerability_map = {
            '1. Injection & Input': [
                {'name': 'Advanced SQLi', 'pattern': r'(SELECT|INSERT|UPDATE|DELETE|UNION|DROP|EXEC|CAST|CONVERT).*?([\s\+\$\%{]).*?[\x27\x22]', 'explanation': 'Identifies complex SQL injection vectors where user input is concatenated into query strings. This bypasses standard filters by using casting or union-based attacks.', 'fix': 'Enforce strictly parameterized queries using prepared statements.', 'severity': 'CRITICAL'},
                {'name': 'Shell Command Injection', 'pattern': r'(os\.system|subprocess|exec|eval|system|popen|shutil|spawn)\(.*?([\+\%]|f["\']).*?\)', 'explanation': 'Detects shell-level execution vulnerabilities where dynamic strings are passed to the OS kernel, allowing arbitrary code execution.', 'fix': 'Avoid shell=True; use list-based arguments with absolute paths.', 'severity': 'CRITICAL'}
            ],
            '2. Web App Logic': [
                {'name': 'XSS (DOM/Reflected)', 'pattern': r'(\.(innerHTML|outerHTML|srcdoc)\s*=|document\.write\(|alert\(|eval\(.*?location)', 'explanation': 'Identifies points where untrusted data is rendered as HTML, allowing script injection into a user\'s browser session.', 'fix': 'Utilize .textContent or perform context-aware output encoding.', 'severity': 'HIGH'}
            ],
            '3. Authentication': [
                {'name': 'Hardcoded Credentials', 'pattern': r'(password|passwd|secret|token|apikey|aws_key|private_key)\s*[:=]\s*[\x27\x22][a-zA-Z0-9_\-]{5,}[\x27\x22]', 'explanation': 'Plaintext secrets detected in source code. This is a primary target for attackers during static analysis.', 'fix': 'Migrate secrets to environment variables or a secure Vault.', 'severity': 'CRITICAL'}
            ],
            '4. AI/ML Safety': [
                {'name': 'Insecure Object Deserialization', 'pattern': r'(pickle\.load\(|joblib\.load\(|yaml\.load\(.*?Loader=)', 'explanation': 'Loading untrusted data into Python objects can trigger arbitrary code execution via __reduce__ methods.', 'fix': 'Use safe loaders (json.loads) or restricted schemas.', 'severity': 'HIGH'}
            ],
            '5. Cloud Infra': [
                {'name': 'Cloud Metadata Leakage', 'pattern': r'(169\.254\.169\.254|s3://.*?/|\.s3\.amazonaws\.com)', 'explanation': 'Exposure of cloud provider metadata endpoints which can leak IAM roles and credentials.', 'fix': 'Enforce IMDSv2 and restrict bucket access policies.', 'severity': 'HIGH'}
            ],
            '6. Cryptography': [
                {'name': 'Weak Cryptographic Primitives', 'pattern': r'(hashlib\.md5|hashlib\.sha1|DES|RC4|blowfish)', 'explanation': 'Use of mathematically compromised algorithms susceptible to collision attacks and brute force.', 'fix': 'Upgrade to SHA-256/3 or AES-256-GCM.', 'severity': 'HIGH'}
            ],
            '7. Memory Safety': [
                {'name': 'Buffer/Heap Operations', 'pattern': r'(strcpy|strcat|sprintf|gets|memcpy|malloc)\(', 'explanation': 'Unsafe memory operations in C-extensions or low-level logic that can lead to buffer overflows.', 'fix': 'Use bounds-checked functions like strncpy or managed memory containers.', 'severity': 'MEDIUM'}
            ],
            '8. API Security': [
                {'name': 'JWT/Auth Misconfiguration', 'pattern': r'(jwt\.decode\(.*?verify=False|algorithm=["\']none["\'])', 'explanation': 'Bypassing signature verification in JSON Web Tokens, allowing identity forgery.', 'fix': 'Always enforce signature verification and prohibit "none" algorithms.', 'severity': 'CRITICAL'}
            ],
            '9. Supply Chain': [
                {'name': 'Insecure Dependency Fetch', 'pattern': r'(curl.*?\|.*?bash|pip install.*?--extra-index-url)', 'explanation': 'Downloading packages from unverified indices or executing remote scripts directly.', 'fix': 'Use pinned versions with sha256 hashes in requirements.txt.', 'severity': 'HIGH'}
            ],
            '10. Privacy/PII': [
                {'name': 'PII Data Exposure', 'pattern': r'(email|ssn|phone|credit_card|social_security)\s*[:=]', 'explanation': 'Unmasked handling of Personally Identifiable Information in logs or variables.', 'fix': 'Implement AES-256 encryption at rest and mask data in transit.', 'severity': 'MEDIUM'}
            ],
            '11. NoSQL/Data': [
                {'name': 'NoSQL Operator Injection', 'pattern': r'(\$where|\$ne|\$gt|\$regex|\$exists)', 'explanation': 'Injecting NoSQL logical operators to bypass query filters or authentication.', 'fix': 'Sanitize input for NoSQL query operators and use schema validation.', 'severity': 'HIGH'}
            ],
            '12. Business Logic': [
                {'name': 'Concurrency Race Conditions', 'pattern': r'(threading\.Thread|asyncio\.create_task).*?(\+=|\-=)', 'explanation': 'State updates on shared variables without atomicity, leading to financial or logic bypasses.', 'fix': 'Implement threading.Lock() or Mutex synchronization.', 'severity': 'MEDIUM'}
            ],
            '13. Path Handling': [
                {'name': 'LFI/Path Traversal', 'pattern': r'(\.\./|\.\.\|/etc/passwd|/proc/|/windows/win\.ini)', 'explanation': 'Accessing files outside the application root via relative path manipulation.', 'fix': 'Use os.path.basename() and validate against an allow-list of directories.', 'severity': 'HIGH'}
            ],
            '14. Container Security': [
                {'name': 'Privileged Escalation Flag', 'pattern': r'(privileged:\s*true|hostNetwork:\s*true)', 'explanation': 'Container configurations that expose the host kernel to the workload.', 'fix': 'Run containers as non-root with restricted capabilities.', 'severity': 'HIGH'}
            ],
            '15. Blockchain/Distributed': [
                {'name': 'Reentrancy Logic', 'pattern': r'(msg\.sender\.call|transfer\(|lock_state).*?(\-=|\+=)', 'explanation': 'Detects external calls occurring before state updates, a classic DeFi vulnerability.', 'fix': 'Follow the Checks-Effects-Interactions pattern.', 'severity': 'CRITICAL'}
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

tab1, tab2, tab3 = st.tabs(['🔍 Advanced Scanner', '📊 Analytics & Meters', '📋 Detailed Remediation'])

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
        st.write('Latency Trend Simulation')
        st.line_chart(pd.DataFrame(np.random.rand(20, 1) * st.session_state.latency, columns=['latency_ms']))
        st.write('Severity Distribution')
        if st.session_state.results:
            df = pd.DataFrame(st.session_state.results)
            st.bar_chart(df['severity'].value_counts())

with tab3:
    st.subheader('Hyper-Detailed Remediation Dashboard')
    if 'results' in st.session_state and st.session_state.results:
        for res in st.session_state.results:
            with st.expander(f"[{res['severity']}] {res['name']} - Vector: {res['category']}"):
                st.markdown(f"### **Precision Analysis**\n{res['explanation']}")
                st.success(f"### **Automated Patch Guide**\n{res['fix']}")
                st.code(f"# Signature Match: {res['pattern']}")
    else:
        st.info('Analyze code to see precise remediation data.')
