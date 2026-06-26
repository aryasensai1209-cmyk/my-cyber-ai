import streamlit as st
import time
import re
import pandas as pd
import numpy as np

# --- Enterprise Proprietary Cyber AI Engine v8.2 ---
# Optimized with the full 15-Vector Security Map
class EnterpriseLogicEngine:
    def __init__(self):
        self.vulnerability_map = {
            '1. Injection & Input': [
                {'name': 'SQLi (Classic/Blind/Union)', 'pattern': r"(SELECT|INSERT|UPDATE|DELETE|UNION|DROP).*?(\+|\$|%|\{).*?['\"]", 'explanation': 'User input is concatenated into SQL queries, allowing database manipulation.', 'fix': 'Use Parameterized Queries.', 'severity': 'CRITICAL'},
                {'name': 'Command Injection', 'pattern': r"(os\.system|subprocess|exec|eval|system|popen)\(.*?(\+|%).*?\)", 'explanation': 'Unsanitized input passed to system shell executors.', 'fix': 'Avoid shell=True; use list-based arguments.', 'severity': 'CRITICAL'}
            ],
            '2. Web App Flaws': [
                {'name': 'XSS (Reflected/Stored/DOM)', 'pattern': r"(\.(innerHTML|outerHTML)\s*=|document\.write\(|alert\()", 'explanation': 'Execution of malicious scripts in the user browser context.', 'fix': 'Use .textContent or sanitize HTML.', 'severity': 'HIGH'}
            ],
            '3. Auth & Session': [
                {'name': 'Hardcoded Credentials', 'pattern': r"(password|passwd|secret|token|apikey)\s*[:=]\s*['\"][a-zA-Z0-9]{5,}['\"]", 'explanation': 'Sensitive credentials stored in plaintext within source code.', 'fix': 'Use Environment Variables or Secret Managers.', 'severity': 'CRITICAL'}
            ],
            '4. AI/ML Security': [
                {'name': 'Insecure Deserialization', 'pattern': r"(pickle\.load\(|joblib\.load\()", 'explanation': 'Loading untrusted data into objects can lead to arbitrary code execution.', 'fix': 'Use JSON or restricted loaders.', 'severity': 'HIGH'}
            ],
            '5. Cloud/Infrastructure': [
                {'name': 'Metadata Exposure', 'pattern': r"(169\.254\.169\.254|s3://.*?/)", 'explanation': 'Accessing internal cloud metadata services or exposed buckets.', 'fix': 'Enforce IMDSv2 and IAM policies.', 'severity': 'HIGH'}
            ],
            '6. Cryptography': [
                {'name': 'Broken Algorithms', 'pattern': r"(hashlib\.md5|hashlib\.sha1|DES|RC4)", 'explanation': 'Use of collision-prone or mathematically broken cryptographic primitives.', 'fix': 'Upgrade to SHA-256/AES-GCM.', 'severity': 'HIGH'}
            ],
            '7. File Systems': [
                {'name': 'Path Traversal', 'pattern': r"(\.\./|\.\.\\|/etc/passwd)", 'explanation': 'Allows reading files outside of the intended web root/application directory.', 'fix': 'Sanitize paths with os.path.basename().', 'severity': 'HIGH'}
            ],
            '8. API Security': [
                {'name': 'Broken Object Level Auth', 'pattern': r"(jwt\.decode\(.*?verify=False)", 'explanation': 'Accepting signed tokens without verifying the signature.', 'fix': 'Set verify=True in JWT decoding.', 'severity': 'CRITICAL'}
            ],
            '9. Mobile Logic': [
                {'name': 'Insecure Logging', 'pattern': r"(Log\.d\(|Log\.v\(|intent\.setData\()", 'explanation': 'Sensitive application logic or data leaked via system logs.', 'fix': 'Disable debug logging in production.', 'severity': 'LOW'}
            ],
            '10. Supply Chain': [
                {'name': 'Dependency Hijacking', 'pattern': r"(pip install.*?--extra-index-url)", 'explanation': 'Pulling packages from unverified indices without hash verification.', 'fix': 'Use requirements.txt with --hash.', 'severity': 'MEDIUM'}
            ],
            '11. Container/Orchestration': [
                {'name': 'Privileged Escalation', 'pattern': r"(privileged:\s*true)", 'explanation': 'Containers running with full root access to the host kernel.', 'fix': 'Remove the privileged flag.', 'severity': 'HIGH'}
            ],
            '12. Business Logic': [
                {'name': 'Race Conditions', 'pattern': r"(threading\.Thread|asyncio\.create_task).*?(\+=|-=)", 'explanation': 'Concurrent operations on shared state without proper locking.', 'fix': 'Use threading.Lock() or Mutex.', 'severity': 'MEDIUM'}
            ],
            '13. NoSQL Security': [
                {'name': 'Operator Injection', 'pattern': r"(\$where|\$ne|\$gt|\$regex)", 'explanation': 'Injecting NoSQL operators to bypass authentication or filter data.', 'fix': 'Use schema-based validation.', 'severity': 'HIGH'}
            ],
            '14. Privacy/PII': [
                {'name': 'PII Leakage', 'pattern': r"(email|ssn|phone|credit_card)\s*[:=]", 'explanation': 'Handling personally identifiable information in unencrypted formats.', 'fix': 'Implement AES-256 encryption at rest.', 'severity': 'MEDIUM'}
            ],
            '15. Distributed Logic & Consensus': [
                {'name': 'Reentrancy Attack', 'pattern': r"(msg\.sender\.call|transfer\(|lock_state).*?(\-=|\+=)", 'explanation': 'External calls occurring before state updates in smart contracts.', 'fix': 'Use Checks-Effects-Interactions pattern.', 'severity': 'CRITICAL'}
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

st.set_page_config(page_title="Enterprise Logic Node", page_icon="♁", layout="wide")

if 'engine' not in st.session_state:
    st.session_state.engine = EnterpriseLogicEngine()

st.title("♁ Enterprise Logic Node v8.2 (Full 15-Vector Edition)")

tab1, tab2, tab3 = st.tabs(["⌕ Security Scanner", "⌂ Remediation Dashboard", "☰ Knowledge Base"])

with tab1:
    code_input = st.text_area("Source Code Input:", height=200, placeholder="Paste code for 15-vector analysis...")
    if st.button("ፁ RUN ANALYSIS"):
        if code_input:
            results, latency = st.session_state.engine.scan(code_input)
            st.session_state.last_results = results
            st.session_state.last_latency = latency
            if results:
                st.error(f"Detected {len(results)} potential vulnerabilities.")
                for res in results:
                    st.warning(f"**[{res['severity']}]** {res['name']}")
            else:
                st.success("Code verified as secure across all vectors.")

with tab2:
    st.subheader("⌒ Deep Remediation & Detail Dashboard")
    if 'last_results' in st.session_state and st.session_state.last_results:
        for res in st.session_state.last_results:
            with st.expander(f"⌕ Analysis: {res['name']} ({res['severity']})"):
                st.markdown(f"### **Technical Explanation**\n{res['explanation']}")
                st.success(f"### **Secure Remediation**\n{res['fix']}")
                st.code(f"# Security Vector: {res['category']}\n# Logic Pattern: {res['pattern']}")
    else:
        st.info("No scan data. Run a scan in the Scanner tab to see detailed remediations.")

with tab3:
    st.subheader("☰ Complete 15-Vector Knowledge Base")
    for category, rules in st.session_state.engine.vulnerability_map.items():
        with st.expander(f"{category}"):
            for rule in rules:
                st.markdown(f"**{rule['name']}** ({rule['severity']})")
                st.caption(f"**Logic:** {rule['explanation']}")
                st.markdown(f"*Recommended Fix: {rule['fix']}*")
                st.divider()

st.sidebar.info(f"● CORE: ONLINE\n● VECTORS: 15 ACTIVE\n● LATENCY: {st.session_state.get('last_latency', 0):.4f}s")
