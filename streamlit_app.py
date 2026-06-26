
import streamlit as st
import re
import pandas as pd
import time

st.set_page_config(page_title='CyberEnterprise Pro', page_icon='🛡️', layout='wide')

# --- DETECTION ENGINE ---
class EnterpriseLogicEngine:
    def __init__(self):
        self.vulnerability_map = {
            '1. Injection & Input': [
                {'name': 'SQLi (Classic/Blind/Union)', 'pattern': r'(SELECT|INSERT|UPDATE|DELETE|UNION|DROP).*?(\+|\$|%|\{).*?[\'\"]', 'fix': 'Use Prepared Statements.', 'severity': 'CRITICAL'},
                {'name': 'NoSQL Injection', 'pattern': r'(\$where|\$ne|\$gt|\$regex)', 'fix': 'Sanitize inputs for NoSQL operators.', 'severity': 'HIGH'},
                {'name': 'Command Injection', 'pattern': r'(os\.system|subprocess|exec|eval|system|popen)\(.*?(\+|%).*?\)', 'fix': 'Avoid shell=True.', 'severity': 'CRITICAL'}
            ],
            '2. Web App Flaws': [
                {'name': 'XSS (Reflected/Stored/DOM)', 'pattern': r'(\.(innerHTML|outerHTML)\s*=|document\.write\(|alert\()', 'fix': 'Use .textContent.', 'severity': 'HIGH'},
                {'name': 'CSRF/IDOR', 'pattern': r'(<form(?!.*?csrf_token).*?>|/user/\?id=)', 'fix': 'Implement anti-CSRF tokens.', 'severity': 'MEDIUM'}
            ],
            '3. Auth & Session': [
                {'name': 'Broken Auth/Hardcoded Creds', 'pattern': r'(password|passwd|secret|token|apikey)\s*[:=]\s*[\'\"][a-zA-Z0-9]{5,}[\'\"]', 'fix': 'Use Environment Variables.', 'severity': 'CRITICAL'}
            ],
            '4. Cryptography': [
                {'name': 'Weak Hashing/Encryption', 'pattern': r'(hashlib\.md5|hashlib\.sha1|DES|RC4)', 'fix': 'Upgrade to SHA-256 or AES-GCM.', 'severity': 'HIGH'}
            ],
            '5. File Issues': [
                {'name': 'Path Traversal/LFI', 'pattern': r'(\.\./|\.\.\\|/etc/passwd|/windows/win\.ini)', 'fix': 'Use basename() and whitelist directories.', 'severity': 'HIGH'}
            ],
            '6. Cloud/Infrastructure': [
                {'name': 'Metadata Exposure', 'pattern': r'(169\.254\.169\.254|s3://.*?/|\.s3\.amazonaws\.com)', 'fix': 'Enforce IMDSv2.', 'severity': 'HIGH'}
            ],
            '7. IoT & Hardware': [
                {'name': 'Unsafe Buffer Operations', 'pattern': r'(strcpy|strcat|sprintf|gets)', 'fix': 'Use strncpy or safer APIs.', 'severity': 'MEDIUM'}
            ],
            '8. API Security': [
                {'name': 'JWT Misconfig', 'pattern': r'(jwt\.decode\(.*?verify=False|None)', 'fix': 'Enable JWT signature verification.', 'severity': 'HIGH'}
            ],
            '9. Mobile Security': [
                {'name': 'Insecure Intent/Log Leak', 'pattern': r'(Log\.d\(|Log\.v\(|intent\.setData\()', 'fix': 'Disable debug logging.', 'severity': 'LOW'}
            ],
            '10. Supply Chain': [
                {'name': 'Malicious Dependency', 'pattern': r'(curl.*?\|.*?bash|pip install.*?--extra-index-url)', 'fix': 'Use pinned versions.', 'severity': 'HIGH'}
            ],
            '11. Container Security': [
                {'name': 'Privileged Container', 'pattern': r'(privileged:\s*true|hostNetwork:\s*true)', 'fix': 'Run as non-root.', 'severity': 'HIGH'}
            ],
            '12. Business Logic': [
                {'name': 'Race Condition', 'pattern': r'(threading\.Thread|asyncio\.create_task).*?(\+=|-=)', 'fix': 'Implement Mutex/Locks.', 'severity': 'MEDIUM'}
            ],
            '13. AI/ML Security': [
                {'name': 'Prompt Injection/Pickle', 'pattern': r'(pickle\.load\(|joblib\.load\(|\.format\(.*?prompt)', 'fix': 'Use safe loaders (json).', 'severity': 'HIGH'}
            ],
            '14. Privacy Compliance': [
                {'name': 'PII Leakage', 'pattern': r'(email|ssn|phone|credit_card)\s*[:=]', 'fix': 'Anonymize PII data.', 'severity': 'MEDIUM'}
            ],
            '15. Distributed Logic': [
                {'name': 'Reentrancy Attack', 'pattern': r'(msg\.sender\.call|transfer\(|lock_state).*?(\-=|\+=)', 'fix': 'Use Checks-Effects-Interactions pattern.', 'severity': 'CRITICAL'}
            ]
        }

    def scan(self, code):
        findings = []
        for category, rules in self.vulnerability_map.items():
            for rule in rules:
                if re.search(rule['pattern'], code, re.IGNORECASE | re.DOTALL):
                    findings.append({'category': category, **rule})
        return findings

# --- UI DESIGN ---
st.title('🛡️ CyberEnterprise Pro v9.2')
st.markdown('### Advanced 15-Vector Vulnerability Scanner')

if 'engine' not in st.session_state:
    st.session_state.engine = EnterpriseLogicEngine()

code_input = st.text_area('Paste Code for Analysis:', height=300)

if st.button('INITIATE SECURITY SCAN'):
    if code_input:
        with st.spinner('AI Logic analyzing security vectors...'):
            results = st.session_state.engine.scan(code_input)
            if results:
                st.error(f'System Breach Risk: {len(results)} vulnerabilities identified.')
                for res in results:
                    with st.expander(f'[{res["severity"]}] {res["name"]}'):
                        st.write(f'**Category:** {res["category"]}')
                        st.success(f'**Recommended Fix:** {res["fix"]}')
            else:
                st.success('No vulnerabilities detected across active vectors.')
    else:
        st.warning('Input required.')

st.sidebar.info('CORE: ONLINE\n\nVECTORS: 15 ACTIVE\n\nMODE: PRODUCTION')
