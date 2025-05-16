# Reputation

Check the reputation of a domain or IP address using multiple services, including VirusTotal, AbuseIPDB, SecurityTrails, and DNS-based blacklists (DNSBLs).

## ✅ Features

* 🔥 **Reputation Checks via APIs:**

  * 🛡️ VirusTotal (API Required)
  * 🚨 AbuseIPDB (API Required)
  * 📜 SecurityTrails for historical DNS data (Optional, API Required)
* 🌐 **DNS-based Blacklist Checks (No API Required)**
* 📅 **Current and Historical Analysis**
* 🚫 **API-less Option for Quick Checks**

---

## 🛠️ Installation

1. **Clone the repository:**

   ```bash
   git clone https://github.com/cdrom0/Reputation.git
   cd Reputation
   ```

2. **Install required packages:**

   ```bash
   pip install requests dnspython argparse
   ```

---

## 🔑 API Keys

This tool uses the following APIs:

* 🛡️ VirusTotal
* 🚨 AbuseIPDB
* 📜 SecurityTrails (Optional for historical DNS)

Replace the placeholders in the script with your actual API keys:

```python
VIRUSTOTAL_API_KEY = "your_virustotal_api_key"
ABUSEIPDB_API_KEY = "your_abuseipdb_api_key"
SECURITYTRAILS_API_KEY = "your_securitytrails_api_key"  # Optional
```

---

## 🧪 Usage

```bash
python Reputation.py <target> [options]
```

### 📦 Arguments:

* `<target>`: The domain or IP address to analyze.

### ⚡ Options:

* `-n`, `--no-api`: Disable all API-based checks.

### 💻 Examples:

1. Check a domain/IP with full analysis (API required):

   ```bash
   python Reputation.py example.com
   ```

2. Check without API (DNSBL only):

   ```bash
   python Reputation.py 192.168.1.1 --no-api
   ```

---

## 📦 Output

The script will provide the following information:

* 🌐 Resolved IP address (if applicable)
* 🔍 Reputation results from VirusTotal and AbuseIPDB (if APIs are enabled)
* 🚫 DNS-based blacklist status
* 🕒 Historical DNS records (if APIs are enabled)
