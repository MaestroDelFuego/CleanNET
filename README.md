**CleanNET DNS is a local DNS server and monitoring dashboard designed for domain-level content filtering and risk assessment. It helps block access to advertising and phishing domains, resolves certain domains to custom IPs, and forwards all other queries to upstream DNS servers.**

**Features**
🛡️ DNS Filtering & Resolution
Ad Domain Blocking: Filters domains listed in ads.txt.

**Phishing Protection:** Uses a local phishing authority API to evaluate domain risks in real-time.

**Custom Resolutions:** Supports domain-to-IP overrides (e.g., fx.local to 192.168.1.141).

**Upstream Forwarding:** For non-blocked queries, CleanNET DNS forwards requests to DNS providers like Google (8.8.8.8) or Cloudflare (1.1.1.1).

**🌐 Web-Based Dashboard**
Real-time domain risk checker.

Lists of currently blocked ad and phishing domains.

Basic system health stats (CPU load, RAM usage, uptime).
