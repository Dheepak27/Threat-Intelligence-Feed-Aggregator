# 🛡️ Cyber Threat Intelligence Feed Aggregator

🔗 **Live Demo**: [Explore on Hugging Face Spaces](https://huggingface.co/spaces/Dheepak27/SocieteGeneral)

An interactive **Gradio-powered dashboard** that aggregates, summarizes, and analyzes real-time cyber threat intelligence from curated feeds. Leveraging **local LLMs via Ollama**, and backed by **NLTK** for fallback summarization, this tool empowers security analysts, researchers, and SOC teams to stay ahead of emerging threats.

---

## 🚀 Features

### 🔥 Threat Feed Aggregation
- Aggregates threat intelligence from leading RSS/Atom sources:
  - The Hacker News
  - BleepingComputer
  - KrebsOnSecurity
  - DarkReading
  - Threatpost
  - US-CERT
- Add and manage custom feeds directly via the dashboard.

---

### 🤖 AI-Powered Threat Summarization
- Uses **Ollama** with local models like **LLaMA2**, **Mistral**, or others to summarize:
  - Nature of threats or vulnerabilities  
  - Known threat actors or campaigns  
  - Affected technologies or sectors  
  - Recommended security responses  
- If Ollama isn't available, falls back to **NLTK** for lightweight keyword-based summaries.

---

### 🎯 IOC (Indicator of Compromise) Extraction
- Automatically identifies and extracts key IOCs including:
  - IP addresses, domains, URLs
  - File hashes (MD5, SHA1, SHA256)
  - CVEs, email addresses, file paths
  - Registry keys, mutex names, ports, and more
- Filter results by IOC type.
- Export in your preferred format: **JSON**, **CSV**, or **TXT**.

---

### 🧠 Buzzword & Hashtag Analysis
- Extracts and tracks trending cybersecurity tags like:
  - `#APT`, `#ZeroDay`, `#Ransomware`, `#Malware`, etc.
- Helps users stay updated on industry buzzwords, attack patterns, and threat actor mentions.

---

### 📊 Graph Analytics & Visual Insights
- Visualize trending hashtags with **interactive bar charts** powered by **Plotly**.
- Automatically updates based on incoming articles.
- Helps analysts identify the most discussed threats in real-time.
- Supports data-driven threat monitoring for SOC dashboards and security research.

---

### 🖥️ Custom Cyber-Themed Interface
- Built with **Gradio 4.x+** for clean, responsive UI.
- Designed with a sleek **charcoal blue/electric indigo (blue-violet shade) cyberpunk aesthetic** to match the threat intel theme.
- Fully interactive and minimal setup — runs in browser.
- Tab-based layout for intuitive navigation:
  - 📊 **Dashboard** – View AI-generated summaries, trending buzzwords, and analytics
  - 🔍 **Search** – Find specific articles by keyword or filter by feed source
  - 🎯 **IOC Analysis** – Explore extracted indicators by type and export them
  - ⚙️ **Feed Management** – Add new RSS/Atom sources for threat aggregation
  - ℹ️ **About** – Learn how the tool works and where to contribute
- 📈 **Graph Analytics**: Interactive bar charts display the most common cybersecurity hashtags and tags across articles, offering real-time visibility into trending threats.


---

## 📦 Tech Stack

- **Frontend:** Gradio
- **Backend:** Python 3.10+, `feedparser`, `requests`, `beautifulsoup4`, `pandas`
- **AI Integration:** Ollama LLMs, NLTK (fallback)
- **Visualization:** Plotly
- **Deployment:** Hugging Face Spaces (Cloud) / Local Python environment

---

📦 Threat-Intelligence-Feed-Aggregator/  
├── app.py                 — Main Gradio application (UI and logic)  
├── ai_summarizer.py       — Handles AI summarization (Ollama + NLTK fallback)  
├── ioc_extractor.py       — Extracts Indicators of Compromise (IOCs)  
├── visualization_utils.py — Creates analytics charts using Plotly  
├── requirements.txt       — List of required Python packages  
└── README.md              — Project documentation (this file)


## 🚀 Getting Started

Follow these steps to clone and run the Threat Intelligence Feed Aggregator locally:

```bash
# 1. Clone the repository
git clone https://github.com/Dheepak27/Threat-Intelligence-Feed-Aggregator.git

# 2. Navigate into the project directory
cd Threat-Intelligence-Feed-Aggregator

# 3. (Optional) Create and activate a virtual environment
python -m venv venv
source venv/bin/activate        # For Linux/macOS
venv\Scripts\activate           # For Windows

# 4. Install dependencies
pip install -r requirements.txt

# 5. Run the app
python app.py

```

## 👥 Team  
22BPS1120 - Kamalesh D<br>
22BPS1177 - Dheepak S<br>
22BPS1193 - Sujith P<br>
22BPS1195 - Monish Raj H



