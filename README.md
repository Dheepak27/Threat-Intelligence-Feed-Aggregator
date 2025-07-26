# Threat-Intelligence-Feed-Aggregator


Link  :  https://huggingface.co/spaces/Dheepak27/SocieteGeneral


# 🛡️ Cyber Threat Intelligence Feed Aggregator

An interactive Gradio-based dashboard that aggregates, summarizes, and analyzes real-time cyber threat intelligence feeds using local Large Language Models (LLMs) via **Ollama**, with fallback to **NLTK** for keyword-based extraction. Built for security analysts, SOC teams, researchers, and students.

---

## 🚀 Features

### 🔥 Threat Feed Aggregation
- Aggregates cyber threat intel from top RSS/Atom sources:
  - The Hacker News
  - BleepingComputer
  - KrebsOnSecurity
  - DarkReading
  - Threatpost
  - US-CERT
- Easily add new feeds through the UI.

### 🤖 AI-Powered Summarization
- Uses **Ollama** to run local LLMs (e.g., LLaMA2, Mistral) for:
  - Incident summarization
  - Threat actor detection
  - Sector/technology targeting
  - Suggested defenses
- If LLMs fail/unavailable, falls back to **NLTK** for keyword-based summarization.

### 🎯 IOC (Indicator of Compromise) Extraction
- Automatically extracts:
  - IPs, Domains, URLs
  - File hashes (MD5, SHA1, SHA256)
  - CVEs, Email addresses, Ports
  - Registry keys, File paths, Mutexes, and more
- Filter IOCs by type in the dashboard
- Export IOCs in **JSON**, **CSV**, or **TXT**

### 🧠 Buzzword & Hashtag Analytics
- Extracts trending cybersecurity tags like `#APT`, `#ZeroDay`, `#Ransomware`
- Displays top tags and mentions in real time

### 🖥️ Custom Cyber-Themed UI
- Built with **Gradio 4.x+**
- Black/red cyberpunk visual theme
- Tab-based interface for:
  - 📊 Dashboard
  - 🔍 Search
  - 🎯 IOC Analysis
  - ⚙️ Feed Management
  - ℹ️ About

---
To Run App
`# 1. Clone the GitHub repository
git clone https://github.com/Dheepak27/Threat-Intelligence-Feed-Aggregator.git

# 2. Change into the project directory
cd Threat-Intelligence-Feed-Aggregator

# 3. Create a virtual environment (optional but recommended)
python -m venv venv
source venv/bin/activate        # For Linux/macOS
venv\Scripts\activate           # For Windows

# 4. Install all required dependencies
pip install -r requirements.txt

# 5. Run the application (Gradio app)
python app.py`
