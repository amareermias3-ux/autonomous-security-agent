# 🛡️ Autonomous Security Agent

ራሱን የሚማር የደህንነት ወኪል — ለKali Linux የተነደፈ ሞጁላር የፔንቴስትሬሽን መሳሪያ።

## ✨ ባህሪያት

| ሞጁል | መግለጫ | ሁኔታ |
|------|--------|------|
| 🔍 **Nmap Recon** | የፖርት እና የአገልግሎት ዳሰሳ | ✅ |
| 💣 **Metasploit Match** | ተጋላጭነቶችን ከexploits ጋር ማመሳሰል | ✅ |
| 🌐 **Burp Integration** | የድር መተግበሪያ ፍተሻ (REST API) | ✅ |
| 🔐 **PQC Checker** | Post-quantum crypto ዝግጁነት | ✅ |
| 🍯 **Honeypot Gen** | ራስ-ሰር የማታለያ አገልጋዮች | ✅ |
| 🤖 **LLM Agent** | ተፈጥሯዊ ቋንቋ ትእዛዝ (Ollama) | ⚠️ |
| 📊 **Reporter** | JSON + HTML ሪፖርቶች | ✅ |

## 🚀 ፈጣን ጅምር

### ቅድመ ሁኔታዎች
- Kali Linux (ወይም Debian-based)
- Python 3.10+
- Nmap (`sudo apt install nmap`)
- Metasploit (`msfrpcd` አስፈላጊ)

### ጭነት
```bash
git clone <repo-url> autonomous-security-agent
cd autonomous-security-agent
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
