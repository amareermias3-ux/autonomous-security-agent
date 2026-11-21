FROM kalilinux/kali-rolling

# አስፈላጊ የሆኑ መሳሪያዎችን ጫን
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    metasploit-framework \
    openssl \
    python3 \
    python3-pip \
    python3-venv \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# የስራ አቃፊ ፍጠር
WORKDIR /app

# የPython ፓኬጆችን ጫን (venv ሳንጠቀም በቀጥታ)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt --break-system-packages

# የፕሮጀክቱን ፋይሎች በሙሉ ገልብጥ
COPY . .

# የስታርት ስክሪፕቱን የማስኬጃ ፈቃድ ስጠው
RUN chmod +x start.sh

# Streamlit ፖርት ክፈት
EXPOSE 8501

# Metasploit RPC ፖርት ክፈት
EXPOSE 55553

# ስታርት ስክሪፕቱን አስኪድ
CMD ["./start.sh"]
