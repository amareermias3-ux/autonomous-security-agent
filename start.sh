#!/bin/bash

echo "🚀 Starting Metasploit RPC daemon..."
msfrpcd -U msf -P changeme -S -a 127.0.0.1 -p 55553 &

# Metasploit እስኪነሳ ትንሽ ጠብቅ
sleep 10

echo "🌐 Starting Streamlit Dashboard on 0.0.0.0:8501..."
# 0.0.0.0 መሆን አለበት ከDocker ውጭ እንዲታይ
streamlit run streamlit_app.py --server.address 0.0.0.0 --server.port 8501
