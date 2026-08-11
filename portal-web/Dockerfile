FROM python:3.10-slim

# Instala ferramentas do sistema e scanner Nmap
RUN apt-get update && apt-get install -y \
    nmap \
    iputils-ping \
    wget \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Instala o scanner Nuclei
RUN wget https://github.com/projectdiscovery/nuclei/releases/download/v3.0.0/nuclei_3.0.0_linux_amd64.zip \
    && unzip nuclei_3.0.0_linux_amd64.zip \
    && mv nuclei /usr/local/bin/ \
    && rm nuclei_3.0.0_linux_amd64.zip

WORKDIR /app

COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app/