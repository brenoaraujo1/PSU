FROM python:3.10-slim

# Instala dependências do sistema e ferramentas de segurança
RUN apt-get update && apt-get install -y \
    nmap \
    gobuster \
    seclists \
    wget \
    unzip \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Instalação do Nuclei (binário mais recente Go)
RUN wget https://github.com/projectdiscovery/nuclei/releases/download/v3.3.0/nuclei_3.3.0_linux_amd64.zip \
    && unzip nuclei_3.3.0_linux_amd64.zip -d /usr/local/bin/ \
    && rm nuclei_3.3.0_linux_amd64.zip

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Baixa/atualiza os templates padrão do Nuclei no build
RUN nuclei -update-templates || true