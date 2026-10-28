FROM python:3.10-slim

# Instala dependências do sistema e ferramentas de segurança
# Retentativas (Acquire::Retries) toleram falhas momentâneas de DNS/rede no build.
RUN apt-get -o Acquire::Retries=5 update \
    && apt-get -o Acquire::Retries=5 install -y --no-install-recommends \
       nmap \
       gobuster \
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

# Wordlist do Gobuster (SecLists) baixada do repositório oficial.
# O pacote apt 'seclists' não está disponível nos repositórios Debian da imagem.
# Se a URL mudar, o build falha aqui (wget com erro) em vez de gerar uma imagem quebrada.
RUN mkdir -p /opt/wordlists \
    && wget -q -O /opt/wordlists/common.txt \
       https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt
ENV GOBUSTER_WORDLIST=/opt/wordlists/common.txt

# Baixa/atualiza os templates padrão do Nuclei no build
RUN nuclei -update-templates || true