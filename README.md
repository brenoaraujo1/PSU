# Plataforma de Segurança Unificada (PSU) - Setup Inicial e Infraestrutura

**Plataforma de Segurança Unificada (PSU)**. A solução combina uma aplicação web em Django com orquestração em contêineres Docker para execução assíncrona de scans de segurança (Nmap/Nuclei) e gestão defensiva. (sujeito a mudanças)

---

## 1. Estrutura do Repositório

O repositório está organizado de forma modular, separando as definições de infraestrutura do código-fonte da aplicação:

```text
PROJETO-UNIFICADO/
├── .gitignore
├── README.md
├── docker/
│   ├── .env
│   ├── .env.example
│   ├── docker-compose.yml
│   └── prometheus/
│       └── prometheus.yml
└── portal-web/
    ├── Dockerfile
    ├── requirements.txt
    ├── manage.py
    ├── portal_web/
    │   ├── __init__.py
    │   ├── celery.py
    │   ├── settings.py
    │   ├── urls.py
    │   └── wsgi.py
    └── scanners/
        ├── admin.py
        ├── models.py
        ├── tasks.py
        └── views.py
```

---

## 2. Arquitetura e Serviços (Docker)

A infraestrutura é orquestrada via **Docker Compose** e isolada na rede de bridge `security-net`. É composta por 7 contêineres:

| Serviço | Contêiner | Descrição / Função | Porta Externa |
| :--- | :--- | :--- | :--- |
| **PostgreSQL** | `security-db` | Banco de dados relacional central do Django e DefectDojo. | Interna (5432) |
| **Redis** | `security-redis` | Broker de mensagens e backend de resultados do Celery. | Interna (6379) |
| **Django (Portal)** | `security-portal` | Interface web e painel de controle administrativo. | `8000` |
| **Celery Worker** | `security-worker` | Executor de background encarregado dos scans (Nmap/Nuclei). | N/A |
| **DefectDojo** | `defectdojo` | Plataforma de gestão e correlação de vulnerabilidades. | `8080` |
| **Prometheus** | `prometheus` | Coletor de métricas do sistema e das aplicações. | `9091` |
| **Grafana** | `grafana` | Painel visual para dashboards de monitoramento. | `3001` |

> **Nota sobre Portas:** As portas do Prometheus (`9091`) e Grafana (`3001`) foram mapeadas fora dos padrões comuns (`9090` e `3000`) para evitar conflitos de socket com serviços nativos do ambiente Kali Linux.

---

## 3. Fluxo de Operação e Automação

```text
[Usuário] -> (Cadastra Alvo no Django Admin)
                  │
                  ▼
         [Banco PostgreSQL]
                  │
                  ▼
     [Trigger: run_nmap_scan.delay()]
                  │
                  ▼
           [Broker Redis]
                  │
                  ▼
         [Celery Worker (Nmap/Nuclei)]
                  │
                  ├──> (Gera Output XML/JSON)
                  └──> (Exporta via API v2) ──> [DefectDojo]
```

1. **Agendamento:** O operador registra um novo alvo (`Target`) via Django Admin (`/admin`).
2. **Enfileiramento Assíncrono:** O evento `save_model` do Django aciona o Celery via Redis, sem travar a interface web.
3. **Execução em Background:** O `celery-worker` executa as ferramentas de varredura diretamente no ambiente Linux do contêiner.
4. **Armazenamento e Integração:** Os dados brutos são salvos na tabela `scanners_scan` e o relatório em XML é enviado diretamente via API v2 para o DefectDojo.

---

## 4. Guia de Implantação Rápida

### Passo 1: Preparar as Variáveis de Ambiente
Na pasta `docker/`, crie o arquivo `.env` baseando-se no modelo `.env.example`:

```env
POSTGRES_DB=security_db
POSTGRES_USER=postgres
DB_PASSWORD=SuaSenhaSegura123!

GRAFANA_ADMIN_USER=admin
GRAFANA_ADMIN_PASSWORD=SuaSenhaGrafana123!

DEFECTDOJO_API_KEY=sua_chave_api_defectdojo
```

### Passo 2: Subir a Infraestrutura na VM
Dentro do diretório `docker/`, execute a compilação e inicialização dos serviços:

```bash
docker compose up -d --build
```

### Passo 3: Executar Migrações e Criar Superusuário
Com os contêineres ativos, prepare a estrutura do banco de dados relacional:

```bash
# Aplica as tabelas no PostgreSQL
docker compose exec web-portal python manage.py migrate

# Cria o usuário Administrador para acesso ao Django Admin
docker compose exec web-portal python manage.py createsuperuser
```

---

## 5. Endereços de Acesso (Localhost / VM)

* **Painel Django:** `http://localhost:8000/admin`
* **DefectDojo:** `http://localhost:8080`
* **Prometheus:** `http://localhost:9091`
* **Grafana:** `http://localhost:3001`

---

## 6. Conexão Remota Entre Máquinas Físicas (Opcional)

Para permitir que outra máquina física na rede local acesse a aplicação rodando dentro da VM:

1. No VirtualBox, altere a placa de rede da VM para **Modo Bridge** (*Bridged Adapter*).
2. Na VM, rode `ip a` e identifique o IP local atribuído pelo roteador (Ex: `192.168.1.50`).
3. A partir de qualquer máquina na mesma rede, acesse os serviços usando o IP da VM:
   * **Portal Django:** `http://192.168.1.50:8000`
   * **DefectDojo:** `http://192.168.1.50:8080`
