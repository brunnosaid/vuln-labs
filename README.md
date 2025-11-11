# Vuln Lab Flask

Laboratório local para estudo de vulnerabilidades e análise (XSS, SQLi, headers, reverse-shell detection, análise estática de binários, IOCs de rede).

**Segurança**: este projeto é educacional. Rode sempre em ambiente isolado (VM/container) e NUNCA aponte portas para a internet pública.

## Requisitos
- Python 3.10+
- (opcional) Docker & docker-compose

## Instalação local
1. `python -m venv .venv`
2. `. .venv/bin/activate` (Linux/mac) ou `.venv\Scripts\activate` (Windows)
3. `pip install -r requirements.txt`
4. `python init_db.py`
5. `python app.py`
6. Acesse `http://localhost:5000`

## Usando com Docker
1. `docker-compose up --build`
2. Acesse `http://localhost:5000`

## O que cada tela faz
- **XSS**: playground reflected / stored / DOM. *As views intencionalmente mostram conteúdo sem escape para aprendizado.*
- **Headers**: endpoint ecoa headers, cookies e body (use Burp para experimentar).
- **SQLi**: formulário login; troque mode para `vulnerable` ou `safe` para comparar.
- **Shell**: cole strings suspeitas (comandos) e veja heurísticas que podem indicar tentativa de shell.
- **Binary**: upload limitado (máx 10MB). Faz análise estática: SHA256, entropy, strings. NÃO executa o arquivo.
- **Network**: cole logs, o sistema checa uma lista de IOCs de exemplo.

## Extensões sugeridas
- integrar YARA (scanner container)
- regras mais avançadas para detecção de shellcode/entropia
- painel de métricas (Grafana/Kibana)
- exercícios automatizados (curl scripts)

## Disclaimer
Uso apenas educativo. Não use este material para atividades ilegais.
