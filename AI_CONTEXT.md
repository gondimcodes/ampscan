# AmpScan — Contexto do Projeto AI_CONTEXT.md

## 📌 Objetivo do Projeto
O **AmpScan** é uma ferramenta de auditoria de segurança desenvolvida em Rust para escanear, identificar e reportar portas de rede suscetíveis a ataques de **amplificação DDoS** (Distributed Denial of Service) em prefixos IPv4 e IPv6 (CIDRs). O sistema armazena configurações de portas, prefixos de redes, e credenciais de usuários em um banco de dados SQLite criptografado via **SQLCipher** (AES-256), e gera relatórios em **PDF** após a execução dos testes.

---

## 🛠️ Stack Tecnológica
*   **Linguagem:** Rust (Edição 2021)
*   **Runtime Assíncrono:** `tokio` (com suporte completo a tasks e I/O)
*   **Banco de Dados:** SQLite + `rusqlite` com a feature `bundled-sqlcipher` (criptografia AES-256 em repouso)
*   **Segurança e Hashing:** `argon2` para hashing de senhas de administradores (`Argon2id`)
*   **Parsing CLI:** `clap` (com derive macro e suporte a variáveis de ambiente)
*   **Geração de Relatórios:** `printpdf` (versão 0.7, escrita de PDF de baixo nível com fontes nativas do leitor)
*   **Utilitários de Rede:**
    *   `ipnet` para manipulação e expansão de prefixos CIDR.
    *   `surge-ping` para validações ICMP assíncronas de hosts ativos.
*   **Aparência e Formatação CLI:** `comfy-table` para exibição de dados tabulares estruturados e `colored` para estilização do console.
*   **Outros:** `rpassword` para leitura segura de senhas no terminal e `uuid` para identificação de sessões de scan.

---

## 📂 Arquitetura e Estrutura de Diretórios

O código-fonte está organizado modularmente sob o diretório `src/`:

```
src/
├── main.rs            # Entrypoint da aplicação, parser da CLI e coordenação dos subcomandos
├── lib.rs             # Declarações públicas dos submódulos da biblioteca
├── auth.rs            # Lógica de criptografia, geração de hash Argon2id e prompts de senha
├── report.rs          # Motor de geração de relatórios PDF estruturados usando printpdf v0.7
├── db/                # Módulo de persistência e banco de dados
│   ├── mod.rs         # Inicialização do SQLCipher, migrations de esquema e gerenciamento de conexão
│   ├── models.rs      # Modelos/structs de dados (Port, Prefix, User)
│   ├── port_repo.rs   # Operações no banco para portas de amplificação (inclui seed de 20 portas padrão)
│   ├── prefix_repo.rs # Operações no banco para prefixos de redes (adicionar, listar, editar, habilitar)
│   └── user_repo.rs   # Operações para gerenciamento e autenticação de usuários administradores
└── scanner/           # Motor de varredura (scanning) de rede
    ├── mod.rs         # Coordenação assíncrona concorrente das tarefas de scan
    ├── probes.rs      # Implementação individual dos probes de rede (ICMP, TCP, UDP e payloads específicos)
    └── result.rs      # Estruturação e filtros sobre os resultados e relatórios do scan
```

---

## 📡 Portas de Amplificação Padrão
O banco de dados é populado automaticamente na inicialização (`ampscan init`) com 20 portas de amplificação comumente exploradas por atacantes:
1.  **UDP 17 (QOTD):** Quote of the Day
2.  **UDP 19 (CHARGEN):** Character Generator
3.  **UDP 53 (DNS):** Domain Name System (Resolvedor Aberto)
4.  **UDP 69 (TFTP):** Trivial File Transfer Protocol
5.  **UDP 111 (RPC):** Portmapper RPC
6.  **UDP 123 (NTP):** Network Time Protocol (com probe `readvar` / `monlist`)
7.  **UDP 137 (NETBIOS):** NetBIOS Name Service
8.  **UDP 161 (SNMP):** Simple Network Management Protocol (community `public`)
9.  **UDP 389 (LDAP):** CLDAP (Connectionless LDAP)
10. **UDP 427 (SLP):** Service Location Protocol (payload customizado)
11. **UDP 1900 (SSDP):** Simple Service Discovery Protocol
12. **UDP 3283 (ARMS):** Apple Remote Management Service
13. **UDP 3702 (WS-DISCOVERY):** Web Services Dynamic Discovery
14. **UDP 5353 (mDNS):** Multicast DNS
15. **UDP 5683 (CoAP):** Constrained Application Protocol
16. **UDP 10001 (UBNT):** Ubiquiti Discovery Protocol
17. **UDP 11211 (MEMCACHED):** Memcached Server
18. **UDP 37810 (DVR-DHCPDiscover):** DVR DHCP Discovery
19. **TCP 4145 (MT4145):** SOCKS proxy MikroTik aberto
20. **TCP 5678 (MT5678):** MikroTik Meris botnet indicator

---

## ⚡ Probes e Payload Builders (`src/scanner/probes.rs`)
A ferramenta implementa lógica dedicada para montar pacotes UDP válidos de consulta para os principais protocolos:
*   **DNS:** Constrói uma query padrão `A` por `google.com`.
*   **mDNS:** Constrói uma query `PTR` por `_services._dns-sd._udp.local`.
*   **SNMP:** Constrói uma requisição `GetRequest` pelo OID do `sysDescr.0` com a comunidade `public`.
*   **NTP:** Envia um pacote de controle NTP (modo 6) com opcode 2 (`readvar`).
*   **SSDP:** Envia a mensagem HTTP `M-SEARCH` para discovery UPnP.
*   **TFTP / NETBIOS / RPC / LDAP / MEMCACHED:** Montam estruturas binárias exatas equivalentes aos comandos reais dos serviços correspondentes.
*   **Payload Customizado (`udp_payload`):** Suporta payloads binários customizados cadastrados em hexadecimal no banco.

---

## 🛠️ Comandos da CLI (`ampscan`)

A CLI exige a variável de ambiente `AMPSCAN_DB_KEY` para abrir ou criar o banco de dados.

### Variáveis de Ambiente Suportadas:
*   `AMPSCAN_DB_KEY`: Chave de criptografia de 256 bits (ex: string com mais de 32 caracteres). **[Obrigatória]**
*   `AMPSCAN_DB_PATH`: Caminho alternativo do arquivo do banco (padrão: `ampscan.db`).
*   `AMPSCAN_USER`: Nome do usuário administrador para evitar prompt iterativo de username.

### Subcomandos Disponíveis:
1.  **`ampscan init`**
    *   Cria e criptografa o arquivo SQLite.
    *   Insere as 20 portas padrão de amplificação.
    *   Solicita interativamente a criação do usuário administrador inicial.
2.  **`ampscan port <SUBCOMANDO>`**
    *   `list`: Lista todas as portas cadastradas no banco em formato de tabela.
    *   `add`: Cadastra nova porta de teste, permitindo especificar payload em hexadecimal.
    *   `edit <ID>`: Edita nome/descrição de uma porta.
    *   `remove <ID>`: Exclui uma porta do cadastro.
    *   `enable/disable <ID>`: Habilita ou desabilita a porta nos escaneamentos.
3.  **`ampscan prefix <SUBCOMANDO>`**
    *   `list`: Lista prefixos de rede (CIDRs) cadastrados.
    *   `add`: Cadastra novo CIDR (IPv4 ou IPv6).
    *   `edit/remove/enable/disable <ID>`: Gerenciamento dos prefixos habilitados para o scan.
4.  **`ampscan user <SUBCOMANDO>`**
    *   `list`: Lista todos os usuários administradores.
    *   `add`: Cria novo usuário administrador de rede.
    *   `change-password`: Atualiza a senha de um usuário.
    *   `remove <ID>`: Remove um administrador.
5.  **`ampscan scan <SUBCOMANDO>`**
    *   `run`: Executa o escaneamento em paralelo de todos os IPs contidos nos prefixos habilitados, testando contra as portas ativas. Gera o relatório PDF (padrão: `ampscan_report.pdf`).
        *   Opções: `--concurrency <N>`, `--timeout <S>`, `--output <PATH>`, `--no-icmp` (ignora ping ICMP).
    *   `single <IP>`: Faz uma varredura direta contra um único IP de destino, imprimindo os resultados em tempo real na tela.

---

## 📈 Estado Atual do Desenvolvimento
*   **Compilação:** Compilando 100% sem erros ou warnings, tanto em profile de `debug` quanto `release`.
*   **Testes:** Todos os 11 testes unitários incluídos na suíte passam com sucesso (`cargo test` OK).
*   **Segurança:** Toda interação sensível a senhas (login, criação de usuário) utiliza `rpassword` para omitir eco de caracteres. O banco de dados SQLite está completamente protegido com AES-256 e os hashes das senhas são gerados via Argon2id de forma isolada e segura.
*   **ICMP Reachability:** Lógica integrada usando `surge-ping` para hosts ativos (requer privilégios administrativos/root no Linux para abrir sockets ICMP crus). Se executado sem privilégios ou com a flag `--no-icmp`, a ferramenta faz um fallback inteligente tentando conexões TCP heurísticas em portas padrão.
