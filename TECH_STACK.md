# Stack de Desenvolvimento e Tecnologia — AmpScan

Este documento detalha a pilha tecnológica, bibliotecas, ferramentas de sistema e decisões técnicas que compõem o **ampscan** (v1.3.2).

---

## 1. Linguagem e Runtime Principal

* **Linguagem**: **Rust (Edição 2021)**
  * **Motivação**: Garantia de segurança de memória sem overhead de *garbage collector*, prevenção de *data races* em concorrência massiva, previsibilidade de recursos e alta performance em operações I/O de rede.
* **Runtime Assíncrono**: [`tokio 1.x`](file:///home/gondim/projetos/ampscan/Cargo.toml#L13) (`features = ["full"]`)
  * **Uso**: Orquestração não-bloqueante de envio/recebimento de pacotes de rede (UDP e TCP), controle fino de concorrência concorrente via semáforos assíncronos (`tokio::sync::Semaphore`) e controle de cooperação entre threads (`yield_now`).

---

## 2. Banco de Dados e Segurança de Dados em Repouso

* **Mecanismo de Armazenamento**: **SQLite3 + SQLCipher** via [`rusqlite 0.32`](file:///home/gondim/projetos/ampscan/Cargo.toml#L58-L64)
  * **Criptografia**: Cifragem transparente AES-256-CBC em repouso para todo o banco de dados contendo usuários, prefixos, portas e histórico de relatórios.
  * **Build Estático/Cross-platform**: 
    * No **Windows** e **Linux ARM64**: Compilado com a feature `bundled-sqlcipher-vendored-openssl` (compilação estática do SQLCipher e do OpenSSL).
    * Nas demais plataformas Unix/Linux/macOS: Utiliza a feature `bundled-sqlcipher`.
* **Derivação de Senhas & Autenticação**: [`argon2 0.5`](file:///home/gondim/projetos/ampscan/Cargo.toml#L16) (**Argon2id**)
  * **Uso**: Algoritmo seguro de derivamento de chave e hashing de senhas dos administradores locais.
* **Higiene de Memória na Heap**: [`zeroize 1.9`](file:///home/gondim/projetos/ampscan/Cargo.toml#L55)
  * **Uso**: Sobrescrita imediata de chaves e senhas brutas na memória Heap (`AMPSCAN_DB_KEY`) assim que o banco criptografado é aberto, minimizando janelas de exposição em dumps de memória.

---

## 3. Interface de Linha de Comando (CLI) e UX

* **Parser de Argumentos**: [`clap 4.x`](file:///home/gondim/projetos/ampscan/Cargo.toml#L10) (`features = ["derive", "env"]`)
  * **Uso**: Declaração estruturada de subcomandos (`init`, `scan run`, `port list`, etc.), flags de controle (`--concurrency`, `--retries`, `--pdf`) e suporte a login não-interativo por variável de ambiente (`AMPSCAN_PASS`).
* **Formatação de Tabelas**: [`comfy-table 7.x`](file:///home/gondim/projetos/ampscan/Cargo.toml#L49)
  * **Uso**: Renderização de tabelas limpas com bordas e alinhamento no terminal para listagens de portas, blocos IP e relatórios sumarizados.
* **Estilização e Cores**: [`colored 2.x`](file:///home/gondim/projetos/ampscan/Cargo.toml#L40)
  * **Uso**: Destaque visual colorido por criticidade (ex: amarelo para status `Open/Protected`, verde/amarelo/vermelho para faixas de latência).
* **Entrada Oculta de Senhas**: [`rpassword 7.x`](file:///home/gondim/projetos/ampscan/Cargo.toml#L43)
  * **Uso**: Captura de senhas do administrador sem exibir eco de caracteres no terminal.

---

## 4. Motor de Escaneamento e Protocolos de Rede

* **Manipulação de Prefixos IP**: [`ipnet 2.x`](file:///home/gondim/projetos/ampscan/Cargo.toml#L19)
  * **Uso**: Validação rigorosa de blocos CIDR (IPv4 e IPv6) e suporte a expansão iterativa completa de faixas.
* **Sondas de Amplificação (Probes)**: Módulo interno [`src/scanner/probes.rs`](file:///home/gondim/projetos/ampscan/src/scanner/probes.rs)
  * **Uso**: Construção manual e serialização de payloads binários de protocolo (DNS, NTP, SNMP, Memcached, SSDP, TFTP, LDAP, NetBIOS, SLP, RPC, MikroTik, etc.) enviados sobre sockets UDP/TCP nativos do Tokio.

---

## 5. Geração de Relatórios e Imagens

* **Motor de PDF**: [`printpdf 0.12`](file:///home/gondim/projetos/ampscan/Cargo.toml#L22) (`features = ["png", "jpeg"]`)
  * **Uso**: Construção vetorial 2D dinâmica de documentos PDF sem dependências externas de sistema (como wkhtmltopdf ou bibliotecas C de terceiros).
* **Processamento de Imagens**: [`image 0.24`](file:///home/gondim/projetos/ampscan/Cargo.toml#L23)
  * **Uso**: Leitura, verificação de magic bytes (PNG/JPEG) e renderização dos logotipos customizados da empresa auditora no cabeçalho do PDF.

---

## 6. Integração com Sistema Operacional e Sistema de Arquivos

* **Ajuste de Limites do Sistema**: [`libc 0.2`](file:///home/gondim/projetos/ampscan/Cargo.toml#L52)
  * **Uso**: Chamadas de sistema Unix (`rlimit`/`getrlimit`/`setrlimit`) para autorregulagem automática de descritores de arquivos de socket (*soft limit* para o *hard limit*), prevenindo erros de exaustão (`EMFILE`).
* **Datas e Identificadores**: [`chrono 0.4`](file:///home/gondim/projetos/ampscan/Cargo.toml#L34) e [`uuid 1.x`](file:///home/gondim/projetos/ampscan/Cargo.toml#L46)
  * **Uso**: Geração de datas formatadas para os relatórios e geração de UUIDv4 para identificação única das varreduras salvas.
* **Configuração**: [`toml 0.8`](file:///home/gondim/projetos/ampscan/Cargo.toml#L28) e [`serde 1.x`](file:///home/gondim/projetos/ampscan/Cargo.toml#L26)
  * **Uso**: Carregamento e serialização de arquivos de configuração locais (`config.toml`).

---

## 7. Infraestrutura de CI/CD e Build Multiplataforma

* **Validação de Código (CI)**: GitHub Actions (`ci.yml`) testando `cargo check` e `cargo test` em ambientes Linux e macOS.
* **Automação de Release (CD)**: GitHub Actions (`release.yml`) acionado por tags `v*` compilando binários estáticos para:
  * Linux x86_64 (`x86_64-unknown-linux-gnu`)
  * Linux ARM64 (`aarch64-unknown-linux-gnu`) via ferramenta `cross` (Docker)
  * Windows x86_64 (`x86_64-pc-windows-msvc`)
  * macOS Intel & Apple Silicon (`x86_64-apple-darwin` / `aarch64-apple-darwin`)
  * FreeBSD x86_64 (`x86_64-unknown-freebsd`) via VM (`freebsd-vm`)
