# Visão Geral

O `ampscan` é uma ferramenta CLI em Rust voltada para auditorias de segurança de rede e testes de portas de amplificação para ataques de negação de serviço distribuído (DDoS). Ele varre faixas IP (IPv4 e IPv6) para identificar serviços vulneráveis que expõem portas UDP/TCP e podem ser explorados como refletores/amplificadores de tráfego.

# Objetivos

*   Identificar servidores vulneráveis e expostos publicamente a riscos de amplificação DDoS.
*   Fornecer relatórios executivos e técnicos em formato PDF e saídas formatadas no terminal (CLI).
*   Garantir a confidencialidade e segurança dos dados coletados salvando-os em um banco de dados local criptografado.

# Escopo

*   Suporte a escaneamento concorrente de sub-redes IPv4 e IPv6 com limite de segurança configurável.
*   Mapeamento de serviços comuns de amplificação: DNS, NTP, SNMP, Memcached, SSDP, TFTP, LDAP, NetBIOS, RPC, entre outros.
*   Geração de relatórios PDF com suporte a customização da empresa auditora por meio de arquivo de configuração local e dados dinâmicos do cliente/destinatário.

# Arquitetura Atual

O projeto é construído em Rust e utiliza uma arquitetura modularizada:
*   **Módulo CLI (`src/main.rs`)**: Gerencia o parseamento de comandos com a biblioteca `clap`, o controle de fluxo de execução dos comandos (`init`, `scan run`, `port list`, etc.), a autenticação de usuários administradores e a renderização das tabelas de saída no terminal (`comfy-table`).
*   **Mecanismo de Escaneamento (`src/scanner/mod.rs`)**: Controla a concorrência assíncrona baseada em semáforos, a resolução/expansão de prefixos CIDR e a execução coordenada das sondagens de liveness (ICMP) e probes de portas ativos.
*   **Mecanismo de Probes (`src/scanner/probes.rs`)**: Contém a implementação detalhada dos payloads de rede UDP/TCP para cada serviço testado, lidando com a construção manual de cabeçalhos e decodificação básica de respostas para computar o fator de amplificação.
*   **Banco de Dados Criptografado (`src/db/`)**: Interface com o SQLite integrado com a extensão SQLCipher para armazenar credenciais de usuários, portas configuradas, prefixos salvos e históricos de relatórios em repouso com cifragem AES-256.
*   **Geração de Relatórios (`src/report.rs`)**: Lógica dedicada a construir e formatar documentos PDF dinâmicos contendo tabelas de resultados de varreduras utilizando a biblioteca `printpdf`.

# Componentes

1.  **Scanner**: Orquestrador que expande os blocos CIDR para IPs individuais, filtra os ativos (liveness check) e dispara as probes sob concorrência estrita controlada (`tokio::sync::Semaphore`).
2.  **Probes**: Módulo contendo os payloads específicos enviados para detecção de vulnerabilidade (ex: requisição wildcard de NetBIOS, consulta de estatísticas do Memcached, requisições de DNS do tipo ANY, etc.).
4.  **PDF Generator**: Layout dinâmico com quebra de página, suporte a logotipos e dados personalizados de clientes/destinatários.

# Estado Atual

*   O projeto está na versão **1.3.1** (com suporte estendido de CI/CD).
*   A base de código compila limpa em modo Release (`cargo build --release`) sem nenhum warning e possui cobertura estável através de 21 testes automatizados (`cargo test`).
*   A varredura CIDR está configurada para expandir todas as faixas completas de IP (incluindo endereços de rede e broadcast no caso de IPv4, como `.0` e `.255`).

# Funcionalidades Concluídas

*   **Substituição Completa para Nmap no PDF**: Comandos de validação manual no PDF que apenas testavam conectividade básica por porta (como UDP/TCP fallback, QOTD e CHARGEN) foram migrados de `nc` para `nmap -sU` ou `nmap -sT` para maior consistência. As portas do MikroTik (`MT4145`/`MT5678`) também geram comandos de validação baseados em `nmap -sT`. Pipelines mais complexos (como Memcached, SSDP e SLP) continuam usando `printf | nc` para envio de payloads.
*   **Configuração de Concorrência e Retentativas**: Adicionadas as flags `--concurrency` e `--retries` aos comandos de scan (`run` e `single`), permitindo aos usuários ajustar o desempenho e a agressividade do scanner.
*   **Auto-Ajuste de Limites de Arquivos (ulimit)**: Implementada a elevação automática do limite de descritores de arquivos (*soft limit* para o *hard limit*) no início do scan sob Unix/Linux para evitar erros de recursos.
*   **Detecção de Exaustão de Sockets**: Interrupção elegante e informativa do scan com aviso explícito de `ulimit` caso o sistema operacional retorne erros do tipo `EMFILE` / `ENFILE` durante o disparo das probes.
*   **Ajuste de Range CIDR**: Substituição do método `.hosts()` da biblioteca `ipnet` (que omitia limites de rede/broadcast) por cálculo manual baseado nas extremidades do prefixo IPv4 (`network` a `broadcast`).
*   **Geração Opcional de PDF e Customização**: Implementação da flag `--pdf`, `--client-name` e `--recipient` para parametrizar o relatório do scan. Carregamento opcional dos dados da empresa auditora via `config.toml`.
*   **Formatos de Imagem Dinâmicos no Relatório**: Validação de arquivos de logo via magic bytes no backend de PDF, aceitando arquivos PNG/JPEG mesmo se renomeados incorretamente.
*   **Ajuste Visual de Status Protected**: Cores de IP e do status `Open/Protected` atualizadas de verde para amarelo no CLI.
*   **Correção de Payload NetBIOS**: Refatoração do pacote UDP da porta 137 para utilizar Transaction ID aleatório e padding idêntico ao comando `nmblookup` para máxima compatibilidade.
*   **Segurança no Fluxo de Banco**: Bloqueio de auto-criação silenciosa de arquivos de banco vazios em comandos de leitura/escaneamento se a base de dados não tiver sido previamente inicializada via comando `init`.
*   **Automação via AMPSCAN_PASS**: Implementada a variável de ambiente `AMPSCAN_PASS` para autenticação não interativa, ideal para automação de scans via cron.
*   **Remoção de Liveness Check (ICMP/TCP)**: Exclusão completa da verificação de atividade por Ping e TCP fallback. A detecção de liveness agora é inferida diretamente das portas ativas (UDP/TCP), eliminando falsos negativos em roteadores UDP e dispensando privilégios de root para a execução padrão.
*   **Remoção da Dependência `surge-ping`**: Limpeza e redução do tempo de compilação da base de código Rust.
*   **Melhorias na UX e Feedback de Progresso**: Adicionado spinner de preparação (`Preparing probes...`) com rendição cooperativa (`yield_now`) das tarefas do Tokio, e aumentada a taxa de atualização da barra de progresso para evitar congelamento visual em grandes varreduras.
*   **Validação Manual no PDF**: Adicionada a página "Manual Validation Procedures" ao final do PDF gerado com comandos baseados em CLI contendo placeholder `<IP>` para testes individuais.
*   **Integração e Versionamento**: Repositório Git configurado e sincronizado com a origem remota do GitHub. Tags correspondentes geradas até a versão `v1.3.1`.
*   **Scanner com Streaming e Baixo Consumo de Memória**: Implementado padrão `acquire-before-spawn` no motor de varredura. O semáforo de concorrência agora é adquirido *antes* de spawnar cada task, limitando o número de tasks em voo a exatamente `concurrency`. Varreduras de `/16` × 20 portas (1.3M probes) agora consomem pico de memória proporcional à concorrência configurada, não ao tamanho total do scan.
*   **Eliminação de Clonagens por Probe**: Os structs `Port` (com múltiplos campos `String`) são agora compartilhados via `Arc<Port>` entre as tasks em vez de clonados. Elimina ~1.3M heap allocations in varreduras de `/16`.
*   **Contrato de Timeout Corrigido**: `--timeout 3` agora significa estritamente 3 segundos por tentativa, sem a divisão silenciosa por 2 que existia na v1.2.x.
*   **Sistema de Migrations com Versionamento**: Adicionada tabela `schema_version` ao banco criptografado. Migrations futuras podem alterar o schema de forma incremental sem exigir re-inicialização do banco.
*   **Remoção do Parâmetro `use_icmp` Morto**: O parâmetro `use_icmp: bool` foi removido de `execute_probe` e todas as funções internas de probe — vestígio da remoção do liveness check que nunca foi limpo.
*   **Tratamento de PoisonError nos Locks do Banco**: Substituição de `.lock().unwrap()` por helper `lock_db()` que retorna erro recuperável em caso de Mutex poisoning, prevenindo panic em cascata.
*   **Zeroize da Chave do Banco**: A chave de cifragem AES-256 (`AMPSCAN_DB_KEY`) é sobrescrita com zeros na heap imediatamente após o banco ser aberto, reduzindo a janela de exposição em dumps de memória.
*   **Remoção da Chave do Ambiente**: `get_db_key()` agora remove `AMPSCAN_DB_KEY` do ambiente do processo após leitura, impedindo herança por processos filhos.
*   **Validação Antecipada de `--prefix`**: O CIDR fornecido via `--prefix` é validado (parse + verificação de tamanho) antes da autenticação, dando feedback imediato.
*   **Detecção de IP Version por IpNet**: Substituída heurística `contains(':')` por `IpNet::parse()` + `net.addr().is_ipv4()` para determinação robusta da versão IP.
*   **Busca Multi-path do `config.toml`**: Agora procura o arquivo de configuração primeiro no diretório do executável, depois no diretório de trabalho atual — resolve a situação onde `ampscan` é rodado de um diretório diferente de onde o config está.
*   **Aviso de Segurança para `AMPSCAN_PASS`**: Login não-interativo via variável de ambiente agora emite aviso explícito sobre risco de exposição in `/proc/<pid>/environ`.
*   **Documentação Completa de CI/CD**: Adicionada seção explicativa e detalhada no manual do projeto (`README.md`) cobrindo as pipelines do GitHub Actions para teste, checagem estática de código (CI) e o pipeline de build multiplataforma automatizado para geração de releases e binários executáveis estáticos (CD).
*   **Expansão Multiplataforma do CI/CD**: Adicionado suporte completo para builds em **macOS** (Apple Silicon/aarch64 e Intel/x86_64), **Linux ARM64** (aarch64-unknown-linux-gnu) e **FreeBSD** (x86_64-unknown-freebsd).
*   **Correção de Tipos Unix para Limites de Arquivos**: Correção de compatibilidade no ajuste do `rlimit` (para FreeBSD, onde `rlim_t` é um tipo sinalizado de 64 bits `i64`, em oposição ao tipo não sinalizado `u64` do Linux).
*   **Estrutura de Builds Resilientes no GitHub**: Migração da compilação de Linux ARM64 para compilação cruzada com a ferramenta `cross` (Docker) e OpenSSL estático/vendored, superando a escassez de runners nativos de contas de usuário.
*   **Correção de Compatibilidade de Shell**: Divisão de comandos de compilação em passos do GitHub Actions condicionados nativamente para evitar falhas de interpretação de scripts bash sob o interpretador PowerShell do Windows.

# Funcionalidades em Desenvolvimento

*   Não há novas funcionalidades em desenvolvimento ativo no momento.

# Pendências

*   Nenhuma pendência crítica ou urgente de bugs foi reportada nas implementações vigentes.

# Próximos Passos

*   Continuar com eventuais evoluções solicitadas pelo usuário sobre novos protocolos ou melhorias no banco de dados.

# Riscos e Dúvidas Abertas

*   Nenhum risco crítico ou dúvida em aberto no momento.

# Referências Técnicas

*   **Crate `ipnet`**: Usado para validação e representação de CIDR IP.
*   **Crate `printpdf`**: Responsável pelo posicionamento absoluto bidimensional de textos e formas geométricas no documento gerado.
*   **Crate `rusqlite`**: Compilado com dependências condicionais por plataforma: no Windows utiliza `bundled-sqlcipher-vendored-openssl` para compilação estática do OpenSSL; nas demais plataformas utiliza `bundled-sqlcipher`.
*   **Infraestrutura de CI/CD**: Utilização do GitHub Actions com dois workflows principales: `ci.yml` (validação através de cargo check/test em pushes e PRs) e `release.yml` (compilação e empacotamento automatizado multiplataforma Linux/Windows disparados por tags `v*`).

