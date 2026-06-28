# Decisões Arquiteturais

*   **Modularização por Probes Específicas**: Cada tipo de serviço de rede escaneado (DNS, NTP, etc.) tem sua sonda de bytes implementada em um arquivo centralizado (`src/scanner/probes.rs`). Isso mantém o scanner desacoplado da lógica de serialização de payloads individuais de protocolo.
*   **Criptografia Transparente do Banco**: Uso de banco de dados criptografado em repouso por meio da extensão SQLCipher integrada à biblioteca SQLite. Toda a lógica de leitura/escrita exige uma autenticação de usuário para descriptografar os dados em tempo de execução.
*   **Remoção do Liveness Check Pré-Varredura**: Decisão de eliminar completamente as verificações de liveness baseadas em ICMP (Ping) e conexões TCP de fallback. A atividade dos hosts agora é inferida de forma inteligente baseada em respostas de portas (se alguma porta responder como aberta, as demais portas sem resposta daquele IP são tratadas como fechadas; caso contrário, permanecem como inconclusivas). Isso remove falsos negativos em hosts puramente UDP, elimina a necessidade de permissão de root (`CAP_NET_RAW` / `sudo`) no escaneamento padrão e simplifica o fluxo.

# Decisões Técnicas

*   **Varredura IP Completa**: Para IPv4, optou-se por construir manualmente o iterador do range completo (`network` até `broadcast`) em vez de utilizar o método nativo `.hosts()` do crate `ipnet`. Isso garante que hosts em endereços `.0` e `.255` em subnets `/24` sejam escaneados (comportamento comum em PPPoE).
*   **Limites de Tamanho de Escaneamento**: 
    *   **IPv4**: Limitado a no máximo 65.536 endereços por prefixo (equivalente a uma sub-rede `/16`).
    *   **IPv6**: Limitado a sub-redes com tamanho de prefixo maior ou igual a `/112` (até 65.536 hosts).
    *   Esses limites evitam a exaustão de memória ram no armazenamento temporário de IPs coletados na execução.
*   **Cor amarela para Open/Protected**: Decisão de destacar IPs identificados com portas de amplificação sob o estado `Open/Protected` usando cor amarela brilhante (bold) no console de terminal em vez de verde, diferenciando IPs seguros de IPs abertos, porém protegidos por mitigação ou regras específicas.
*   **Abertura Segura de Banco de Dados**: Comandos CLI que não são de inicialização (`init`) verificam explicitamente se o arquivo `.db` existe em disco antes de tentar instanciar a conexão do SQLite. Isso previne que novas bases vazias sem tabelas estruturadas sejam geradas por engano ao rodar leituras.
*   **Barra de Progresso e Spinner Customizados**: Optou-se por implementar uma barra de progresso customizada com blocos Unicode (`█` e `░`) e spinners dinâmicos em vez de adicionar a biblioteca `indicatif`, mantendo a base de código enxuta.
*   **Animação e Rendição de Tarefas**: Implementação de animação de preparação (`Preparing probes...`) com rendição cooperativa de threads via `tokio::task::yield_now()` ao enfileirar tarefas. Isso mantém a interface responsiva durante o agendamento de centenas de milhares de tarefas no Tokio.
*   **Frequência da Barra de Progresso**: O progresso se atualiza no primeiro resultado e a cada 200 resultados (além do passo padrão de 1%), evitando que a tela fique estática por longos períodos durante o processamento de timeouts.
*   **Automação não interativa via `AMPSCAN_PASS`**: Criação da variável de ambiente `AMPSCAN_PASS` para contornar o prompt interativo de login e senha do administrador em ambientes de automação (ex: cron).
*   **Colorização Condicional de Latência**: Os tempos de resposta das portas na tabela do terminal são coloridos em verde (<50ms), amarelo (<150ms) ou vermelho (>=150ms) para permitir que o auditor identifique visualmente a rapidez das respostas dos servidores.
*   **Instruções de Teste no Relatório**: Inclusão automática de uma seção de "Procedimentos de Validação Manual" no final do PDF com comandos baseados em CLI (`dig`, `snmpget`, `nc`, etc.) contendo o placeholder `<IP>`, permitindo que o auditor revalide facilmente as vulnerabilidades encontradas.

# Decisões de Infraestrutura

*   **Versionamento do Repositório GitHub**: Gerenciamento de releases por meio de tags de versão semântica (`v1.2.x`) associadas diretamente à ramificação `main` remota.

# Decisões de Ferramentas

*   **Uso de `printpdf` para Relatórios**: Escolha por gerar relatórios PDF nativamente em Rust sem dependências externas de sistema (como bibliotecas gráficas pesadas ou compiladores wkhtmltopdf).
*   **Uso de `image` para Imagens**: Integração da crate `image` com as funcionalidades de imagem de `printpdf` para decodificar e redimensionar logotipos JPEG/PNG no cabeçalho do PDF.

# Decisões Rejeitadas

*   **Uso de `.hosts()` do `ipnet` para IPv4**: Rejeitado pois desconsiderava endereços importantes de borda (como o primeiro e o último IP da sub-rede) úteis em cenários reais de provedor de internet.
*   **Dependência `surge-ping` para ICMP**: Removida completamente da base de código após a decisão de retirar o teste de liveness prévio, visando eliminar dependência de privilégios de root e prevenir falsos negativos.

# Motivações

*   **Exatidão de Escaneamento**: Garantir que as auditorias corporativas e de provedores não deixem servidores expostos indetectados nas extremidades de blocos CIDR IP ou devido a firewalls bloqueando ICMP/TCP de liveness.
*   **UX Premium e Legibilidade**: As tabelas CLI e arquivos gerados em PDF precisam de designs visualmente bem divididos e cores adequadas que demonstrem claramente o nível de risco associado a cada descoberta (por exemplo: verde para protegido, amarelo para protegido/aberto e vermelho para aberto/vulnerável).
*   **Resiliência a Limites de Recursos**: Evitar que varreduras com alto nível de concorrência quebrem silenciosamente ou gerem falsos negativos devido a limites de descritores de arquivos (`ulimit`) impostos pelo sistema operacional.

# Trade-offs Considerados

*   **Iteração em Memória vs Eficiência**: A expansão de prefixos CIDR é feita inteiramente armazenando os IPs em um vetor dinâmico (`Vec<IpAddr>`). Embora isso introduza limites para sub-redes muito grandes (como `/16` em IPv4 e `/112` em IPv6), essa abordagem garante que o deduplicador e o ordenamento dinâmico funcionem sem vazamento de memória ou sobrecarga de concorrência massiva indesejada.
*   **Auto-Elevação Dinâmica de Limites (rlimit)**: Optou-se por utilizar o crate `libc` sob plataformas Unix para tentar elevar dinamicamente o soft limit para o hard limit. Embora introduza código inseguro (`unsafe`) e dependência de chamadas nativas do sistema operacional, essa automação remove do usuário a necessidade de ajustar o `ulimit` manualmente na maioria dos cenários reais.

# Novas Decisões (v1.2.1)

*   **Controle de Concorrência e Retries via CLI**: Adição das flags `--concurrency` e `--retries` para permitir que o auditor defina o ritmo de escaneamento ideal para a infraestrutura de rede testada.
*   **Aborto Seguro em Falhas de Sistema**: Interrupção total e limpa do escaneamento ao capturar exceções `EMFILE` (Too many open files) ou `ENFILE`. A abordagem de abortar em vez de continuar com erros garante a confiabilidade do relatório final (evitando falsos negativos causados por pacotes que não puderam ser enviados).

# Novas Decisões (v1.2.2)

*   **Validação Manual Baseada em Protocolo no Relatório**: Decisão de refatorar o agrupamento de portas abertas na geração de PDF para incluir a porta e o protocolo. Isso permite gerar instruções corretas de Netcat TCP ou UDP no relatório. Além disso, as portas de proxies e botnets MikroTik (`MT4145` e `MT5678`) passam a gerar explicitamente comandos baseados em `nmap` TCP para revalidação rápida, alinhado com as ferramentas mais usadas pelo auditor.

# Novas Decisões (v1.2.3)

*   **Migração Total de Testes Básicos de Conectividade para Nmap**: Decisão de padronizar todas as verificações de portas puras (que apenas testam porta aberta/fechada, sem payload especial no relatório, como CHARGEN, QOTD e fallbacks) utilizando a ferramenta `nmap` (`nmap -sT` para TCP, `nmap -sU` para UDP) nas instruções de validação manual.
*   **Simplificação de Protocolo**: Confirmação de que o scanner do `ampscan` continua operando o teste conforme cadastrado no banco (apenas UDP nas portas UDP, e apenas TCP nas portas do MikroTik), mantendo a simplicidade e a eficiência de recursos.

# Novas Decisões (v1.3.0)

*   **Padrão Acquire-Before-Spawn para Bounded Memory**: Decisão de adquirir o permit do semáforo *antes* de spawnar cada task (em vez de spawnar tudo e usar o semáforo apenas para controlar execução). Isso garante que no máximo `concurrency` tasks existam em memória simultaneamente, independentemente do tamanho total do scan. Trade-off: leve overhead de uma await por probe na fase de produção, desprezível frente ao ganho de memória (eliminação de pico de 300–500MB em scans /16).
*   **Arc\<Port\> em Vez de Clone por Probe**: Os structs `Port` agora são compartilhados via `Arc<Port>` entre as tasks de cada IP. Elimina a heap allocation de Strings (name, protocol, description, probe_type) por probe. Com 65536 IPs × 20 portas = 1.3M clones eliminados por scan de /16.
*   **Timeout Por Tentativa, Não Total**: Removida a divisão silenciosa por 2 do timeout por tentativa. `--timeout N` agora significa N segundos por tentativa de probe, alinhado com a descrição da flag no CLI. Usuários que precisarem de timeout total menor podem reduzir o valor ou usar `--retries 0`.
*   **Zeroize da Chave do Banco**: Após `open_database()` retornar, a String da chave é sobrescrita com zeros via crate `zeroize`. Isso limpa a heap da chave após o SQLCipher copiá-la para seu estado interno, reduzindo a janela de exposição em dumps de memória. Decidido usar `zeroize` em vez de `secrecy` para minimizar mudanças na API pública.
*   **Remoção de `AMPSCAN_DB_KEY` do Ambiente Pós-Leitura**: `get_db_key()` agora executa `std::env::remove_var("AMPSCAN_DB_KEY")` imediatamente após ler o valor. Isso não afeta `/proc/self/environ` (snapshot no início do processo), mas impede que processos filhos (ex: shells, ferramentas invocadas pelo relatório) herdem a chave.
*   **Busca Multi-path do `config.toml`**: Hierarquia de busca: (1) diretório do executável, (2) diretório de trabalho atual. A prioridade do diretório do executável reflete o modelo de instalação típico onde o binário e o config ficam na mesma pasta (ex: `/usr/local/bin/`).
*   **Migrations Versionadas com `schema_version`**: Adicionada tabela `schema_version` que registra a versão do schema aplicada. Bancos existentes (pré-v1.3.0) recebem a tabela automaticamente na primeira execução e são marcados como versão 1. Nenhum ALTER TABLE necessário para esta versão — o sistema está preparado para futuras evoluções do schema.
*   **Helper `lock_db()` para PoisonError**: Em vez de `.lock().unwrap()` (que propaga panic em cascata se qualquer thread panics enquanto segura o lock), foi criado `lock_db()` que converte o `PoisonError` em `anyhow::Error` recuperável. A política de não usar `unwrap()` em locks de Mutex é agora padrão em todo o módulo `db/`.
*   **Compilação Condicional para SQLCipher/OpenSSL no Windows**: Para suportar a compilação do SQLCipher com OpenSSL estático em ambiente Windows sem exigir configuração manual do usuário final, dividimos as dependências do `rusqlite` no `Cargo.toml`. O Windows usa a feature `bundled-sqlcipher-vendored-openssl` (que compila o OpenSSL das fontes C), enquanto outros SOs usam `bundled-sqlcipher`.
*   **Pipeline Automatizado de CD/CI (GitHub Actions)**: Adicionados fluxos de validação de código (`ci.yml` rodando cargo check e cargo test a cada push/PR) e publicação de releases automáticas (`release.yml` rodando em tag pushes `v*`). O build do Windows no CD é suportado por inicialização do ambiente MSVC Developer Command Prompt e Strawberry Perl. Os artefatos são nomeados uniformemente como `ampscan-v<versao>-<target>.<ext>` para compatibilidade de glob no upload.
*   **Exclusão Local Invisível de Configurações Privadas (`CLAUDE.md`)**: Decidiu-se retirar de toda a história do Git arquivos de convenção de desenvolvimento local (`CLAUDE.md`) para não poluírem o repositório público nem o histórico Git. A restrição local foi implementada via `.git/info/exclude` em vez do `.gitignore` público, garantindo que o arquivo não seja trackeado localmente sem expor a regra publicamente.

# Novas Decisões (v1.3.1)

*   **Documentação Centralizada de CI/CD**: Optou-se por documentar de forma detalhada o fluxo de integração contínua (CI) e entrega contínua (CD) diretamente no arquivo principal `README.md`. Isso facilita o onboarding de novos desenvolvedores que queiram testar ou compilar o executável estaticamente para Windows/Linux sem precisar inspecionar os arquivos YAML de workflows.

# Novas Decisões (v1.3.2)

*   **Expansão de Plataformas no CI/CD**: Decisão de suportar builds automatizados de release para macOS ARM64 (`aarch64-apple-darwin`), macOS Intel (`x86_64-apple-darwin`), Linux ARM64 (`aarch64-unknown-linux-gnu`) e FreeBSD (`x86_64-unknown-freebsd`). A validação do CI agora também roda no `macos-latest` além do `ubuntu-latest`.
*   **Compilação Cruzada com `cross` para Linux ARM64**: Adotado o uso da ferramenta `cross` (que encapsula o build em um container Docker pré-configurado) para gerar o binário de Linux ARM64 a partir do runner de host `ubuntu-latest`. Isso contorna a restrição e fila de espera dos runners nativos ARM64 (`ubuntu-24.04-arm64`) para contas de usuário comuns no GitHub.
*   **OpenSSL Vendored para Linux ARM64**: Configuração condicional no `Cargo.toml` específica para o target Linux ARM64 (`cfg(all(target_os = "linux", target_arch = "aarch64"))`) para usar a feature `bundled-sqlcipher-vendored-openssl`. Isso faz a ferramenta compilar o OpenSSL estaticamente a partir dos fontes, resolvendo erros de falta de headers de desenvolvimento do OpenSSL para ARM64 no ambiente de compilação cruzada.
*   **Casting Seguro de `rlimit` para FreeBSD**: Correção em `src/sys_limits.rs` para fazer o cast dos campos de limite do descritor de arquivo (`rlim_cur` e `rlim_max`) para `u64` durante comparações matemáticas, antes de convertê-los de volta para `rlim_t` via `as _`. Isso resolve erros de tipos no FreeBSD, onde `rlim_t` é um tipo assinado de 64 bits (`i64`), diferente do tipo não-sinalizado (`u64`) padrão do Linux/macOS.
*   **Separação Nativa de Comandos no GitHub Actions**: Divisão da etapa de compilação em passos do Actions mutuamente exclusivos via `if:` condicional do YAML (um passo rodando cargo nativo e outro rodando `cross`). Isso resolve erros de sintaxe e parser causados por comandos bash de tomada de decisão (`if/else`) rodados no interpretador PowerShell padrão de máquinas Windows do Actions.
*   **Compilação de FreeBSD via VM no CI/CD**: Uso do `vmactions/freebsd-vm@v1` para criar uma VM de FreeBSD 14.x no ar e rodar a compilação de forma nativa e segura, exportando os diretórios de include e lib do OpenSSL (`/usr/local`) via variáveis de ambiente (`CFLAGS`, `LDFLAGS`, `OPENSSL_DIR`) para a correta compilação do SQLCipher.

# Assuntos Ainda Não Decididos

*   **Rate limiting por IP de destino**: Sem limite por IP, um scanner com muitas portas TCP habilitadas pode gerar rajadas que triggeram IDS do cliente. Necessita discussão sobre semântica desejada antes de implementar.
*   **Pool de sockets UDP**: Criar e destruir um socket por probe UDP (1M+ bind/drop em /16) tem custo de syscall mensurável. Pool de sockets reutilizáveis reduziria esse overhead, mas requer mudança na arquitetura das probes. Pós-v1.3.0.


