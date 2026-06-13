# AmpScan — Manual de Uso e Guia do Usuário

O **AmpScan** é uma ferramenta de linha de comando (CLI) escrita em Rust de alta performance projetada para auditar redes e identificar portas abertas e mal configuradas que possam ser exploradas em ataques de **amplificação DDoS** sobre protocolos IPv4 e IPv6.

---

## 🔒 Segurança em Primeiro Lugar

O AmpScan foi desenhado com segurança em repouso. O banco de dados SQLite local (`ampscan.db`) é **completamente criptografado usando SQLCipher (AES-256)**.

### Variáveis de Ambiente Cruciais

Antes de rodar qualquer subcomando, você deve definir as seguintes variáveis no seu ambiente:

*   `AMPSCAN_DB_KEY`: **[Obrigatória]** A chave secreta usada para criptografar/descriptografar o banco de dados (recomenda-se uma string longa com mais de 32 caracteres).
*   `AMPSCAN_DB_PATH`: *(Opcional)* Caminho personalizado para o banco de dados (padrão: `ampscan.db`).
*   `AMPSCAN_USER`: *(Opcional)* Define o usuário administrador para evitar que o terminal pergunte o username de forma interativa a cada comando.

Exemplo de preparação do ambiente:
```bash
export AMPSCAN_DB_KEY="uma_chave_secreta_muito_segura_e_longa_para_o_banco"
export AMPSCAN_USER="admin"
```

---

## 🛠️ Instalação e Compilação

Para compilar o projeto em sua máquina (requer o conjunto de ferramentas do Rust / Cargo instalado):

```bash
# Clone o repositório ou navegue até a pasta
cd amplification_port_testing

# Compile em modo Release para máxima performance de scanning
cargo build --release
```

O binário compilado estará localizado em `target/release/ampscan`.

---

## 🧭 Fluxo de Utilização Rápido (Quick Start)

### 1. Inicializar o Banco de Dados
Na primeira execução, inicialize o banco para criar o esquema criptografado, registrar as 20 portas padrão e configurar a senha do usuário administrador inicial:

```bash
./target/release/ampscan init
```
*Digite o nome de usuário desejado e defina uma senha forte quando solicitado interativamente.*

### 2. Cadastrar um Prefixo de Rede (CIDR)
Para que o escaneamento completo funcione, você precisa cadastrar quais prefixos de rede de sua propriedade/responsabilidade serão testados:

```bash
./target/release/ampscan prefix add --prefix "192.168.1.0/24" --description "Rede Corporativa Escritorio"
```

### 3. Listar Portas Cadastradas
Verifique as portas de amplificação registradas no sistema:

```bash
./target/release/ampscan port list
```

### 4. Executar o Scan Completo
Rode o escaneamento paralelo em todos os prefixos ativos e gere o relatório em PDF:

```bash
./target/release/ampscan scan run --concurrency 512 --output relatorio_seguranca.pdf
```

---

## 📖 Referência de Comandos da CLI

### `ampscan init`
Inicializa a estrutura do banco criptografado, popula com as 20 portas padrão de amplificação e cria o usuário master do sistema.

### Gerenciamento de Portas (`port`)
Permite gerenciar quais portas e payloads serão testados durante a varredura:

*   **Listar:**
    ```bash
    ./target/release/ampscan port list
    ```
*   **Adicionar porta customizada (UDP):**
    ```bash
    ./target/release/ampscan port add --port 12345 --proto udp --name "CUSTOM-UDP" --description "Serviço interno UDP" --probe-type udp_payload --payload-hex "FF00AA55"
    ```
*   **Desabilitar / Habilitar uma porta específica:**
    ```bash
    ./target/release/ampscan port disable <ID>
    ./target/release/ampscan port enable <ID>
    ```
*   **Remover porta:**
    ```bash
    ./target/release/ampscan port remove <ID>
    ```

### Gerenciamento de Prefixos (`prefix`)
Define os alvos dos escaneamentos em lote (aceita faixas IPv4 e IPv6):

*   **Listar:**
    ```bash
    ./target/release/ampscan prefix list
    ```
*   **Adicionar:**
    ```bash
    ./target/release/ampscan prefix add --prefix "2001:db8::/120" --description "Hosts IPv6 Homologação"
    ```
*   **Desabilitar / Habilitar:**
    ```bash
    ./target/release/ampscan prefix disable <ID>
    ./target/release/ampscan prefix enable <ID>
    ```

### Gerenciamento de Usuários (`user`)
*   **Adicionar novo administrador:**
    ```bash
    ./target/release/ampscan user add --username novo_admin
    ```
*   **Alterar senha:**
    ```bash
    ./target/release/ampscan user change-password --username admin
    ```

### Execução de Scans (`scan`)

O AmpScan possui dois modos de execução:

#### 1. Modo Scan Lote (`scan run`)
Busca todos os prefixos e portas marcados como ativos (`enabled`) no banco de dados e realiza testes de alcance paralelos.

**Parâmetros suportados:**
*   `--concurrency <N>`: Número de probes enviados simultaneamente (padrão: `256`).
*   `--timeout <S>`: Tempo limite de espera para resposta de cada probe em segundos (padrão: `3`).
*   `--output <PATH>`: Nome do arquivo PDF a ser gerado (padrão: `ampscan_report.pdf`).
*   `--no-icmp`: Desativa a validação prévia de ping (ICMP) por host. Útil caso você esteja executando sem privilégios de `root` ou permissão `CAP_NET_RAW` no Linux.
    *   *Nota:* Com `--no-icmp` ativo, fallbacks locais (TCP handshakes) são tentados para saber se o host está online, e o status "Inconclusivo" não será retornado.
*   `--prefix <CIDR>`: Prefixo de rede manual a ser varrido (ex: `192.168.1.0/24`). **Ignora os prefixos configurados no banco de dados e pula a geração do relatório PDF**.

Exemplo de execução robusta:
```bash
./target/release/ampscan scan run --concurrency 500 --timeout 2 --output scan_junho.pdf
```

Exemplo com prefixo manual:
```bash
./target/release/ampscan scan run --prefix "10.0.0.0/29" --no-icmp
```

#### 2. Modo Único IP (`scan single`)
Testa todas as portas ativas contra um único IP de destino, imprimindo as respostas e tempos em tempo real no console:

```bash
./target/release/ampscan scan single 1.1.1.1 --timeout 2 --no-icmp
```

---

## 📈 Entendendo os Resultados

Durante a varredura de cada porta, o status pode ser classificado como:

1.  🔴 **Aberta (Vulnerável):** O alvo respondeu ao probe enviado. Significa que a porta de amplificação está aberta e responde publicamente a requisições externas sem filtragem.
2.  🟢 **Fechada:** O host respondeu ao ping ICMP ou conexão TCP, mas o serviço de amplificação na porta indicada não deu resposta.
3.  🔵 **Inconclusiva:** O host testado não respondeu ao ping ICMP ou probe, o que sugere que o host pode estar offline ou bloqueando tráfego de diagnóstico inteiramente.
4.  🟡 **Erro:** Um erro interno de rede local ou timeout estrito ocorreu ao tentar a conexão.
