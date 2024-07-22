# Traffic Analyzer (Case Mercado Livre)

## Objetivo do Projeto
Este projeto captura pacotes de rede e exibe estatísticas básicas sobre o tráfego. Utiliza a biblioteca Scapy para captura de pacotes e análise de protocolos, e armazena os dados em um banco de dados SQLite.

## Tecnologias Utilizadas
- Python 3
- Scapy
- SQLite
- WSL (Windows Subsystem for Linux)
- Docker

## Instruções de Instalação e Utilização

### 1. Configurar WSL no Windows

1. **Abrir o PowerShell como Administrador**:
   - Pressione `Win + X` e selecione `Windows PowerShell (Admin)`.

2. **Habilitar o WSL**:
   - Execute o seguinte comando:
     ```powershell
     wsl --install
     ```

3. **Reiniciar o Computador** (se necessário).

4. **Configurar o Ubuntu**:
   - Abra o Ubuntu através do menu Iniciar e siga as instruções na tela para configurar (definir nome de usuário e senha).

### 2. Instalar Dependências no WSL (Ubuntu)

1. **Atualizar os Pacotes**:
   ```bash
   sudo apt-get update
   sudo apt-get upgrade -y

2. **Instalar Python e Pip**:
   'sudo apt-get install python3 python3-pip -y'

3. **Instalar Scapy**:
   pip3 install scapy

4. **Instalar sqlite3**:
   sudo apt-get install sqlite3 -y

### 3. Instalar Docker

1. **Instalar Docker**:
   sudo apt-get install docker.io -y

2. **Iniciar o Serviço Docker**:
   sudo service docker start

3. **Adicionar o Usuário Atual ao Grupo Docker**:
   sudo usermod -aG docker $USER
   
4. **Criar arquivo Dockerfile**:
   nano dockerfile
    
5. **Reiniciar o WSL para aplicar as mudanças de grupo.**:

### 4. Executar o Script

1. **Acessar o local do Script**
   Exemplo: cd /seulocal/traffic_analyzer
   
3. **Executar o Script**:
   sudo python3 traffic_analyzer.py

4. **Interromper o Script**:
   Pressione Ctrl+C para interromper a execução do script e gerar o relatório.

### 5. Visualizar o banco de dados

1. **Abrir o Cliente SQLite**:
   sqlite3 traffic_analyzer.db

2. **Listar Tabelas**:
   .tables

3. **Visualizar Dados na Tabela packets**:
   SELECT * FROM packets;

4. **Sair do Client SQLite**:
   .exit


## Exemplos de Uso
Gerar Tráfego: Navegue em websites, transfira arquivos ou use ping para gerar tráfego.
Interromper Captura: Pressione Ctrl+C para parar a captura e exibir o relatório.

## Notas Adicionais
Certifique-se de que a interface de rede especificada está correta. Use ifconfig ou ip a para identificá-la.
O código foi testado no WSL (Ubuntu) com Python 3 e Scapy.
