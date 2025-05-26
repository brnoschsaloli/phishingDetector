# Detector de URLs Suspeitas

Este é um projeto que verifica URLs em busca de características suspeitas de phishing. O sistema pode ser usado de duas formas: como uma extensão para navegador ou como uma aplicação web.

## Funcionalidades

### Extensão para Navegador
- Verificação em tempo real de URLs durante a navegação
- Detecção de padrões suspeitos:
  - Números no domínio
  - Subdomínios excessivos
  - Caracteres especiais
- Integração com Google Safe Browsing API
- Bloqueio automático de URLs suspeitas
- Notificações de segurança
- Configurações personalizáveis:
  - Níveis de sensibilidade
  - Lista de URLs permitidas
  - Notificações para URLs seguras

### Aplicação Web
- Verificação de URLs contra a base de dados do PhishTank
- Detecção de padrões suspeitos:
  - Números no domínio
  - Subdomínios excessivos
  - Caracteres especiais
- Interface web simples e intuitiva
- Indicadores visuais de segurança (verde/vermelho)

## Requisitos

- Python 3.7 ou superior
- pip (gerenciador de pacotes Python)

## Instalação e Uso

### Extensão para Navegador

1. Clone este repositório:
```bash
git clone [https://github.com/brnoschsaloli/phishingDetector.git]
cd phishingDetector
```

2. Abra o Firefox e acesse `about:debugging`
3. Clique em "This Firefox"
4. Clique em "Load Temporary Add-on"
5. Navegue até a pasta `plugin` do projeto e selecione o arquivo `manifest.json`

6. Configure a extensão:
   - Clique no ícone da extensão
   - Acesse as opções
   - Configure sua chave da API do Google Safe Browsing (opcional)
   - Ajuste a sensibilidade conforme necessário
   - Ative o bloqueio automático se desejar

### Aplicação Web

1. Clone este repositório:
```bash
git clone [https://github.com/brnoschsaloli/phishingDetector.git]
cd phishingDetector
```

2. Instale as dependências:
```bash
pip install -r requirements.txt
```

3. Inicie o servidor Flask:
```bash
python app.py
```

4. Abra seu navegador e acesse:
```
http://localhost:5000
```

## Como Usar

### Extensão para Navegador
- A extensão verifica automaticamente as URLs durante a navegação
- URLs suspeitas serão marcadas e, se configurado, bloqueadas
- Notificações aparecerão para URLs suspeitas e seguras (se ativado)
- Configure URLs permitidas na lista de whitelist

### Aplicação Web
1. Digite a URL que deseja verificar no campo de entrada
2. Clique em "Verificar" ou pressione Enter
3. Os resultados serão exibidos na tabela abaixo, com:
   - Status da URL (Seguro/Suspeito)
   - Detalhes sobre os padrões suspeitos encontrados

## Estrutura do Projeto

```
phishingDetector/
├── app.py              # Aplicação principal Flask
├── requirements.txt    # Dependências do projeto
├── plugin/            # Extensão para navegador
│   ├── manifest.json  # Configuração da extensão
│   ├── background.js  # Lógica principal da extensão
│   ├── content.js     # Script de conteúdo
│   ├── options.js     # Configurações da extensão
│   └── warning.html   # Página de aviso
├── static/
│   └── style.css      # Estilos CSS
└── templates/
    └── index.html     # Template HTML
```