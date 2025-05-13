# Detector de URLs Suspeitas

Este é um projeto que verifica URLs em busca de características suspeitas de phishing. O sistema analisa URLs usando a API do PhishTank e verifica padrões suspeitos como números no domínio, subdomínios excessivos e caracteres especiais.

## Funcionalidades

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

## Instalação

1. Clone este repositório:
```bash
git clone [URL_DO_REPOSITÓRIO]
cd phishingDetector
```

2. Instale as dependências:
```bash
pip install -r requirements.txt
```

## Executando o Projeto

1. Inicie o servidor Flask:
```bash
python app.py
```

2. Abra seu navegador e acesse:
```
http://localhost:5000
```

## Como Usar

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
├── static/
│   └── style.css      # Estilos CSS
└── templates/
    └── index.html     # Template HTML
```