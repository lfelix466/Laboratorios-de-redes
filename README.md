# Laboratórios de Redes

Repositório das atividades práticas da disciplina de Redes de Computadores. Cada laboratório fica em seu próprio diretório e deve conter seu código, arquivos auxiliares e a documentação específica da atividade.

## Estrutura atual

```text
.
├── README.md
└── Lab1/
    ├── README.md
    ├── main.py
    └── files/
        ├── error.html
        └── index.html
```

## Laboratórios disponíveis

### Lab1 - Servidor HTTP com sockets

Implementação de um servidor HTTP básico em Python utilizando sockets TCP, sem framework web. O servidor:

- escuta na porta `6789`;
- aceita conexões em todas as interfaces de rede (`0.0.0.0`);
- atende cada cliente em uma thread independente;
- disponibiliza arquivos estáticos do diretório `Lab1/files`;
- identifica o tipo MIME dos arquivos;
- retorna `200 OK` para arquivos encontrados;
- retorna `404 Not Found` para arquivos inexistentes;
- retorna `405 Method Not Allowed` para métodos diferentes de `GET`;
- bloqueia caminhos que tentem sair do diretório de arquivos.

Consulte o [README do Lab1](Lab1/README.md) para os requisitos, comandos de execução, testes e limitações.

## Requisitos gerais

- Python 3.8 ou superior;
- sistema operacional com suporte a sockets TCP;
- terminal para executar os laboratórios;
- navegador ou `curl` para testar o servidor quando aplicável.

O Lab1 utiliza somente módulos da biblioteca padrão do Python, portanto não exige instalação de dependências externas.

## Como executar um laboratório

Entre no diretório do laboratório e siga as instruções do README correspondente. Para executar o laboratório atual:

```bash
cd Lab1
python3 main.py
```

O terminal deve exibir `Ready to serve...`. Em seguida, acesse `http://localhost:6789/` em um navegador.

Para encerrar um servidor em execução, pressione `Ctrl+C`.

## Escopo do repositório

Este repositório é destinado a implementações e experimentos didáticos de redes. Os laboratórios podem evoluir independentemente, com seus próprios comandos e requisitos. No estado atual, somente o Lab1 está disponível.
