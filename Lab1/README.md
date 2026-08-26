# Lab1 - Servidor HTTP com sockets

Servidor HTTP didático implementado em Python usando diretamente sockets TCP. O objetivo é praticar a abertura de uma porta, o recebimento de requisições HTTP, o envio de cabeçalhos e conteúdo, e o atendimento concorrente de clientes.

## Escopo

O servidor disponibiliza arquivos estáticos armazenados em `files/`. A implementação cobre:

- socket TCP IPv4 (`AF_INET` e `SOCK_STREAM`);
- escuta em `0.0.0.0:6789`, aceitando conexões de qualquer interface local;
- fila de até 5 conexões pendentes;
- uma thread daemon por conexão aceita;
- suporte ao método HTTP `GET`;
- identificação do tipo MIME com `mimetypes`;
- cabeçalhos `Content-Length`, `Content-Type`, `Content-Disposition` e `Connection`;
- proteção contra tentativa de acessar caminhos fora de `files/`;
- encerramento controlado com `Ctrl+C`.

## Estrutura

```text
Lab1/
├── README.md
├── main.py
└── files/
    ├── error.html
    ├── index.html
    ├── pdf.pdf
    └── word.docx
```

`main.py` é o servidor. O diretório `files/` é a raiz dos arquivos publicados. O arquivo `index.html` é a página de teste, `pdf.pdf` é um documento PDF, `word.docx` é um documento do Word e `error.html` é usado nas respostas de erro.

## Requisitos

- Python 3.8 ou superior;
- porta `6789` disponível;
- navegador ou `curl` para realizar as requisições.

Não há dependências externas: o programa usa apenas a biblioteca padrão do Python.

## Acesso pela rede local

O servidor é associado a `0.0.0.0:6789`. Isso significa que ele aceita conexões em todas as interfaces de rede da máquina que o executa. Portanto, outras máquinas podem acessá-lo usando o endereço IP da máquina servidora e a porta `6789`, desde que estejam na mesma rede e que o firewall permita essa porta.

Para descobrir o IP da máquina servidora, use um dos comandos abaixo:

```bash
# Linux
hostname -I

# Windows
ipconfig
```

Em outra máquina da mesma rede, abra no navegador:

```text
http://IP_DA_MAQUINA_SERVIDORA:6789/index.html
```

Por exemplo:

```text
http://192.168.1.10:6789/index.html
```

`0.0.0.0` é usado apenas para indicar em quais interfaces o servidor deve escutar; ele não deve ser digitado no navegador. O endereço `localhost` ou `127.0.0.1` funciona somente na própria máquina servidora.

## Execução

No terminal, a partir da raiz do repositório:

```bash
cd Lab1
python3 main.py
```

Também é possível executar estando dentro do diretório `Lab1`:

```bash
python3 main.py
```

O código procura o diretório `files/` com base na localização do arquivo `main.py`, portanto ele pode ser iniciado a partir de qualquer diretório. Ao iniciar, o servidor exibirá:

```text
Ready to serve...
```

Mantenha esse terminal aberto e use outro terminal para os testes. Para parar o servidor, pressione `Ctrl+C`.

## Testes

### Navegador

Abra:

```text
http://localhost:6789/
```

Como o caminho `/` é convertido diretamente para o diretório `files`, a forma mais segura de testar o arquivo fornecido é:

```text
http://localhost:6789/index.html
```

### cURL

Requisição de um arquivo existente:

```bash
curl -i http://localhost:6789/index.html
```

Os arquivos `pdf.pdf` e `word.docx` são enviados como download pelo navegador:

```text
http://localhost:6789/pdf.pdf
http://localhost:6789/word.docx
```

Também é possível baixá-los com `curl`:

```bash
curl -OJ http://localhost:6789/pdf.pdf
curl -OJ http://localhost:6789/word.docx
```

Requisição de um arquivo inexistente:

```bash
curl -i http://localhost:6789/nao-existe.html
```

Teste de um método não permitido:

```bash
curl -i -X POST http://localhost:6789/index.html
```

O resultado esperado é, respectivamente, `200 OK`, `404 Not Found` e `405 Method Not Allowed`.

Também é possível testar a proteção de caminho:

```bash
curl -i http://localhost:6789/../main.py
```

O acesso deve ser recusado com `404 Not Found`. Dependendo do cliente, a sequência `..` pode ser normalizada antes de chegar ao servidor; nesse caso, use uma ferramenta que envie o caminho bruto ou observe o comportamento diretamente no código.

## Funcionamento

1. O socket é criado, configurado com `SO_REUSEADDR`, associado à porta `6789` e colocado em modo de escuta.
2. O laço principal aceita uma conexão TCP.
3. Uma thread chama `atender_requisicao` para ler até 1024 bytes e interpretar a primeira linha HTTP.
4. O caminho solicitado é resolvido dentro de `files/`.
5. `enviar_resposta` lê o arquivo em modo binário, monta os cabeçalhos e envia a resposta.
6. A conexão é fechada após o envio.

Arquivos `.pdf` e `.docx` são enviados com `Content-Disposition: attachment`; os demais são enviados como `inline`.

## Limitações conhecidas

Este é um servidor para fins didáticos, não um servidor HTTP para produção. Entre as limitações atuais estão:

- somente o método `GET` é processado;
- a requisição é limitada à leitura inicial de 1024 bytes;
- não há suporte a HTTPS;
- não há logging estruturado, autenticação, cache ou compressão;
- os arquivos são carregados integralmente na memória antes do envio;
- não há tratamento completo de todos os formatos e casos previstos pela especificação HTTP;
- o caminho de arquivos depende do diretório atual ao executar `main.py`.

## Conceitos praticados

- comunicação cliente-servidor;
- sockets TCP;
- ciclo de vida `bind`, `listen` e `accept`;
- estrutura básica de uma requisição e resposta HTTP;
- códigos de status HTTP;
- tipos MIME;
- concorrência com threads;
- validação de caminhos e prevenção de path traversal.
