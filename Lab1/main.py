from socket import *
import sys
import mimetypes
import os
import threading

serverSocket = socket(AF_INET, SOCK_STREAM)

# 0.0.0.0 significa que o servidor aceitará conexões vindas de qualquer interface de rede da máquina.
HOST = '0.0.0.0'

# Porta em que o servidor ficará aguardando conexões.
PORT = 6789

# Define o diretório dos arquivos com base na localização deste script.
FILES_DIRECTORY = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'files')

serverSocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
serverSocket.bind((HOST, PORT))

# O número 5 representa o tamanho máximo da fila
serverSocket.listen(5)

def enviar_resposta(connection_socket, status, filepath):
    """
    Envia uma resposta HTTP contendo o arquivo solicitado.
    """

    with open(filepath, 'rb') as file:
        outputdata = file.read()

    content_type = mimetypes.guess_type(filepath)[0]

    # Define se o navegador deve abrir o arquivo diretamente ou fazer o download.
    disposition = (
        'attachment'
        if filepath.lower().endswith(('.pdf', '.docx'))
        else 'inline'
    )

    # Monta os cabeçalhos da resposta HTTP.
    headers = (
        f'HTTP/1.1 {status}\r\n'
        f'Content-Type: {content_type}\r\n'
        f'Content-Length: {len(outputdata)}\r\n'
        f'Content-Disposition: {disposition}; filename="{os.path.basename(filepath)}"\r\n'
        'Connection: close\r\n'
        '\r\n'
    ).encode()

    # Envia o conteúdo do arquivo e o header.
    connection_socket.sendall(headers)
    connection_socket.sendall(outputdata)

def atender_requisicao(connection_socket, addr):
    """
    Recebe uma requisição HTTP de um cliente,
    identifica o arquivo solicitado e envia a resposta.
    """

    try:
        # Recebe até 1024 bytes da requisição enviada pelo navegador.
        message = connection_socket.recv(1024).decode()

        # Divide a requisição em linhas e pega a primeira linha.
        request_line = message.splitlines()[0]
        method, requested_path, _ = request_line.split()
        if method != 'GET':
            enviar_resposta(connection_socket, '405 Method Not Allowed',
                os.path.join(FILES_DIRECTORY, 'error.html'))
            return

        # Remove a "/" inicial do caminho e depois junta o nome ao diretório "files".
        requested_file = os.path.abspath(
            os.path.join(FILES_DIRECTORY, requested_path.lstrip('/'))
        )

        if not requested_file.startswith(FILES_DIRECTORY + os.sep):
            raise FileNotFoundError

        # Se tudo estiver correto, envia o arquivo com o status HTTP 200 (OK).
        enviar_resposta(connection_socket, '200 OK', requested_file)

        # Mostra no terminal informações sobre a requisição.
        print(f'Requisicao de {addr} atendida pela ' +
                f'thread {threading.current_thread().name}')

    except (FileNotFoundError, IOError, IndexError, ValueError):
        # Envia uma mensagem de erro
        error_file = os.path.join(FILES_DIRECTORY, 'error.html')
        enviar_resposta(connection_socket, '404 Not Found', error_file)

    finally:
        connection_socket.close()

try:
    while True:
        print('Ready to serve...')

        # Aguarda um cliente se conectar.
        connectionSocket, addr = serverSocket.accept()

        # Cria uma nova thread para atender esse cliente.
        request_thread = threading.Thread(target=atender_requisicao,
            args=(connectionSocket, addr), daemon=True)
        request_thread.start()

#Encerra o servidor ao digitar ctrl + c
except KeyboardInterrupt:
    print('\nServidor encerrado.')

finally:
    serverSocket.close()
    sys.exit()