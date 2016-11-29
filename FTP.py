import argparse
import os
import re
import socket
import sys

PORT_NUMBER = 25370
USE_PASSIVE = False
FILE_TRANSFER_START = '150'


def main():
    args = parse_args()
    if args.passive:
        global USE_PASSIVE
        USE_PASSIVE = True
    address = (args.address, args.port)
    print('Connecting to {}:{}'.format(address[0], address[1]))
    sock = socket.socket()
    data_sock = socket.socket()
    try:
        sock = connect(address)
        print(receive_full_reply(sock))
        data_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        data_sock.close()
        login(sock, None, None, None)
        run(sock, data_sock)
    except ConnectionError as error:
        print(error)
        sys.exit(1)
    except Exception as error:
        print(error)
        run(sock, data_sock)


def run(control_sock, data_sock):
    while True:
        message = input('>')
        query = message.split(' ')
        command = query[0].lower()
        argument = query[1] if len(query) > 1 else None
        option = query[2] if len(query) > 2 else None
        comm = FUNCTIONS.get(command, invalid)
        result = comm(control_sock, data_sock, argument, option)
        if result is not None:
            data_sock = result


def parse_args():
    parser = argparse.ArgumentParser(prog='ftp.py', description='Connects to ftp server')
    parser.add_argument('address', help='address to connect')
    parser.add_argument('port', help='port', type=int, default=21)
    parser.add_argument('--passive', help='use passive mode instead of active', action='store_true')
    return parser.parse_args()


def connect(host):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        address = socket.getaddrinfo(host[0], host[1])
        sock.connect(address[0][4])
    except socket.gaierror as error:
        raise ConnectionError('Address fetching failed: {}:{}'.format(host[0], host[1]))
    except Exception as error:
        raise ConnectionError('Connection error: ' + str(error))
    return sock


def pasv(control_sock, data_sock=None, argument=None, extra_arg=None):
    send(control_sock, 'PASV')
    reply = receive_full_reply(control_sock)
    print(reply)
    reg = r'(\d+),(\d+),(\d+),(\d+),(\d+),(\d+)'
    res = re.findall(reg, reply)[0]
    ip_address = '.'.join(res[:4])
    port = int(res[4]) * 256 + int(res[5])
    parameters = (ip_address, port)
    data = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    data.connect(parameters)
    return data


def port(control_sock, data_sock=None, argument=None, extra_argument=None):
    global PORT_NUMBER
    ip_address = control_sock.getsockname()[0]
    port_whole, port_factor = PORT_NUMBER // 256, PORT_NUMBER % 256
    sock = socket.socket()
    sock.bind(('', PORT_NUMBER))
    query = 'PORT {},{},{}'.format(ip_address.replace('.', ','), port_whole, port_factor)
    send(control_sock, query)
    reply = receive_full_reply(control_sock)
    print(reply)
    sock.listen()
    PORT_NUMBER += 1
    return sock


def login(control_sock, data_sock, name, extra_arg):
    if name is None:
        name = input('Username: ')
    send(control_sock, 'USER', name)
    reply = receive_full_reply(control_sock)
    print(reply)
    password(control_sock, None, None, None)


def password(control_sock, data_sock, passw, extra_arg):
    passw = input('Password: ')
    send(control_sock, 'PASS', passw)
    reply = receive_full_reply(control_sock)
    reg = re.compile(r'2\d\d')
    print(reply)
    if not re.match(reg, reply):
        raise ValueError('Login is incorrect. Sign in with \'user\' command')


def dir_list(control_sock, data_sock, argument, extra_arg):
    if not USE_PASSIVE:
        sock = port(control_sock)
    else:
        data_sock = pasv(control_sock)
    send(control_sock, 'LIST')
    reply = receive_full_reply(control_sock)
    print(reply)
    if not USE_PASSIVE:
        data_sock, address = sock.accept()
    if data_sock is None:
        raise ConnectionError('Data connection is required')
    data = data_sock.recv(65535).decode('UTF-8')
    print(data)
    data_sock.close()
    reply = receive_full_reply(control_sock)
    print(reply)


def quit(control_sock, data_sock, argument, extra_arg):
    send(control_sock, 'QUIT')
    reply = receive_full_reply(control_sock)
    print(reply)
    sys.exit(0)


def server_help(control_sock, data_sock, argument, extra_arg):
    send(control_sock, 'HELP')
    reply = receive_full_reply(control_sock)
    print(reply)


def transfer_type(control_sock, data_sock, name, extra_arg):
    send(control_sock, 'TYPE', name)
    reply = receive_full_reply(control_sock)
    print(reply)


def cwd(control_sock, data_sock, path, extra_arg):
    send(control_sock, 'CWD', path)
    reply = receive_full_reply(control_sock)
    print(reply)


def pwd(control_sock, data_sock, argument, extra_arg):
    send(control_sock, 'PWD')
    reply = receive_full_reply(control_sock)
    print(reply)


def syst(control_sock, data_sock, argument, extra_arg):
    send(control_sock, 'SYST')
    reply = receive_full_reply(control_sock)
    print(reply)


def stat(control_sock, data_sock, argument, extra_arg):
    send(control_sock, 'STAT')
    reply = receive_full_reply(control_sock)
    print(reply)


def size(control_sock, data_sock, filename, path_value):
    send(control_sock, 'SIZE', filename)
    reply = receive_full_reply(control_sock)
    reg = r' (\d+)'
    result = re.findall(reg, reply)
    return int(result[0])


def get(control_sock, data_sock, filename, path_value):
    if path_value is None:
        path_value = '{}\\{}'.format(os.getcwd(), filename.split('/')[-1])
    transfer_type(control_sock, None, 'I', None)
    file_size = size(control_sock, None, filename, None)
    if not USE_PASSIVE:
        sock = port(control_sock)
    else:
        data_sock = pasv(control_sock)
    send(control_sock, 'RETR', filename)
    reply = receive_full_reply(control_sock)
    print(reply)
    if not reply.startswith(FILE_TRANSFER_START):
        raise FileNotFoundError('Couldn\'t download file {}'.format(filename))
    if not USE_PASSIVE:
        data_sock, address = sock.accept()
    with open(path_value, 'wb') as result:
        received = 0
        while file_size > received:
            data = data_sock.recv(65535)
            if not data:
                break
            result.write(data)
            received += 65535
    data_sock.close()
    reply = receive_full_reply(control_sock)
    print(reply)


def put(control_sock, data_sock, local_file, remote_name):
    if remote_name is None:
        folder = get_current_remote_directory(control_sock)
        remote_name = folder + '/' + local_file.split('/')[-1]
    transfer_type(control_sock, None, 'I', None)
    if not USE_PASSIVE:
        sock = port(control_sock)
    else:
        data_sock = pasv(control_sock)
    send(control_sock, 'STOR', remote_name)
    reply = receive_full_reply(control_sock)
    print(reply)
    if not USE_PASSIVE:
        data_sock, address = sock.accept()
    with open(local_file, 'rb') as file:
        data_sock.sendfile(file)
    reply = receive_full_reply(control_sock)
    print(reply)


def get_current_remote_directory(control_sock):
    send(control_sock, 'PWD')
    reply = receive_full_reply(control_sock)
    reg = re.compile(r'"([0-9A-Za-z_]")')
    current = re.findall(reg, reply)
    return current


def receive_full_reply(sock):
    reply = ''
    tmp = sock.recv(65535).decode('ASCII')
    reply += tmp
    first_reply_reg = re.compile(r'^\d\d\d ', re.MULTILINE)
    while not re.findall(first_reply_reg, tmp):
        tmp = sock.recv(65535).decode('ASCII')
        reply += tmp
    return reply


def send(sock, command, argument=None):
    if argument is not None:
        query = '{} {}\r\n'.format(command, argument)
    else:
        query = '{}\r\n'.format(command)
    sock.sendall(bytes(query, 'ASCII'))


def int_help(arg1, arg2, arg3, arg4):
    print("""Supported commands:
    login\tpass\tpasv\tls
    dir\tquit\thelp\ttype
    cd\tpwd\tsyst\tstat
    size\tget\t?
    """)


def send_explicitly(sock, message):
    sock.sendall(bytes(message + '\r\n', 'ASCII'))
    reply = sock.recv(65535).decode('ASCII')
    print(reply)


def invalid(arg1, arg2, arg3, arg4):
    print('Invalid command\nUse "HELP" command or "/?" for internal help')


FUNCTIONS = {
    'user': login,
    'pass': password,
    'pasv': pasv,
    'ls': dir_list,
    'dir': dir_list,
    'quit': quit,
    'help': server_help,
    'type': transfer_type,
    'cd': cwd,
    'pwd': pwd,
    'syst': syst,
    'stat': stat,
    'size': size,
    'get': get,
    'port': port,
    'put': put,
    '?': int_help
}

if __name__ == '__main__':
    main()
