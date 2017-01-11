# !/usr/bin/python3
# -*- coding: utf-8 -*-

import socket
import socketserver
import sys
import random
import json
from xml.sax import make_parser
from xml.sax.handler import ContentHandler
from time import time, gmtime, strftime
import hashlib
from uaserver import AddLog
import time
"""
PROXY REGISTRAR
"""


class SmallSMILHandler(ContentHandler):

    def __init__(self):

        self.lista = []
        self.dicc = {"server": ["name", "ip", "puerto"],
                    "database": ["path", "passwdpath"],
                    "log": ["path"]}

    def startElement(self, name, attrs):
        if name in self.dicc:
            empty = {}
            for atrib in self.dicc[name]:
                empty[atrib] = attrs.get(atrib, "")
            self.lista.append([name, empty])

    def get_tags(self):
        return self.lista

p_file = open('passwords', 'r')
p_data = p_file.read().split()
password1 = p_data[1]
password2 = p_data[3]


class EchoHandler(socketserver.DatagramRequestHandler):

    dicc = {}
    #  Almacenamos en un archivo los usuarios registrados

    def register2json(self):
        fichj = open('registered.json', 'w')
        json.dump(self.dicc, fichj)
        fichj.close()

    def json2registered(self):
        try:
            fich = open('registered.json', 'r')
            self.dicc = fich.load(fich)
            fich.close()
        except:
            self.dicc = {}

    def handle(self):
        ip = self.client_address[0]
        port = self.client_address[1]
        while 1:
            self.register2json()
            linea = self.rfile.read()
            if not linea:
                break
            print("El cliente nos manda: " + '\r\n' + linea.decode('utf-8'))
            client_m = linea.decode('utf-8')
            mensaje_c = client_m.split()
            method = mensaje_c[0]

            #  Log
            event = 'Send to ' + ip + ':' + str(port) + ':'
            event += client_m
            tiempo = time.time()
            AddLog(log['path'], tiempo, event)

            #  print("MENSAJE CLIENTE: ")
            sip_line = mensaje_c[1].split(':')
            #  print(" Linea sip: " , sip_line)
            user = sip_line[1]
            nonce = random.randint(0, 9999999999999999999)

            if method == 'REGISTER':

                if len(mensaje_c) == 8:

                    if mensaje_c[5].split(":")[0] == 'Authorization':

                        response = mensaje_c[7].split("'")[1]

                        if user == 'melvinakaBS@gtasa.com':
                            passw = password1
                            m = hashlib.sha1()
                            m.update(b'nonce' + b'passw')
                            exp_response = m.hexdigest()
                            if exp_response == response:
                                self.wfile.write(b"SIP/2.0 200 OK\r\n")
                        if user == 'seanakasweet@gtasa.com':
                            passw = password2
                            m = hashlib.sha1()
                            m.update(b'nonce' + b'passw')
                            exp_response = m.hexdigest()
                            if exp_response == response:
                                self.wfile.write(b"SIP/2.0 200 OK\r\n")

                        usser = sip_line[1]
                        port = sip_line[2]
                        expires = mensaje_c[4]

                        t_actual = int(time.time())
                        t_expiracion = int(expires) + t_actual

                        self.dicc[usser] = {'address': ('127.0.0.1'),
                                            'port': port,
                                            'expires': t_expiracion}

                        expired_list = []

                        try:
                            attr = self.dicc[usser]
                            if t_actual >= attr['expires']:
                                expired_list.append(usser)
                                del self.c_dicc[usser]
                        except:
                            pass

                elif len(mensaje_c) == 5:
                    sip_line = ("SIP/2.0 401 Unauthorized\r\n\r\n")
                    send_line = sip_line + "WWW Authenticate: Digest "
                    send_line += "nonce=" + "'" + str(nonce) + "'"
                    self.wfile.write(bytes(send_line, 'utf-8'))

                    #  Log
                    event = 'Send to ' + ip + ':' + str(port) + ':'
                    event += send_line
                    tiempo = time.time()
                    AddLog(log['path'], tiempo, event)

            elif method == 'INVITE':
                sip_line = mensaje_c[1].split(':')
                guest = sip_line[1]
                user_origen = mensaje_c[6].split('=')[1]

                #  Log
                event = 'Send to ' + ip + ':' + str(port) + ':'
                event += client_m
                tiempo = time.time()
                AddLog(log['path'], tiempo, event)

                print("Queremos invitar a: ", guest)

                with open('registered.json') as file:
                    jfich = json.load(file)
                    Encontrado = False
                    for user in jfich:
                        if user == guest:
                            Encontrado = True
                    if Encontrado:
                        ipjfich = jfich[guest]['address']
                        portjfich = jfich[guest]['port']
                        my_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                        my_socket.connect((ipjfich, int(portjfich)))
                        my_socket.send(bytes(client_m, 'utf-8') + b'\r\n')
                        received = my_socket.recv(1024)
                        print(received.decode('utf-8'))
                        linea_r = received.decode('utf-8').split()

                        if linea_r[2] == 'Trying' and linea_r[5] == 'Ring' and linea_r[8] == 'OK':
                            self.wfile.write(b"SIP/2.0 100 Trying\r\n\r\n")
                            self.wfile.write(b"SIP/2.0 180 Ring\r\n\r\n")
                            self.wfile.write(b"SIP/2.0 200 OK\r\n\r\n")
                    else:
                        self.wfile.write(b"SIP/2.0 404 User Not Found\r\n\r\n")

            elif method == 'ACK':
                sip_line = mensaje_c[1].split(':')
                user_sip = sip_line[1]
                guest = mensaje_c[1].split(':')[1]

                #  Log
                event = 'Send to ' + ip + ':' + str(port) + ':'
                event += client_m
                tiempo = time.time()
                AddLog(log['path'], tiempo, event)

                with open('registered.json') as file:
                    jfich = json.load(file)
                    for user in jfich:
                        if user == guest:
                            ip = jfich[guest]['address']
                            port = jfich[guest]['port']
                            my_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                            my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                            my_socket.connect((ip, int(port)))
                            my_socket.send(bytes(client_m, 'utf-8') + b'\r\n')
                            received = my_socket.recv(1024)
                            print(received.decode('utf-8'))

            elif method == 'BYE':
                sip_line = mensaje_c[1].split(':')
                user_sip = sip_line[1]
                guest = mensaje_c[1].split(':')[1]

                #  Log
                event = 'Send to ' + ip + ':' + str(port) + ':'
                event += client_m
                tiempo = time.time()
                AddLog(log['path'], tiempo, event)

                with open('registered.json') as file:
                    jfich = json.load(file)
                    for user in jfich:
                        if user == guest:
                            ip = jfich[guest]['address']
                            port = jfich[guest]['port']
                            my_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                            my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                            my_socket.connect((ip, int(port)))
                            my_socket.send(bytes(client_m, 'utf-8') + b'\r\n')
                            received = my_socket.recv(1024)
                            print(received.decode('utf-8'))
                            self.wfile.write(b"SIP/2.0 200 OK\r\n\r\n")

if __name__ == '__main__':

    try:
        CONFIG = sys.argv[1]
    except:
        sys.exit("Usage: python proxy_registrar.py config")

    parser = make_parser()
    cHandler = SmallSMILHandler()
    parser.setContentHandler(cHandler)
    parser.parse(open(CONFIG))
    data = cHandler.get_tags()
    #  print(data)

    #  Lista de diccionarios de nuestra lista--->"data"
    server = data[0][1]
    database = data[1][1]
    log = data[2][1]

    print('Server ' + server['name'] + ' listening at port ' + server['puerto'] + ' ...')

    proxy_serv = socketserver.UDPServer((server['ip'], int(server['puerto'])), EchoHandler)
    print("Listening...")
    try:
        proxy_serv.serve_forever()
    except KeyboardInterrupt:
        print("Servidor Finalizado")
