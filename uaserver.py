# !/usr/bin/python3
# -*- coding: utf-8 -*-

import socket
import os
import socketserver
import sys
from xml.sax import make_parser
from xml.sax.handler import ContentHandler
import time


"""
USER AGENT SERVER
"""


class SmallSMILHandler(ContentHandler):

    def __init__(self):

        self.lista = []
        self.dicc = {"account": ["username", "passwd"],
                    "uaserver": ["ip", "puerto"],
                    "rtpaudio": ["puerto"],
                    "regproxy": ["ip", "puerto"],
                    "log": ["path"],
                    "audio": ["path"]}

    def startElement(self, name, attrs):
        if name in self.dicc:
            empty = {}
            for atrib in self.dicc[name]:
                empty[atrib] = attrs.get(atrib, "")
            self.lista.append([name, empty])

    def get_tags(self):
        return self.lista


def AddLog(path, tiempo, event):

    fich = open(path, 'a')
    tiempo = time.gmtime(tiempo)
    fich.write(time.strftime('%Y%m%d%H%M%S', tiempo))
    fich.write(' ' + event + '\r\n')
    fich.close()


class EchoHandler(socketserver.DatagramRequestHandler):

    def handle(self):
        while 1:
            linea = self.rfile.read()
            if not linea:
                break
            mensaje_p = linea.decode('utf-8').split()
            method = mensaje_p[0]
            event = ' Received from ' + proxy['ip'] + ':' + proxy['puerto']
            event += ':' + linea.decode('utf-8')
            tiempo = time.time()
            AddLog(log['path'], tiempo, event)
            if method == 'INVITE':
                self.wfile.write(b"SIP/2.0 100 Trying\r\n" +
                                b"SIP/2.0 180 Ring\r\n" +
                                b"SIP/2.0 200 OK\r\n")
            elif method == 'ACK':
                aEjecutar = './mp32rtp -i 127.0.0.1 -p ' + rtpaudio['puerto'] + ' < ' + audio_file
                print("Vamos a ejecutar: " + aEjecutar)
                os.system(aEjecutar)
            elif method == 'BYE':
                self.wfile.write(b"SIP/2.0 200 OK\r\n")
            elif method not in ['ACK', 'INVITE', 'BYE']:
                print("Metodo erroneo: " + method)
                self.wfile.write(b"SIP/2.0 405 Method Not Allowed \r\n")
            else:
                print("Peticion mal formada")
                self.wfile.write(b"SIP/2.0 400 Bad Request \r\n")


if __name__ == "__main__":
    try:
        CONFIG = sys.argv[1]
    except:
        sys.exit("Usage: python uaserver.py config")

    parser = make_parser()
    cHandler = SmallSMILHandler()
    parser.setContentHandler(cHandler)
    parser.parse(open(CONFIG))
    data = cHandler.get_tags()

    proxy = data[3][1]
    log = data[4][1]
    audio = data[5][1]
    rtpaudio = data[2][1]
    audio_file = audio['path']
    uaserver = data[1][1]
    uas_port = uaserver['puerto']
    uas_ip = uaserver['ip']
    serv = socketserver.UDPServer((uas_ip, int(uas_port)), EchoHandler)

    print("Listening...")
    try:
        serv.serve_forever()
    except KeyboardInterrupt:
        print("Servidor Finalizado")
