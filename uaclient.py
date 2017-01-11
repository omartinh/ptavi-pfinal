#!/usr/bin/python3
#-*- coding: utf-8 -*-

import socket
import sys
import time
from xml.sax import make_parser
from xml.sax.handler import ContentHandler
from uaserver import AddLog
import hashlib
from uaserver import AddLog


"""
USER AGENT CLIENT
"""


class SmallSMILHandler(ContentHandler):

    def __init__(self):


        self.lista = []
        self.dicc = {"account" : ["username","passwd"],
                    "uaserver" : ["ip","puerto"],
                    "rtpaudio" : ["puerto"],
                    "regproxy" : ["ip","puerto"],
                    "log" : ["path"],
                    "audio" : ["path"]}


    def startElement(self, name, attrs):
        if name in self.dicc:
            empty={}
            for atrib in self.dicc[name]:
                empty[atrib] = attrs.get(atrib,"")
            self.lista.append([name,empty])


    def get_tags(self):
        return self.lista



try:
    CONFIG = sys.argv[1]
    METHOD = sys.argv[2]
    OPTION = sys.argv[3]
except:
    sys.exit("Usage: python uaclient.py config method option")



parser = make_parser()
cHandler = SmallSMILHandler()
parser.setContentHandler(cHandler)
parser.parse(open(CONFIG))
data=cHandler.get_tags()
#print(data)


#  Lista de diccionarios de nuestra lista--->"data"
account = data[0][1]
passw = account['passwd']
uaserver = data[1][1]
rtpaudio = data[2][1]
regproxy = data[3][1]
log = data[4][1]
audio = data[5][1]

#  SOCKET

my_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
my_socket.connect((regproxy['ip'],int(regproxy['puerto'])))

#  Log
event = 'Starting...'
tiempo = time.time()
AddLog(log['path'], tiempo, event)

#  METODOS

if METHOD == 'REGISTER':
    Expires = OPTION
    sip_info = account['username'] + ':' + uaserver['puerto']
    linea1 = " sip:" + sip_info + " SIP/2.0" + "\r\n"
    linea2 = "Expires: " + Expires + "\r\n"
    cabecera_r = "REGISTER" + linea1 + linea2
    #  print("Enviando: " + "\r\n" + cabecera_r)
    my_socket.send(bytes(cabecera_r, 'utf-8') + b'\r\n')
    data = my_socket.recv(1024)
    print(data.decode('utf-8'))
    

    #  Log
    event = 'Send to ' + regproxy['ip'] + ':' + regproxy['puerto'] + ':'
    event += cabecera_r
    tiempo = time.time()
    AddLog(log['path'], tiempo, event)


    data_list = data.decode('utf-8').split()
    #  print(data_list)
    if data_list[1] == "401":
        nonce = data_list[6].split("'")[1]
        m = hashlib.sha1()
        m.update(b'nonce' + b'passw')
        m.hexdigest()
        response = m.hexdigest()
        line_authent = "Authorization: Digest response=" + "'"
        line_authent += response + "'" + "\r\n"
        linea = "REGISTER " + linea1 + linea2 + line_authent
        my_socket.send(bytes(linea, 'utf-8') + b'\r\n')
        data = my_socket.recv(1024)
        print(data.decode('utf-8'))

        #  Log
        event = 'Send to ' + regproxy['ip'] + ':' + regproxy['puerto'] + ':'
        event += linea
        tiempo = time.time()
        AddLog(log['path'], tiempo, event)
        

elif METHOD == 'INVITE':
    User = OPTION
    linea1 = " sip:" + User + " SIP/2.0\r\n"
    linea2 = "Content-Type: application/sdp" + "\r\n"
    v = "v=0" + "\r\n"
    o = "o=" + account['username'] + " " + uaserver['ip'] + "\r\n"
    s = "s=SesionGrove" + "\r\n" 
    t = "t=0" + "\r\n"
    m = "m=audio" + rtpaudio['puerto'] + " RTP" + "\r\n"
    linea_sdp = v + o + s + t+ m
    cabecera_i = "INVITE" + linea1 + linea2 + linea_sdp

    my_socket.send(bytes(cabecera_i, 'utf-8') + b'\r\n')
    data = my_socket.recv(1024)
    print(data.decode('utf-8'))
    linea_r = data.decode('utf-8').split()

    #  Log
    event = 'Send to ' + regproxy['ip'] + ':' + regproxy['puerto'] + ':'
    event += cabecera_i
    tiempo = time.time()
    AddLog(log['path'], tiempo, event)



    if linea_r[2] == 'Trying' and linea_r[5] == 'Ring' and linea_r[8] == 'OK' :
        User = OPTION
        linea = "ACK" + " sip:" + User + " SIP/2.0\r\n"
        my_socket.send(bytes(linea, 'utf-8') + b'\r\n')
        data = my_socket.recv(1024)
        print(data.decode('utf-8'))
        print("Enviando audio...")

        #  Log
        event = 'Send to ' + regproxy['ip'] + ':' + regproxy['puerto'] + ':'
        event += linea
        tiempo = time.time()
        AddLog(log['path'], tiempo, event)


elif METHOD == 'BYE':
    User = OPTION
    linea1 = " sip:" + User + " SIP/2.0" + "\r\n"
    cabecera_b = "BYE" + linea1

    my_socket.send(bytes(cabecera_b, 'utf-8') + b'\r\n')
    data = my_socket.recv(1024)
    print(data.decode('utf-8'))

    #  Log
    event = 'Send to ' + regproxy['ip'] + ':' + regproxy['puerto'] + ':'
    event += cabecera_b
    tiempo = time.time()
    AddLog(log['path'], tiempo, event)

    
my_socket.close()
