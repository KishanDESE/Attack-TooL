from netfilterqueue import NetfilterQueue
from scapy.all import sniff, Ether, IP, TCP
import threading

from mms_handler import handle_mms
from goose_handler import handle_goose
from sv_handler import handle_sv

MMS_PORT = 102

def nfqueue_handler(packet):

    pkt = IP(packet.get_payload())

    if pkt.haslayer(TCP):

        if pkt[TCP].sport == 102 or pkt[TCP].dport == 102:
            handle_mms(pkt)

    packet.accept()

def l2_handler(pkt):

    if pkt.haslayer(Ether):

        if pkt[Ether].type == 0x88B8:
            handle_goose(pkt)

        elif pkt[Ether].type == 0x88BA:
            handle_sv(pkt)    

def start_nfqueue():

    nfq = NetfilterQueue()
    nfq.bind(1, nfqueue_handler)
    nfq.run()


def start_l2_sniffer():

    sniff(
        iface="eth0",
        prn=l2_handler,
        store=False,
        filter="ether proto 0x88b8 or ether proto 0x88ba"
    )


if __name__ == "__main__":

    t1 = threading.Thread(target=start_nfqueue)
    t2 = threading.Thread(target=start_l2_sniffer)

    t1.start()
    t2.start()

