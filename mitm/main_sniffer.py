from netfilterqueue import NetfilterQueue
from scapy.all import sniff, Ether, IP, TCP, Dot1Q
import threading

from mitm.mms_handler import handle_mms
from mitm.goose_handler import handle_goose
from mitm.sv_handler import handle_sv

MMS_PORT = 102


def nfqueue_handler(packet):

    pkt = IP(packet.get_payload())

    if pkt.haslayer(TCP):

        if pkt[TCP].sport == MMS_PORT or pkt[TCP].dport == MMS_PORT:
            handle_mms(packet)
            return

    packet.accept()


def l2_handler(pkt):

    if not pkt.haslayer(Ether):
        return

    eth = pkt[Ether]

    # NORMAL GOOSE
    if eth.type == 0x88B8:
        handle_goose(pkt)
        return

    # VLAN GOOSE
    if pkt.haslayer(Dot1Q):

        vlan = pkt[Dot1Q]

        if vlan.type == 0x88B8:
            handle_goose(pkt)
            return

        if vlan.type == 0x88BA:
            handle_sv(pkt)
            return

    # NORMAL SV
    if eth.type == 0x88BA:
        handle_sv(pkt)

def start_nfqueue():

    nfq = NetfilterQueue()
    nfq.bind(1, nfqueue_handler)
    nfq.run()


def start_l2_sniffer():

    sniff(
        iface="eth1",
        prn=l2_handler,
        store=False,
    )


if __name__ == "__main__":

    t1 = threading.Thread(target=start_nfqueue, daemon=True)
    t2 = threading.Thread(target=start_l2_sniffer, daemon=True)

    t1.start()
    t2.start()

    t1.join()
    t2.join()
