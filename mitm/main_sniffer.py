import sys
import threading
import argparse
from netfilterqueue import NetfilterQueue
from scapy.all import sniff, Ether, IP, TCP, Dot1Q, PcapReader
from scapy.all import PcapWriter

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
    
    
def modify_packet(pkt, args):

    if pkt.haslayer(IP):

        if args.src_ip:
            pkt[IP].src = args.src_ip

        if args.dst_ip:
            pkt[IP].dst = args.dst_ip

        del pkt[IP].chksum

        if pkt.haslayer(TCP):
            del pkt[TCP].chksum


    if pkt.haslayer(Ether):

        if args.src_mac:
            pkt[Ether].src = args.src_mac

        if args.dst_mac:
            pkt[Ether].dst = args.dst_mac

    return pkt          
    
    
def run_pcap(file, args):

    writer = None
    
    if args.save:
        writer = PcapWriter(args.save, sync = True)
        

    with PcapReader(file) as pcap:

        packet_index = 0
        
        for pkt in pcap:
            
            packet_index += 1
            
            if args.packet and packet_index == args.packet
                pkt = modify_packet(pkt, args)
            
            # MMS detection
            if pkt.haslayer(TCP):
                if pkt[TCP].sport == MMS_PORT or pkt[TCP].dport == MMS_PORT:
                    handle_mms(pkt)

            # GOOSE / SV detection
            if pkt.haslayer(Ether):
                l2_handler(pkt)
            
            if writer:
                writer.write(pkt)
                
    if writer:
        writer.close()           
                      

if __name__ == "__main__":

     parser = argparse.ArgumentParser()

     parser.add_argument("pcap", nargs="?")
     parser.add_argument("--src-ip")
     parser.add_argument("--dst-ip")
     parser.add_argument("--src-mac")
     parser.add_argument("--dst-mac")
     parser.add_argument("--save")
     parser.add_argument("--pkt", type=int, help = "packet no to modify")

     args = parser.parse_args()

     if args.pcap:
        run_pcap(args.pcap, args)
     else:
        t1 = threading.Thread(target=start_nfqueue, daemon=True)
        t2 = threading.Thread(target=start_l2_sniffer, daemon=True)

        t1.start()
        t2.start()

        t1.join()
        t2.join()
