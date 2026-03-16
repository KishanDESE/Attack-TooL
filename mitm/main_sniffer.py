import sys
import threading
import argparse
from netfilterqueue import NetfilterQueue
from scapy.all import sniff, Ether, IP, TCP, Dot1Q, PcapReader, Raw
from scapy.all import PcapWriter

from mitm.mms_handler import handle_mms, extract_mms_pdu
from mitm.goose_handler import handle_goose, extract_goose_pdu
from mitm.sv_handler import handle_sv, extract_sv_pdu
from src.parser.tlv_parser import parse_all, encode_tlv, modify_tlv_value

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
    
def find_tlv_by_tag_number(tlv, tag_number):

    results = []

    if isinstance(tlv, list):
        for node in tlv:
            results.extend(find_tlv_by_tag_number(node, tag_number))
        return results

    if tlv["tag_number"] == tag_number:
        results.append(tlv)

    if tlv["constructed"]:
        for child in tlv["value"]:
            results.extend(find_tlv_by_tag_number(child, tag_number))

    return results
    
        
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
            
            
    # PDU VALUE CHANGE
    if args.t and args.v is not None and pkt.haslayer(Raw):

        payload = pkt[Raw].load
        pdu = None

	# MMS
        if pkt.haslayer(TCP) and (pkt[TCP].sport == MMS_PORT or pkt[TCP].dport == MMS_PORT):
            pdu = extract_mms_pdu(payload)

	# GOOSE
        elif pkt.haslayer(Ether) and pkt[Ether].type == 0x88B8:
            start = payload.find(b'\x61')
            if start != -1:
                pdu = payload[start:]

	# SV
        elif pkt.haslayer(Ether) and pkt[Ether].type == 0x88BA:
            start = payload.find(b'\x60')
            if start != -1:
                pdu = payload[start:]

        if pdu:

            tlvs = parse_all(pdu)
            nodes = find_tlv_by_tag_number(tlvs, args.t)

            for node in nodes:
                modify_tlv_value(node, args.v)

            encoded = b''
            for tlv in tlvs:
                encoded += encode_tlv(tlv)

            start = payload.find(pdu)

            pkt[Raw].load = payload[:start] + encoded
            
    print("Packet fields changed.....")		
    return pkt          
    
    
def run_pcap(file, args):

    writer = None
    
    if args.s:
        writer = PcapWriter(args.s, sync = True)
        print("Packet file saved!!")
        

    with PcapReader(file) as pcap:

        packet_index = 0
        
        for pkt in pcap:
            
            packet_index += 1
            modified = False
            
            if args.pkt and packet_index in args.pkt:
                pkt = modify_packet(pkt, args)
                modified = True
            
            if args.prt:
                # MMS detection
                if pkt.haslayer(TCP):
                    if pkt[TCP].sport == MMS_PORT or pkt[TCP].dport == MMS_PORT:
                        handle_mms(pkt)

                # GOOSE / SV detection
                if pkt.haslayer(Ether):
                    l2_handler(pkt)
            
            if writer:
                if args.mod:
                    if modified:
                        writer.write(pkt)
                else:
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
     parser.add_argument("--s")
     parser.add_argument("--pkt", type=int, help = "packet no to modify", nargs="+")
     parser.add_argument("--mod", action="store_true")
     parser.add_argument("--t", type=lambda x: int(x,16), help="BER tag to modify")
     parser.add_argument("--v", type=int, help="new value for the tag")
     parser.add_argument("--prt", action ="store_true", help="Print parsed pkt info")

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
