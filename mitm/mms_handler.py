#!/usr/bin/env python3

from scapy.all import IP, TCP, Raw, send
from src.parser.tlv_parser import parse_all, pretty_print, encode_tlv

# CONFIG
MMS_PORT = 102
QUEUE_NUM = 1

flows = {}


# HELPERS
def flow_key(pkt):
    return (pkt[IP].src, pkt[TCP].sport,
            pkt[IP].dst, pkt[TCP].dport)

def reverse_flow_key(pkt):
    return (pkt[IP].dst, pkt[TCP].dport,
            pkt[IP].src, pkt[TCP].sport)

def is_tpkt(payload):
    return len(payload) >= 4 and payload[0] == 0x03 and payload[1] == 0x00

def adjust_seq_ack(pkt, direction):
    tcp = pkt[TCP]

    if direction == "forward":
        key = flow_key(pkt)
        if key in flows:
            tcp.seq += flows[key]["delta"]
    else:
        key = reverse_flow_key(pkt)
        if key in flows:
            tcp.ack -= flows[key]["delta"]


def extract_ber_after_cotp(payload):

    # ---- TPKT ----
    
    if len(payload) < 4 or payload[0] != 0x03:
        return None

    tpkt_len = int.from_bytes(payload[2:4], "big")
    tpkt_body = payload[4:tpkt_len]

    # ---- COTP ----
    if len(tpkt_body) < 1:
        return None

    cotp_len = tpkt_body[0]
    after_cotp = tpkt_body[cotp_len:]

    return after_cotp

def extract_mms_pdu(full_payload):

    ber_data = extract_ber_after_cotp(full_payload)
    if ber_data is None:
        return None
    tlvs = parse_all(ber_data)

    mms_tlv = find_mms_tlv(tlvs)

    if not mms_tlv:
        return None

    start = mms_tlv["start"]
    end = mms_tlv["end"]

    return ber_data[start:end]

def find_mms_tlv(tlv):

    if isinstance(tlv, list):
        for node in tlv:
            result = find_mms_tlv(node)
            if result:
                return result
        return None

    if tlv["tag_class"] == 2 and tlv["constructed"]:
        return tlv

    if tlv["constructed"]:
        for child in tlv["value"]:
            result = find_mms_tlv(child)
            if result:
                return result

    return None  

# =========================
# PACKET HANDLER
# =========================
def handle_mms(packet):
    if hasattr(packet, "get_payload"):
        pkt = IP(packet.get_payload())
    else:
        pkt = packet
        
    if not pkt.haslayer(TCP):
        packet.accept()
        return

    tcp = pkt[TCP]
    direction = "forward" if tcp.dport == MMS_PORT else "reverse"
    key = flow_key(pkt) if direction == "forward" else reverse_flow_key(pkt)

    if key not in flows:
        flows[key] = {
            "tpkt_count": 0,
            "initiate_payload": None,
            "delta": 0,
            "injected": False
        }

    state = flows[key]

    # 🔧 Adjust TCP numbers first
    adjust_seq_ack(pkt, direction)

    # CLIENT → SERVER
    if direction == "forward" and pkt.haslayer(Raw):
        payload = pkt[Raw].load

        if is_tpkt(payload):
            
            #Parse live-MMS 
            try:
                mms_bytes = extract_mms_pdu(payload)
                
                if not mms_bytes:
                   print("MMS PDU not found")
                   return
                print(f"\nMMS Packet: {pkt[IP].src}  →  {pkt[IP].dst}")
                print("\n===== MMS PDU HEX =====")
                print(mms_bytes.hex())
                
                tlvs = parse_all(mms_bytes)
                pretty_print(tlvs)

            except Exception as e:
                print("Parser error:", e)


    # FIX CHECKSUMS
    if pkt.haslayer(Raw):
        del pkt[IP].len
        del pkt[IP].chksum
        del pkt[TCP].chksum
        if hasattr(packet, "set_payload"):
            packet.set_payload(bytes(pkt))
    
    if hasattr(packet, "accept"):
        packet.accept()
