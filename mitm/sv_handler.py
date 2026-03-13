from scapy.all import Ether


def handle_sv(pkt):

    eth = pkt[Ether]

    print("\n===== SAMPLE VALUES =====")

    print("SRC MAC:", eth.src)
    print("DST MAC:", eth.dst)

    payload = bytes(pkt.payload)

    print("SV HEX:")
    print(payload.hex())