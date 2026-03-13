from scapy.all import Ether


def handle_goose(pkt):

    eth = pkt[Ether]

    print("\n===== GOOSE FRAME =====")

    print("SRC MAC:", eth.src)
    print("DST MAC:", eth.dst)

    payload = bytes(pkt.payload)

    print("GOOSE HEX:")
    print(payload.hex())