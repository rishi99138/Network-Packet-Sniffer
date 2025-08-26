from scapy.all import sniff

def show(pkt):
    try:
        print(pkt.summary())
    except Exception as e:
        print(f"error: {e}")

sniff(count=10, prn=show, store=False)
