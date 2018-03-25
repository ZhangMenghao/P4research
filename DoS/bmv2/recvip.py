from scapy.all import *

def handle_pkt(pkt):
    pkt = str(pkt)
    if len(pkt)<12: return
    print pkt


def main():
    dkpt =  sniff(iface = "veth6",
                  prn = lambda x: x.show())
    wrpcap("demo.pacp",dkpt)

if __name__ == '__main__':
    main()
