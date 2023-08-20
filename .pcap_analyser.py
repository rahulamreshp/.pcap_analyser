from scapy.all import rdpcap


def pcap(p_filename):
    packets = rdpcap(p_filename)

    print("Packet Details:")

    for packet in packets:
        protocol = None
        info = None

        if packet.haslayer("IP"):
            ip = packet["IP"]
            protocol = "IP"
            info = f"Source IP: {ip.src}, Destination IP: {ip.dst}"

            if packet.haslayer("TCP"):
                tcp = packet["TCP"]
                protocol = "TCP"
                info += f", Source Port: {tcp.sport}, Destination Port: {tcp.dport}, TCP Flags: {tcp.flags}"

            elif packet.haslayer("UDP"):
                udp = packet["UDP"]
                protocol = "UDP"
                info += f", Source Port: {udp.sport}, Destination Port: {udp.dport}"

            elif packet.haslayer("ICMP"):
                protocol = "ICMP"
                info += f", Type: {packet['ICMP'].type}, Code: {packet['ICMP'].code}"

        elif packet.haslayer("ARP"):
            protocol = "ARP"
            arp = packet["ARP"]
            info = f"Source IP: {arp.psrc}, Destination IP: {arp.pdst}"

        elif packet.haslayer("Ether"):
            protocol = "Ethernet"
            ether = packet["Ether"]
            info = f"Source MAC: {ether.src}, Destination MAC: {ether.dst}"

        if protocol:
            print(f"Protocol: {protocol}, {info}")

        print("-----")


if __name__ == "__main__":
    filename = input("Enter the path to the .pcap file: ")
    pcap(filename)
