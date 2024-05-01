from scapy.arch.windows import get_windows_if_list
from scapy.all import sniff

#choose interface to capture from
def choose_interface():
    # display all network interface to capture from
    interfaces = get_windows_if_list()
    print("Available network interfaces: \n ")
    i = 1
    for interface in interfaces:
        print(f"{i}.{interface['name']}")
        i+=1

    #choose interface to capture from
    index_interface = int(input("select the number of interface you want to capture from :"))
    return interfaces[index_interface - 1]['name']


#packet_sniffing
def sniff_packets(interface):
    packets = sniff(iface = interface , count = 5)
    if packets:
        return packets
    else:
        print("No packets captured from interface:", interface)
        return None

#analyze packet
def packet_analyze(packets):
    for packet in packets:
        print("origin packet:", packet)
        print("packet summary:" , packet.summary())


interface = choose_interface()
packets_captured = sniff_packets(interface)
print("details \n")
print(packet_analyze(packets_captured))



















