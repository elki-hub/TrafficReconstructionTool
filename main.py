from scapy.all import *
from scapy.layers.dns import DNS
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP

pcap_data = rdpcap("data.pcap")


commands = (
    ('help', 'Show available commands'),
    ('sniff', 'Open pcap data'),
    ('sus', 'Suspicious traffic'),
    ('conv', 'Print conversations'),
    ('quit', 'Go back'),
    ('exit', 'Close the program')
)


def filter_packets(pkts):
    filtered = [pkt for pkt in pkts if UDP in pkt]
    # for pkt in pkts:
    #     if TCP in pkt:
    #         print(pkt.summary())
    # filtered = [pkt for pkt in pkts if TCP in pkt and ((
    #             pkt[IP].src == src and pkt[IP].dst == dst and pkt[TCP].sport == sp and
    #             pkt[TCP].dport == dp) or (
    #             pkt[IP].src == dst and pkt[IP].dst == src and pkt[TCP].sport == dp and
    #             pkt[TCP].dport == sp))]
    return filtered


def sus_data():
    print("*****filtering data: ******")
    index = 0
    for pkt in pcap_data:
        if UDP in pkt:
            if pkt['UDP'].sport != 1900 or pkt['UDP'].dport != 1900:
                print(str(index) + " " + pkt.summary())
        elif TCP in pkt:
            if str(pkt.flags) == "DNS":
                print(str(index) + " " + pkt.summary())
        index = index + 1
    print("*****the end of filtering*****")


def confirmation_message(message):
    cmd = input(message)

    if cmd == "Yes" or cmd == "Y" or cmd == "y" or cmd == "yes":
        return True
    elif cmd == "No" or cmd == "N" or cmd == "n" or cmd == "no":
        return False
    else:
        print('Unknown command.')
        confirmation_message(message)


def show_packet_info(pkt):
    print(ls(pkt))
    if TCP in pkt:
        print("Source of the IP: " + pkt[1].src + ":" + str(pkt['TCP'].sport))
        print("Destination of the IP: " + pkt[1].dst + ":" + str(pkt['TCP'].dport))
        print("Protocol: " + "TCP")

    elif UDP in pkt:
        description = re.search("\/ IP \/ (\w+) /?(.+)", pkt.summary())
        print("Source of the IP: " + pkt[1].src + ":" + str(pkt['UDP'].sport))
        print("Destination of the IP: " + pkt[1].dst + ":" + str(pkt['UDP'].dport))
        print("Protocol: " + description.group(1))
        print("Description: " + description.group(2))
    elif IP in pkt:
        print("Source of the IP: " + pkt['IP'].src)
        print("Destination of the IP: " + pkt['IP'].dst)
        print("Protocol: " + "none")
    elif ARP in pkt:
        description = re.search("\/ (ARP) ([^\d]+) ([^\s]+) (\w+) ([^\s]+)", pkt.summary())
        print("Source of the IP: " + str(pkt['ARP'].psrc))
        print("Destination of the IP: " + str(pkt['ARP'].pdst))
        print("Protocol: " + description.group(1))
        print("Description: " + description.group(0))
    else:
        print("This is else")
        print(pkt.summary())

    print("Data in hex form: ")
    hexdump(pkt)


def sniff():
    print(pcap_data)
    length = len(pcap_data)
    # print(pcap_data.show())
    #print(len(filter_packets(pcap_data)))
    while True:
        cmd = input("Enter index of packet from 0 to " + str(length - 1) + " : ")

        try:
            index = int(cmd)
            if length > index >= 0:
                print("---------- " + cmd + " Packet info ----------")
                show_packet_info(pcap_data[index])
                print("--------------------------------------------")
            else:
                interpret(cmd, "")
        except ValueError:
            interpret(cmd, "")


def interpret(cmd, arguments):
    """Perform command required by user."""
    if cmd == 'help':
        print('Available commands:')
        for name, desc in commands:
            print('    %s%s' % (name.ljust(28), desc))
    elif cmd == 'sus':
        sus_data()
    elif cmd == 'sniff':
        sniff()
    elif cmd == 'conv':
        pcap_data.conversations(type="jpg", target="> conversations.jpg")
    elif cmd == 'quit':
        return False
    elif cmd == 'exit':
        if confirmation_message("Are you sure you want to close the program? Y/N "):
            exit(0)
    else:
        print('Unknown command.')


if __name__ == '__main__':
    while True:
        print('\nWrite command ("help" for details):')
        try:
            command = input('> ').split(' ')
        except (EOFError, KeyboardInterrupt):
            print('')
            exit(0)
        cmd = command[0]
        arguments = command[1:]
        interpret(cmd, arguments)
