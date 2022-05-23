import pygeoip
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP

pcap_data = rdpcap("exercise1.pcap")
rawdata = pygeoip.GeoIP('GeoLiteCity.dat')

commands = (
    ('help', 'Show available commands'),
    ('sniff', 'Open pcap data'),
    ('det <index>', 'Print detailed packet info'),
    ('dump <index>', 'Print detailed packet diagram'),
    ('sus', 'Print suspicious traffic'),
    ('conv', 'Print conversations'),
    ('quit', 'Go back'),
    ('exit', 'Close the program')
)


def filter_packets(pkts):
    filtered = [pkt for pkt in pkts if UDP in pkt]
    return filtered


def sus_data():
    print("*************** Suspicious data: ***************")
    index = 0
    for pkt in pcap_data:
        if UDP in pkt:
            if pkt['UDP'].sport != 1900 or pkt['UDP'].dport != 1900:
                print("* " + str(index) + " " + pkt.summary())
        elif TCP in pkt:
            if str(pkt.flags) == "DNS":
                print("* " + str(index) + " " + pkt.summary())
        index = index + 1
    print("*************************************************")


def confirmation_message(message):
    cmd = input(message)

    if cmd == "Yes" or cmd == "Y" or cmd == "y" or cmd == "yes":
        return True
    elif cmd == "No" or cmd == "N" or cmd == "n" or cmd == "no":
        return False
    else:
        print('Unknown command.')
        confirmation_message(message)


def get_location(ip):
    try:
        return rawdata.record_by_name(ip)['country_name']
    except:
        return ""


def show_packet_info(pkt):
    protocol = "none"
    description = ""

    if TCP in pkt:
        src = pkt[1].src + ":" + str(pkt[2].sport)
        dst = pkt[1].dst + ":" + str(pkt[2].dport)
        protocol = "TCP"
        dst_country = get_location(pkt[1].src)
        src_country = get_location(pkt[1].dst)
    elif UDP in pkt:
        src = pkt[1].src + ":" + str(pkt[2].sport)
        dst = pkt[1].dst + ":" + str(pkt[2].dport)
        protocol = "UDP"
        description = re.search("\/ IP \/ (\w+) /?(.+)", pkt.summary()).group(0)
        dst_country = get_location(pkt[1].src)
        src_country = get_location(pkt[1].dst)
    elif IP in pkt:
        src = pkt['IP'].src
        dst = pkt['IP'].dst
        dst_country = get_location(src)
        src_country = get_location(dst)
        if pkt['IP'].proto == 2:
            protocol = "IGMP"
    elif ARP in pkt:
        description = re.search("\/ (ARP) ([^\d]+) ([^\s]+) (\w+) ([^\s]+)", pkt.summary()).group(0)
        protocol = "ARP"
        src = str(pkt['ARP'].psrc)
        dst = str(pkt['ARP'].pdst)
        dst_country = get_location(src)
        src_country = get_location(dst)
    else:
        print("This is else")
        return print(pkt.summary())

    print("Source of the IP: " + src + " " + src_country)
    print("Destination of the IP: " + dst + " " + dst_country)
    print("Protocol: " + protocol)
    print("Description: " + description)
    print("Time stamp: " + str(datetime.fromtimestamp(int(pkt.time))))
    print("Data in hex form: ")
    hexdump(pkt)


def det(arguments):
    if len(arguments) == 0:
        print("Packet index value is missing")
        return
    try:
        index = int(arguments[0])
        if len(arguments) > 1 and arguments[1] == "-f":
            return det_full(arguments)
        if len(pcap_data) > index >= 0:
            print("---------- " + arguments[0] + " Packet info ----------")
            show_packet_info(pcap_data[index])
            print("--------------------------------------------")
        else:
            print("Packet index value has to be between 0 and " + str(len(pcap_data)))
    except ValueError:
        interpret(arguments[0], "")


def det_full(arguments):
    if len(arguments) == 0:
        print("Packet index value is missing")
        return
    try:
        index = int(arguments[0])
        if len(pcap_data) > index >= 0:
            print("---------- " + arguments[0] + " Packet info ----------")
            pcap_data[index].show()
            print("--------------------------------------------")
        else:
            print("Packet index value has to be between 0 and " + str(len(pcap_data)))
    except ValueError:
        interpret(arguments[0], "")


def dump(arguments):
    if len(arguments) == 0:
        print("Packet index value is missing")
        return
    try:
        index = int(arguments[0])

        if len(pcap_data) > index >= 0:
            pcap_data[index].pdfdump(layer_shift=1)
        else:
            print("Packet index value has to be between 0 and " + str(len(pcap_data)))
    except ValueError:
        interpret(arguments[0], "")


def sniff():
    print(pcap_data)
    length = len(pcap_data)
    while True:
        print("Enter index of packet from 0 to " + str(length - 1) + " : ")
        command = input('> ').split(' ')

        cmd = command[0]
        arguments = command[1:]

        if len(arguments) > 0:
            return interpret(cmd, arguments)
        elif cmd == "quit":
            return
        else:
            det([cmd])


def interpret(cmd, arguments):
    """Perform command required by user."""
    if cmd == 'help':
        print('Available commands:')
        for name, desc in commands:
            print('    %s%s' % (name.ljust(28), desc))
    elif cmd == 'sniff':
        sniff()
    elif cmd == 'det':
        det(arguments)
    elif cmd == 'dump':
        dump(arguments)
    elif cmd == 'sus':
        sus_data()
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
    print('\n')
    while True:
        print('Write command ("help" for details):')
        try:
            command = input('> ').split(' ')
        except (EOFError, KeyboardInterrupt):
            print('')
            exit(0)
        cmd = command[0]
        arguments = command[1:]
        interpret(cmd, arguments)
