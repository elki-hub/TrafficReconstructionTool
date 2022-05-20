from graphviz import *
from scapy.all import *

pcap_data = rdpcap("data.pcap")

commands = (
    ('help', 'Print this help message'),
    ('sniff', 'Open pcap data'),
    ('conv', 'Print conversations'),
    ('quit', 'Close the program')
)


def show_packet_info(pkt):
    param = re.search("\/.+\/ (\w+) ([^\s]+) > ([^\s]+)", pkt.summary())
    print("Source of the IP: " + param.group(2))
    print("Destination of the IP: " + param.group(3))
    print("Protocol: " + param.group(1))
    print("Data in hex form: ")
    hexdump(pkt)


def sniff():
    print(pcap_data)
    length = len(pcap_data)
    while True:
        cmd = input("Enter index of packet from 0 to " + str(length - 1) + " : ")

        if cmd in ('quit', 'q'):
            return False

        try:
            index = int(cmd)
            if length > index >= 0:
                print("---------- " + cmd + " Packet info ----------")
                show_packet_info(pcap_data[index])
                print("--------------------------------------------")
            else:
                print("wrong input try again!")
        except ValueError:
            print("wrong input try again!")


def interpret(cmd, arguments):
    """Perform command required by user."""
    if cmd == 'help':
        print('Available commands:')
        for name, desc in commands:
            print('    %s%s' % (name.ljust(28), desc))
    elif cmd == 'sniff':
        sniff()
    elif cmd == 'conv':
        pcap_data.conversations(type="jpg", target="> test.jpg")
    elif cmd == 'quit':
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