from scapy.all import *

pcap_data = rdpcap("data.pcap")

commands = (
    ('help', 'Print this help message'),
    ('sniff', 'Open pcap data'),
    ('conv', 'Print conversations'),
    ('quit', 'Go back'),
    ('exit', 'Close the program')
)


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