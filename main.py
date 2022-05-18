from scapy.all import *


def show_packet_info(pkt):
    print("Source of the IP: " + pkt.src)
    print("Destination of the IP: " + pkt.dst)
    print("Protocol: " + re.search("\/.+\/ (\w+) ", pkt.summary()).group(1))
    print("Data in hex form: ")
    hexdump(pkt)


def show_data(data):
    print(data)
    # print(len(data))
    pkt = data[1000]
    # print(pkt)
    # print(type(pkt))
    # print(dir(pkt))
    # print()
    # print(ls(pkt))
    # print(lsc())
    # print(pkt.src)
    print("summary: " + pkt.summary())
    pkt.show()
    print("Show the Source of the IP: " + pkt.src)
    print("Show the destination of the IP: " + pkt.dst)
    # print("Show what protocol was used to transmit data: " + pkt)
    # print("Show data in hex form: " + hexdump(pkt))


if __name__ == '__main__':
    data = rdpcap("data.pcap")
    print(data)
    length = len(data)

    print("To end the process enter 'exit'")
    var = ""
    while var != "exit":
        var = input("Enter index of packet from 0 to " + str(length - 1) + " : ")

        if var == "exit":
            break

        try:
            index = int(var)
            if length > int(var) >= 0:
                print("---------- " + var + " Packet info ----------")
                show_packet_info(data[int(var)])
                print("--------------------------------------------")
            else:
                print("wrong input try again!")
        except ValueError:
            print("wrong input try again!")