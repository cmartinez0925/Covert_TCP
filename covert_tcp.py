#Author: Chris Martinez
#Course: Covert Channels
#Date:   June 15, 2024
#Description: Takes the original covert_tcp.c script written by
#             Craig H. Rowland (1996) and coverts it into a 
#             modern python script using Scapy as its main 
#             driver for the packet manipulation turning
#             the ID field within an IP packet into a covert channel.
#             The encyrption is simple, I am just turning the char
#             into a value via unicode that can be used to fill in
#             the ID field. I've only tested this on kali linux. You
#             can use this on other linux distros, but results may vary.


#########################################################################################
#IMPORTS - Gathering the troops
#########################################################################################
import atexit
import argparse
import os
import sys
import time

from scapy.all import IP, TCP, send, sniff

#########################################################################################
#GLOBAL VARIABLES
#########################################################################################
received_data_file = None #So the process_packets can use it for sniff()

#########################################################################################
#FUNCTIONS
#########################################################################################
#Author: Chris Martinez
#Date: June 16, 2024 
#Description: Parses id field of an IP packet to get covert character
#Params: IP/TCP Packet
#Return: None
def process_packets(pkt):
    global received_data_file
    char = chr(pkt["IP"].id) #grab the "secret" letter
    print(f"Receiving Data: {char}")
    if received_data_file:
        try:
            received_data_file.write(char)
            received_data_file.flush()
        except Exception as e:
            print(f"Error writing to file: {e}")

#Author: Chris Martinez
#Date: June 16, 2024
#Description: Closes file upon exit
#Params: None
#Return: None
def exit_handler():
    global received_data_file
    if received_data_file is not None:
        received_data_file.close()


#########################################################################################
#MAIN() SCRIPT
#########################################################################################
#Author: Chris Martinez
#Date: June 16, 2024
#Description: Main Script
#Params: None
#Return: None
def main():
    #########################################################################################
    #TERMINAL ARGUMENTS SETUP - Get data from user via the terminal
    #########################################################################################
    parser = argparse.ArgumentParser(description="Covert TCP - Covert channel message transfer for Linux")
    parser.add_argument("-s", "--src_ip", action="store", dest="src_ip", type=str, 
                        required=True, help="Source IP Address")
    parser.add_argument("-d", "--dest_ip", action="store", dest="dst_ip", type=str,
                        required=True, help="Destination IP Address")
    parser.add_argument("-p", "--src_port", action="store", dest="src_port", type=int, 
                        required=True, help="Source Port")
    parser.add_argument("-t", "--dst_port", action="store", dest="dst_port", type=int, 
                        required=True, help="Destination Port")
    parser.add_argument("-f", "--filename", action="store", dest="filename", type=str,
                        required=True, help="File that contains message to be sent")
    parser.add_argument("-S", "--server", action="store_true", dest="server",
                        help="Run Script in Server Mode")
    args = parser.parse_args()

    #########################################################################################
    #CONSTANT VARIABLES - Thou shall not change
    #########################################################################################
    VERSION = "1.0"
    SRC_ADDR = args.src_ip
    DEST_ADDR = args.dst_ip
    SRC_PORT = args.src_port
    DEST_PORT = args.dst_port
    FILENAME = args.filename
    RECEIVING_DATA = args.server #original script used --server, but this variable name helps me keeps things straight in my nugget
    BPF = f"tcp and src host {SRC_ADDR} and src port {SRC_PORT} and dst host {DEST_ADDR} and dst port {DEST_PORT} and tcp[tcpflags] == tcp-syn"
    MSG_SIZE = 1
    ONE_SECOND = 1
    ROOT = 0

    global received_data_file
    atexit.register(exit_handler)
    
    #Lets get the party started
    print(f"Covert TCP {VERSION} (c)2024 Christopher E. Martinez (cmart104@jh.edu)")
    print("Not for commercial use without permission.") #But if you do, give your boy a shout out please
    print("Covert Channel Assignment 1 - Recreating covert_tcp.c using Scapy\n")

    #Only god can wield such power... him and root
    if os.geteuid() != ROOT:
        sys.exit("You need to be root to run this script.")

    #########################################################################################
    #RECEIVING COVERT DATA - We do the following if we are receiving the covert message
    #########################################################################################
    if RECEIVING_DATA:
        try:
            received_data_file = open(FILENAME, "at")
            received_data_file.writelines(["\nPrinting Covert Message...\n"])
            received_data_file.flush()
        except Exception as e:
            sys.exit(f"Error opening file: {e}")

        print(f"Sniffing Packets with this BPF filter:\n{BPF}")
        try:
            sniff(filter=BPF, iface='eth0', prn=process_packets, store=0)
        except Exception as e:
            print(f"Error during sniffing: {e}")
    #########################################################################################
    #SENDING COVERT DATA - We do this if we are trying to send the covert message
    #########################################################################################
    else:
        try:
            with open(FILENAME, "rt") as data_to_send_file:
                while True:
                    char = data_to_send_file.read(MSG_SIZE) 
                    if not char:
                        break
                    print(f"Sending data: {char}")
                    #Lets build this packet and send this bad boy
                    packet = IP(src=SRC_ADDR, dst=DEST_ADDR, id=ord(char)) / TCP(sport=SRC_PORT, dport=DEST_PORT, flags="S")
                    send(packet)
                    time.sleep(ONE_SECOND) #we need to make sure each packet gets there in order
        except Exception as e:
            sys.exit(f"Error reading file: {e}")

if __name__ == '__main__':
    main()
