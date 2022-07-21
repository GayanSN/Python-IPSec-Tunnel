#! /usr/bin/python3

import struct, os, socket
from fcntl import ioctl
from struct import *
from ctypes import *
from threading import Thread
import netifaces as ni
from hashlib import md5
from Crypto.Cipher import AES
import getpass

TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000
TUNMODE = IFF_TUN

ETH_P_IP = 0x0800

class IPv4(Structure):
    _fields_ = [
            ("ver", c_ubyte, 4),
	    ("ihl", c_ubyte, 4),
            ("tos", c_ubyte),
            ("len", c_ushort),
            ("id", c_ushort),
            ("offset", c_ushort),
            ("ttl_val", c_ubyte),
            ("protocol_num", c_ubyte),
            ("checksum", c_ushort),
            ("src", c_uint),
            ("dst", c_uint)
            ]
    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):

        self.src_address = socket.inet_ntoa(pack("@I",self.src))
        self.dst_address = socket.inet_ntoa(pack("@I",self.dst))

         ##map protocol constants to their names
        self.protocol_map = {1:"ICMP", 6:"TCP", 17:"UDP", 50:"ESP", 51:"AH"}

        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except:
            self.protocol = str(self.protocol_num)


class AESencryptor:
    def __init__(self, key):
        self.key = md5(key.encode('utf8')).hexdigest()

    def padding_length(self, s):
        length = (AES.block_size - len(s) % AES.block_size)
        return length

    def pad(self, s):
        length = self.padding_length(s)
        s =  s + b"\0" * length
        return s

    def encrypt(self, raw):
        raw = self.pad(raw)
        cipher = AES.new(self.key.encode("utf8"), AES.MODE_ECB)
        return cipher.encrypt(raw)

    def decrypt(self, ciphertext):
        cipher = AES.new(self.key.encode("utf8"), AES.MODE_ECB)
        plaintext = cipher.decrypt(ciphertext)
        return (plaintext.rstrip(b"\0"))


def tun_open(devname):
    fd = os.open("/dev/net/tun", os.O_RDWR)
    ifr = struct.pack('16sH', devname.encode(), IFF_TUN | IFF_NO_PI)
    ifs = ioctl(fd, TUNSETIFF, ifr)
    return fd


def create_esph(seq):

    esp_spi = 100
    esp_seqno = seq
    
    esp_header =  pack('!II', esp_spi, esp_seqno)

    esp = esp_header

    return esp

def create_espt(data):
    
    esp_padlength = AESencryptor(key).padding_length(data)
    esp_nextheader = 1 

    esp_trailer =  pack('!BB', esp_padlength, esp_nextheader)

    return esp_trailer


def create_ip(esp):

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ESP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    ip_ihl = 5
    ip_ver = 4
    ip_tos = 0
    ip_tot_len = 0
    ip_id = 54321
    ip_frag_off = 0
    ip_ttl_val = 128
    ip_prot = 50     ##50 --> ESP
    ip_checksum = 0
    ip_saddr = socket.inet_aton(ip)         ##source IP address
    ip_daddr = socket.inet_aton(dest)       ##destination IP address

    ip_ihl_ver = (ip_ver << 4) + ip_ihl

    ip_header = pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl_val, ip_prot, ip_checksum, ip_saddr, ip_daddr)

    packet = ip_header + esp

    sock.sendto(packet, (dest, 0))  


def send_data(fd,):
    sq = 1

    while True:
        try:
            data = os.read(fd, 1600)     ##read data from virtual interface

            esp_trailer = create_espt(data)     ##create ESP Trailer

            data_to_encrypt = data + esp_trailer  

            enc_payload = AESencryptor(key).encrypt(data_to_encrypt)  ##encrypt original packet + ESP Trailer

            esp_h = create_esph(sq)  ##create ESP Header
            sq += 1

            esp_h = esp_h + enc_payload

            create_ip(esp_h)   ##create a new IP Header, place the ESP Header inside the new IP Header and send to the destination

        except Exception as e:
            print(e)
            exit(1)


def recv_data(fd,):

    while True:
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_IP))
            s.bind((iface, 0))

            data = s.recvfrom(65565)[0]
            ip = IPv4(data[14:])

            if ip.src_address == dest and ip.protocol == "ESP":    ##check for ESP packets

                data_to_decrypt = data[42:]         ##get the encrypted data field to decrypt
                                                    ##Ethernet(14) + IP(20) + ESP(8) headers = 42bytes

                dec_payload = AESencryptor(key).decrypt(data_to_decrypt)  ##decrypt the data and retrieve the original packet

                dec_payload = os.write(fd, dec_payload)   ##write the original packet to the virtual interface

        except Exception:
            print(f"\nTunnel Establishment Failed!\nPlease Verify the Secret Key and Try Again!\n")
            os._exit(1)


def ipsec_tunnel():
    while True:
        try:
            ts = Thread(target=send_data, args=(fd,), daemon = True)
            tr = Thread(target=recv_data, args=(fd,), daemon = True)

            ts.start()
            tr.start()

            ts.join()
            tr.join()

        except KeyboardInterrupt:
            print("\nClosing IPSec Tunnel...\n")
            exit(1)


if __name__ == "__main__":

    try:
        dest = input("\nEnter the IP address of Remote Host: ")     ##Destination IP address
        key = str(getpass.getpass("Enter the Encryption Key: "))    ##Encryption Key
        
        if_list = ni.interfaces()
        iface = input("Select the Interface --> {} : ".format(if_list))
    
    except KeyboardInterrupt:
        exit(1)

    ip = ni.ifaddresses(iface)[ni.AF_INET][0]['addr']  ##get the IP address of the interface 

    fd = tun_open('asa0')

    print(f"\nOpening IPSec Tunnel...")

    ipsec_tunnel()             ##calling the main function

	
