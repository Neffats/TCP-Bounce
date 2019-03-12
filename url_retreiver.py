from scapy.all import *
import time
from bs4 import BeautifulSoup
import requests
import re
import socket
import os

class URL_Retreiver():
        
    def __init__(self, source: str):
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
        for url in self.URLs:
            try:
                address = socket.gethostbyname(url)
            except:
                print(f"Failed to resolve: {url}")
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