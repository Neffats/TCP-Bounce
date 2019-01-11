from bs4 import BeautifulSoup
import requests
import re
import socket

class URL_Retreiver():
        
        def __init__(self, source):
                self.source = source
                self.URLs = []
                self.pageSoup = None
                self.pattern = re.compile(r'\w*\.\w*')
                self.ipAddresses = []
        
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
                        #print(i)
                        try:
                                address = socket.gethostbyname(i)
                        except:
                                continue
                        #print(address)
                        self.ipAddresses.append(address)                                

        def get_info(self):
                self.get_page()
                self.parse_page()
                self.get_ip()
                print(len(self.ipAddresses))


r = URL_Retreiver("https://moz.com/top500")
r.get_info()