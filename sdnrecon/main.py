import signal
import os
import socket
import ipcalc
import netifaces
import re
import xlrd
import sys, select
from inputimeout import inputimeout, TimeoutOccurred

def signal_handler(signal, frame):
  #Handle Ctrl+C here
  print("")
  print("Exiting...")
  exit(0)

def is_valid_ipv4_address_1(address):
	if ("/" in address):
		address = address.split("/")[0]
	try:
		socket.inet_pton(socket.AF_INET, address)
	except AttributeError: 
		try:
			socket.inet_aton(address)
		except socket.error:
			return False
		return address.count('.') == 3
	except socket.error: 
		return False
	return True

def is_valid_ipv4_address_2(address):
	try:
		socket.inet_pton(socket.AF_INET, address)
	except AttributeError: 
		try:
			socket.inet_aton(address)
		except socket.error:
			return False
		return address.count('.') == 3
	except socket.error: 
		return False
	return True

def is_valid_iface(interface):
	try:
		list_ifaces = netifaces.interfaces()
	except:
		print("Error: Can't identify list of valid interfaces")
		return False

	if interface not in list_ifaces:
		return False
	else:
		return True

def is_valid_port(port):
	list_ports=[]
	if("," in port):
		list_ports=port.split(",")
	elif("-" in port):
		list_ports=port.split("-")
	else:
		list_ports.append(port)
	check=0
	for p in list_ports:
		if (p.isdigit() == False):
			return False
		else:
			if (int(p)<1) or (int(p)>65535):
				check = check + 1
				if check > 0:
					return False
	if check==0:
		return True

def is_valid_macaddr802(value):
    allowed = re.compile(r"""
                         (
                             ^([0-9A-F]{2}[-]){5}([0-9A-F]{2})$
                            |^([0-9A-F]{2}[:]){5}([0-9A-F]{2})$
                         )
                         """,
                         re.VERBOSE|re.IGNORECASE)

    if allowed.match(value) is None:
        return False
    else:
        return True

def input_timeout(prompt_input, time_out=10):
	try:
		something = inputimeout(prompt=prompt_input, timeout=time_out)
	except TimeoutOccurred:
		something = ""
	return something

def Option1():
	print("""



               __       _______                        
     .-----.--|  .-----|   _   .-----.----.-----.-----.
     |__ --|  _  |     |.  l   |  -__|  __|  _  |     |
     |_____|_____|__|__|.  _   |_____|____|_____|__|__|
                       |:  |   |                       
                       |::.|:. |                       
                       `--- ---'                       
      SDNRecon [*] is a reconnaissance framework. 
               [*] targets SDN Network.
               [*] has the capability of automation.
     
      
      [++] Choose a number:
            
            [01] SDN Network Detector
            [02] Host Discovery tools
            [03] Controller Detector 
            [04] Port Scanner 
            [05] Rule Reconstructor
            [06] AutoRecon Utility

    """)
def Choose_Op1():
		Option1()
		c = input("sdnrecon> ")
		if(c=="exit"):
			print("Exiting...")
			return
		while ((c.isdigit()==False) or (int(c) not in range (1,7))):
			if(c=="exit"):
				print("Exiting...")
				return
			c = input("sdnrecon> ")
		return int(c)
def OptionHD():
	print("host_discovery> ")
	print("""
    [01] ARPScan  
    [02] PingScan
    """)

def Choose_HD():
	OptionHD()
	c = input("host_discovery> ")
	if(str(c)=="back"):
		return c
	while ((c.isdigit()==False) or (int(c) not in range (1,3))):
		if(str(c)=="back"):
			return 0
		print("""1.arp_scan  2.ping_scan""")
		c = input("host_discovery> ")
	else:
		return int(c)

def OptionSDNDetect():
	print("sdn_detect> ")
	print("""
    [01] Base on observing Round-Trip Times (RTT) for ICMP traffic
    [02] Base on observing Round-Trip Times (RTT) for ARP traffic
    [03] Base on detecting OpenFlow protocol
    [04] Detect openFlow version 
    """)

def Choose_SDNDetect():
	OptionSDNDetect()
	c = input("sdn_detect> ")
	if(str(c)=="back"):
		return c
	while ((c.isdigit()==False) or (int(c) not in range (1,5))):
		if(str(c)=="back"):
			return 0
		print("""
    [01] Base on observing Round-Trip Times (RTT) for ICMP traffic
    [02] Base on observing Round-Trip Times (RTT) for ARP traffic
    [03] Base on detecting OpenFlow protocol
    [04] Detect openflow version 
    """)
		c = input("sdn_detect> ")
	else:
		return int(c)

def OptionCD():
	print("controller_detect> ")
	print("""
    [01] Detect type of controller base on lldp traffic
    [02] Detect type of controller base on northbound interface
    [03] Detect multi controller
    """)



def Choose_CD():
	OptionCD()
	c = input("controller_detect> ")
	if(str(c)=="back"):
		return c
	while ((c.isdigit()==False) or (int(c) not in range (1,4))):
		if(str(c)=="back"):
			return 0
		print("""
    [01] Detect type of controller base on lldp traffic
    [02] Detect type of controller base on northbound interface
    [03] Detect multi controller
    """)
		c = input("controller_detect> ")
	else:
		return int(c)
def OptionPS():
	print("port_scanner> ")
	print("""
    [01] Simple Port Scanner
    [02] Phantom Host Scanner
    """)

def Choose_PS():
	OptionPS()
	c = input("port_scan> ")
	if(str(c)=="back"):
		return c
	while ((c.isdigit()==False) or (int(c) not in range (1,3))):
		if(str(c)=="back"):
			return 0
		print("""
    [01] Simple Port Scanner
    [02] Phantom Host Scanner
    """)
		c = input("port_scan> ")
	else:
		return int(c)
def OptionRR():
	print("rule_recontruction> ")
	print("""
    [01] Use ICMP protocol
    [02] Use ARP protocol
    """)

def Choose_RR():
	OptionRR()
	c = input("rule_recontruction> ")
	if(str(c)=="back"):
		return c
	while ((c.isdigit()==False) or (int(c) not in range (1,3))):
		if(str(c)=="back"):
			return 0
		print("""
    [01] Use ICMP protocol
    [02] Use ARP protocol
    """)
		c = input("rule_recontruction> ")
	else:
		return int(c)



def Session1():
	signal.signal(signal.SIGINT, signal_handler) #Assign the signal handler
	back=1
	while back == 1:
		back=0
		c_1 = Choose_Op1()
		if (c_1 == 2):
			back2 = 1
			while back2 == 1:
				back2=0
				c_HD = Choose_HD() 
				if (str(c_HD) == "back"): 
					back = 1
					continue
				elif (c_HD == 1):
					print("host_discovery> ARP Scan")
					ip = input("[?] Target IP Address: ")
					if (str(ip) == "back"):
						back2=1
						continue
					while(is_valid_ipv4_address_1(ip)==False):
						ip = input("[?] Target IP Address: ")
					iface = input("[?] Target Network Interface: ")
					if  (str(iface) == "back"):
						back2=1
						continue
					while(is_valid_iface(iface)==False):
						iface = input("[?] Target Network Interface: ")
					timeout = input("[?] Timeout [3]:")
					if (str(timeout) == "back"):
						back2=1
						continue
					if(timeout == ""):
						timeout=3
					else:
						while(timeout.isdigit()==False):
							if(timeout == ""):
								timeout=3
								break
							timeout = input("[?] Timeout [3]:")
						timeout=int(timeout)
					ip=str(ip)
					iface=str(iface)
					timeout=str(timeout)
					#Ví dụ lệnh chạy ARPScan là: python arpscan.py -IP <Địa chỉ IP> -I <Interface> -timeout <timeout> 
					#Cây thư mục đặt file main.py và arpscan.py như sau:
					# C:.
					# |   main.py
					# |
					# \---arpscan
							# arpscan.py
					#command="python arpscan/arp_scan.py -t "+ip+" -I "+iface+" -timeout "+timeout
					command="python3.6 arpscan/arp_scan.py -t "+ip+" -i "+iface+ " -to "+timeout
					#print(command)
					os.system(command)
					#back=1

				elif (c_HD == 2):
					print("host_discovery> Ping Scan")
					ip = input("[?] Target IP Address: ")
					if (str(ip) == "back"):
						back2=1
						continue
					while(is_valid_ipv4_address_1(ip)==False):
						ip = input("[?] Target IP Address: ")
					#iface = input("[?] Target Network Interface: ")
					#if  (str(iface) == "back"):
					#	back2=1
					#	continue
					#while(is_valid_iface(iface)==False):
					#	iface = input("[?] Target Network Interface: ")
					timeout = input("[?] Timeout [1]:")
					if (str(timeout) == "back"):
						back2=1
						continue
					if(timeout == ""):
						timeout=1
					else:
						while(timeout.isdigit()==False):
							if(timeout == ""):
								timeout=1
								break
							timeout = input("[?] Timeout [1]:")
						timeout=int(timeout)
					ip=str(ip)
					#iface=str(iface)
					timeout=str(timeout)
					command="python3.6 pingscan/ping_scan.py -t "+ip+" -to "+timeout
					#print(command)
					os.system(command)
					#back=1

		
		elif (c_1 == 1):
			back2 = 1
			while back2 == 1:

				back2=0

				c_SDN = Choose_SDNDetect() 

				if (str(c_SDN) == "back"): 
					back = 1
					continue
				elif (c_SDN == 1):
					print("sdn_detect> ICMP RTT")
					ip = input("[?] Target IP Address: ")
					if (str(ip) == "back"):
						back2=1
						continue
					while(is_valid_ipv4_address_2(ip)==False):
						ip = input("[?] Target IP Address: ")
						if (str(ip) == "back"):
							back2=1
							break
					if (str(ip) == "back"):
						back2=1
						continue
					interval = input("[?] Interval at which packets are sent [1]:")
					if (str(interval) == "back"):
						back2=1
						continue
					if(interval == ""):
						interval=1
					else:
						while(interval.isdigit()==False):
							if(interval == ""):
								interval=1
								break
							interval = input("[?] Interval at which packets are sent [1]:")
						interval=int(inteval)
					num_pkts = input("[?] Number of packets to send [10]:")
					if (str(num_pkts) == "back"):
						back2=1
						continue
					if(num_pkts == ""):
						num_pkts=10
					else:
						while(num_pkts.isdigit()==False):
							if(num_pkts == ""):
								num_pkts=10
								break
							interval = input("[?] Number of packets to send [10]:")
						num_pkts=int(num_pkts)
					ip=str(ip)
					interval=str(interval)
					num_pkts=str(num_pkts)
					command="python3.6 sdndetect/sdn_detect.py -m icmp -t "+ip+" -i "+interval+ " -c "+num_pkts
					#print(command)
					os.system(command)
					#back=1
					

				elif (c_SDN == 2):
					print("sdn_detect> ARP RTT")
					ip = input("[?] Target IP Address: ")
					if (str(ip) == "back"):
						back2=1
						continue
					while(is_valid_ipv4_address_2(ip)==False):
						ip = input("[?] Target IP Address: ")
					interval = input("[?] Interval at which packets are sent [1]:")
					if (str(interval) == "back"):
						back2=1
						continue
					if(interval == ""):
						interval=1
					else:
						while(interval.isdigit()==False):
							if(interval == ""):
								interval=1
								break
							interval = input("[?] Interval at which packets are sent [1]:")
						interval=int(inteval)
					num_pkts = input("[?] Number of packets to send [10]:")
					if (str(num_pkts) == "back"):
						back2=1
						continue
					if(num_pkts == ""):
						num_pkts=10
					else:
						while(num_pkts.isdigit()==False):
							if(num_pkts == ""):
								num_pkts=10
								break
							num_pkts = input("[?] Number of packets to send [10]:")
						num_pkts=int(num_pkts)
					ip=str(ip)
					interval=str(interval)
					num_pkts=str(num_pkts)
					command="python3.6 sdndetect/sdn_detect.py -m arp -t "+ip+" -i "+interval+ " -c "+num_pkts
					#print(command)
					os.system(command)
					#back=1
				
				elif (c_SDN == 3):
					print("sdn_detect> OpenFlow detection")
					iface = input('''[?] Target Network Interface [One or More by ","]: ''')
					if  (str(iface) == "back"):
						back2=1
						continue
					check_ifaces=0
					
					while (check_ifaces == 0):
						if back2==1:
							break
						ifaces=[]
						if ("," in str(iface)):
							ifaces=iface.split(",")
						else:
							ifaces.append(str(iface))
					
						for i in ifaces:
							if(is_valid_iface(i)==False):
								check_ifaces=0
								iface = input('''[?] Target Network Interface [One or More by ","]: ''')
								if  (str(iface) == "back"):
									back2=1
								break
							else:
								check_ifaces=1
					if  (str(iface) == "back"):
						back2=1
						continue
					#print(iface)
					iface = str(iface)
					command="python3.6 sdndetect/sdn_detect.py -m opf -if "+iface
					#print(command)
					os.system(command)
					#back=1
					
				elif (c_SDN == 4):
					print("sdn_detect> Detect OpenFlow Version")
					ip = input("[?] Target IP Address: ")
					if (str(ip) == "back"):
						back2=1
						continue
					while(is_valid_ipv4_address_1(ip)==False):
						ip = input("[?] Target IP Address: ")
						if (str(ip) == "back"):
							back2=1
							break
					if (str(ip) == "back"):
						back2=1
						continue
					port = input("[?] Port Scan [6633,6634, and 6653]: ")
					if (str(port) == "back"):
						back2=1
						continue
					if (str(port) == ""):
						port = "6633,6634,6653"
					while(is_valid_port(port)==False or port.isdigit() == False):
						port = input("[?] Port Scan [6633,6634,6653]: ")
						if (str(port) == "back"):
							back2=1
							break
					if (str(port) == "back"):
						back2=1
						continue
					timeout = input("[?] Timeout [2]: ")
					if (str(timeout) == "back"):
						back2=1
						continue
					if(timeout == ""):
						timeout=2
					else:
						while(timeout.isdigit()==False):
							if(timeout == ""):
								timeout=2
								break
							timeout = input("[?] Timeout [2]:")
						timeout=int(timeout)
					ip=str(ip)					
					port=str(port)
					timeout=str(timeout)
					command="python3.6 sdnpwn/of_scan.py -t "+ip+ " -p "+port + " -s "+ timeout
					print(command)
					os.system(command)
					#back=1



		elif (c_1 == 3):
			back2 = 1
			while back2 == 1:
				back2=0
				c_CD = Choose_CD() 
				if (str(c_CD) == "back"): 
					back = 1
					continue
				elif (c_CD == 1):
					print("controller_detect> Base On LLDP Traffic")
					iface = input("[?] Target Network Interface: ")
					if  (str(iface) == "back"):
						back2=1
						continue
					while(is_valid_iface(iface)==False):
						iface = input("[?] Target Network Interface: ")
						if  (str(iface) == "back"):
							back2=1
							break
					if  (str(iface) == "back"):
						back2=1
						continue
					iface=str(iface)
					command="python3.6 controllerdetect/controller_detect.py -l -i "+ iface
					print(command)
					os.system(command)
					#back=1
					

				elif (c_CD == 2):
					print("controller_detect> Base On Northbound Interface")
					ip = input("[?] Controller IP Address: ")
					if (str(ip) == "back"):
						back2=1
						continue
					while(is_valid_ipv4_address_2(ip)==False):
						ip = input("[?] Controller IP Address: ")
						if (str(ip) == "back"):
							back2=1
							break
					if (str(ip) == "back"):
						back2=1
						continue
					port = input("[?] Port Scan [8080,9000,8181]: ")
					if (str(port) == "back"):
						back2=1
						continue
					if (str(port) == ""):
						port="8080,9000,8181"
					while(is_valid_port(port)==False):
						port = input("[?] Port Scan [8080,9000,8181]: ")
						if (str(port) == "back"):
							back2=1
							break
					if (str(port) == "back"):
						back2=1
						continue
					ip=str(ip)
					port=str(port)
					command="python3.6 controllerdetect/controller_detect.py -t "+ ip+" -p "+port
					print(command)
					os.system(command)
					#back=1
				
				elif (c_CD == 3):
					print("controller_detect> Multi Controller Detect")
					iface = input('''[?] Target Network Interface [One or More by ","]: ''')
					if  (str(iface) == "back"):
						back2=1
						continue
					check_ifaces=0
					while (check_ifaces == 0):
						if back2==1:
							break
						ifaces=[]
						if ("," in str(iface)):
							ifaces=iface.split(",")
						else:
							ifaces.append(str(iface))
					
						for i in ifaces:
							if(is_valid_iface(i)==False):
								check_ifaces=0
								iface = input('''[?] Target Network Interface [One or More by ","]: ''')
								if  (str(iface) == "back"):
									back2=1
								break
							else:
								check_ifaces=1
					if  (str(iface) == "back"):
						back2=1
						continue
					#print(iface)
					iface = str(iface)
					command="python3.6 controllerdetect/multi_controller_detect.py -i "+ iface
					print(command)
					os.system(command)
					#back=1


		elif (c_1 == 4):
			back2 = 1
			while back2 == 1:
				back2=0
				c_PS = Choose_PS() 
				if (str(c_PS) == "back"): 
					back = 1
					continue
				elif (c_PS == 1):
					print("port_scan> Simple Port Scan")
					ip_input = input("""[?] Target IP Address [One or More by ","]: """)
					if (str(ip_input) == "back"):
						back2=1
						continue
					check_ip=0
					while (check_ip == 0):
						if back2==1:
							break
						ips=[]
						if ("," in str(ip_input)):
							ips=ip_input.split(",")
						else:
							ips.append(str(ip_input))
					
						for i in ips:
							if(is_valid_ipv4_address_2(i)==False):
								check_ip=0
								ip_input = input('''[?] Target IP Interface [One or More by ","]: ''')
								if  (str(ip_input) == "back"):
									back2=1
								break
							else:
								check_ip=1
					if  (str(ip_input) == "back"):
						back2=1
						continue
					port = input("""[?] Port Scan [21,22,23,25,53,80,110,111,135,139,143,443,445,
                 993,995,1723,3306,3389,5900,8080,6633,6653,8000]: """)
					if (str(port) == "back"):
						back2=1
						continue
					if (str(port) == ""):
						port="21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,6633,6653,8000"
					while(is_valid_port(port)==False):
						port = input("""[?] Port Scan [21,22,23,25,53,80,110,111,135,139,143,443,445,
                 993,995,1723,3306,3389,5900,8080,6633,6653,8000]: """)
						if (str(port) == "back"):
							back2=1
							break
					if (str(port) == "back"):
						back2=1
						continue
					ip_input=str(ip_input)
					port=str(port)
					command="python3.6 portscanner/scan_port.py -t "+ ip_input +" -p "+port +" -a"
					print(command)
					os.system(command)
					#back=1

				elif (c_PS == 2):
					print("port_scan> Phantom Host Scan")
					iface = input("[?] Target Network Interface: ")
					if  (str(iface) == "back"):
						back2=1
						continue
					while(is_valid_iface(iface)==False):
						iface = input("[?] Target Network Interface: ")
						if  (str(iface) == "back"):
							back2=1
							break
					if  (str(iface) == "back"):
						back2=1
						continue
					ip = input("[?] Target IP Address: ")
					if (str(ip) == "back"):
						back2=1
						continue
					while(is_valid_ipv4_address_2(ip)==False):
						ip = input("[?] Target IP Address: ")
						if (str(ip) == "back"):
							back2=1
							break
					if (str(ip) == "back"):
						back2=1
						continue
					t_mac = input("[?] Target MAC Address: ")
					if (str(t_mac) == "back"):
						back2=1
						continue
					if (str(t_mac) == ""):
						t_mac = " "
					while(is_valid_macaddr802(t_mac)==False and t_mac != " "):
						t_mac = input("[?] Target MAC Address: ")
						if (str(t_mac) == ""):
							t_mac = " "
						if (str(t_mac) == "back"):
							back2=1
							break
					if (str(t_mac) == "back"):
						back2=1
						continue

					port = input("[?] Port Scan [22,23,80]: ")
					if (str(port) == "back"):
						back2=1
						continue
					if (str(port) == ""):
						port="22,23,80"
					while(is_valid_port(port)==False):
						port = input("[?] Port Scan [22,23,80]: ")
						if (str(port) == "back"):
							back2=1
							break
					if (str(port) == "back"):
						back2=1
						continue
					phantom_ip = input("[?] Phantom IP Address: ")
					if (str(phantom_ip) == "back"):
						back2=1
						continue
					while(is_valid_ipv4_address_2(phantom_ip)==False):
						phantom_ip = input("[?] Phantom IP Address: ")
						if (str(phantom_ip) == "back"):
							back2=1
							break
					if (str(phantom_ip) == "back"):
						back2=1
						continue
					phantom_mac = input("[?] Phantom Host MAC Address: ")
					phantom_mac = input("[?] Phantom Host MAC Address: ")
					if (str(phantom_mac) == "back"):
						back2=1
						continue
					if (str(phantom_mac) == ""):
						phantom_mac = " "
					while(is_valid_macaddr802(phantom_mac)==False and phantom_mac != " "):
						phantom_mac = input("[?] Phantom Host MAC Address: ")
						if (str(phantom_mac) == ""):
							phantom_mac = " "
						if (str(phantom_mac) == "back"):
							back2=1
							break
					if (str(phantom_mac) == "back"):
						back2=1
						continue
					iface=str(iface)
					ip=str(ip)
					t_mac=str(t_mac)
					port=str(port)
					phantom_ip=str(phantom_ip)
					phantom_mac=str(phantom_mac)
					if (t_mac==" ") and (phantom_mac==" "):
						command="python3.6 sdnpwn/phantom_host_scan.py --iface "+ iface+" --target-ip "+ip +" --ports "+port+" --phantom-ip "+phantom_ip
					if (t_mac!=" ") and (phantom_mac!=" "):
						command="python3.6 sdnpwn/phantom_host_scan.py --iface "+ iface+" --target-ip "+ip +" --ports "+port+" --phantom-ip "+phantom_ip+" --phantom-mac "+phantom_mac+" --target-mac "+t_mac
					if (t_mac == " " and phantom_mac !=" "):
						command="python3.6 sdnpwn/phantom_host_scan.py --iface "+ iface+" --target-ip "+ip +" --ports "+port+" --phantom-ip "+phantom_ip+" --phantom-mac "+phantom_mac
					if (phantom_mac == " " and t_mac != " "):
						command="python3.6 sdnpwn/phantom_host_scan.py --iface "+ iface+" --target-ip "+ip +" --ports "+port+" --phantom-ip "+phantom_ip+" --target-mac "+t_mac
					
					print(command)
					os.system(command)
					#back=1
					
		elif (c_1 == 5):
			back2 = 1
			while back2 == 1:
				back2=0
				c_RR = Choose_RR() 
				if (str(c_RR) == "back"): 
					back = 1
					continue
				elif (c_RR == 1):
					print("rule_recontruction> Use ICMP Protocol")
					ip = input("[?] Target IP Address: ")
					if (str(ip) == "back"):
						back2=1
						continue
					while(is_valid_ipv4_address_1(ip)==False):
						ip = input("[?] Target IP Address: ")
						if (str(ip) == "back"):
							back2=1
							break
					if (str(ip) == "back"):
						back2=1
						continue
					iface = input("[?] Target Network Interface: ")
					if  (str(iface) == "back"):
						back2=1
						continue
					while(is_valid_iface(iface)==False):
						iface = input("[?] Target Network Interface: ")
						if  (str(iface) == "back"):
							back2=1
							break
					if  (str(iface) == "back"):
						back2=1
						continue
					port = input("[?] Port For Recontruct Rule: ")
					if (str(port) == "back"):
						back2=1
						continue
					if (str(port) == ""):
						port="[]"
					while(is_valid_port(port)==False and port != "[]"):
						port = input("[?] Port For Recontruct Rule: ")
						if (str(port) == ""):
							port="[]"
						if (str(port) == "back"):
							back2=1
							break
					if (str(port) == "back"):
						back2=1
						continue
					ip=str(ip)
					iface=str(iface)
					port=str(port)
					if str(port) != "[]":
						port="["+str(port)+"]"
					command="python sdnmap/main.py "+ ip + " icmp "+ iface + " "  + port
					print(command)
					os.system(command)
					#back=1

				elif (c_RR == 2):
					print("rule_recontruction> Use ARP Protocol")
					ip = input("[?] Target IP Address: ")
					if (str(ip) == "back"):
						back2=1
						continue
					while(is_valid_ipv4_address_1(ip)==False):
						ip = input("[?] Target IP Address: ")
						if (str(ip) == "back"):
							back2=1
							break
					if (str(ip) == "back"):
						back2=1
						continue
					iface = input("[?] Target Network Interface: ")
					if  (str(iface) == "back"):
						back2=1
						continue
					while(is_valid_iface(iface)==False):
						iface = input("[?] Target Network Interface: ")
						if  (str(iface) == "back"):
							back2=1
							break
					if  (str(iface) == "back"):
						back2=1
						continue
					port = input("[?] Port Scan: ")
					if (str(port) == "back"):
						back2=1
						continue
					if (str(port) == ""):
						port="[]"
					while(is_valid_port(port)==False and port != "[]"):
						port = input("[?] Port Scan: ")
						if (str(port) == ""):
							port="[]"
						if (str(port) == "back"):
							back2=1
							break
					if (str(port) == "back"):
						back2=1
						continue
					ip=str(ip)
					iface=str(iface)
					port=str(port)
					if str(port) != "[]":
						port="["+str(port)+"]"
					command="python sdnmap/main.py "+ ip + " arp "+ iface + " "  + port
					print(command)
					os.system(command)
					#back=1

		elif (c_1 == 6):
			back2 = 1
			while back2 == 1:
				back2=0
				ip_network = input("[?] Target IP Network Address: ")
				if (str(ip_network) == "back"):
					back2=1
					continue
				while((is_valid_ipv4_address_1(ip_network)==False) and ("/" not in ip_network)):
					ip_network = input("[?] Target IP Address: ")
					if (str(ip_network) == "back"):
						back2=1
						break
				if (str(ip_network) == "back"):
					back2=1
					continue

				iface = input("[?] Target Network Interface: ")
				if  (str(iface) == "back"):
					back2=1
					continue
				while(is_valid_iface(iface)==False):
					iface = input("[?] Target Network Interface: ")
					if  (str(iface) == "back"):
						back2=1
						break
				if  (str(iface) == "back"):
					back2=1
					continue

				ip_network = str(ip_network)
				iface = str(iface)
				
				print("[*] Host Discovery")
				print("[**] ARP Scan")
				command1="python3.6 arpscan/arp_scan.py -t "+ip_network+" -i "+iface+ " -to 3 -e"
				os.system(command1)
				print("\n")
				print("[**] Ping Scan")
				command2="python3.6 pingscan/ping_scan.py -t "+ip_network+" -to 3 -e"
				os.system(command2)
				
				#Get IP from report_arp_scan.xlsx
				path = ("./report/host_discovery/report_arp_scan.xlsx")
				wb = xlrd.open_workbook(path)
				sheet = wb.sheet_by_index(0)
				ip_arp=[]
				mac_arp=[]
				for i in range(1,sheet.nrows):
					ip_arp.append(sheet.cell_value(i,1))
				for i in range(1,sheet.nrows):
					mac_arp.append(sheet.cell_value(i,2))

				#Get IP from report_arp_scan.xlsx
				path = ("./report/host_discovery/report_ping_scan.xlsx")
				wb = xlrd.open_workbook(path)
				sheet = wb.sheet_by_index(0)
				ip_ping=[]
				for i in range(1,sheet.nrows):
					ip_ping.append(sheet.cell_value(i,1))
				
				print("\n")
				print("[*] Port Scan")
				print("[**] Simple port scan")				
				#list IP to scan_port
				ip_arp_filter=[]
				ip_ping_filter=[]
				for i in ip_arp:
					if (i != " "):
						ip_arp_filter.append(i)
				for i in ip_ping:
					if (i != " "):
						ip_ping_filter.append(i)

				ip_to_scanport=[]
				if (len(ip_arp_filter) > 0) and (len(ip_ping_filter) > 0):
					ip_to_scanport = ip_arp_filter
					for i in ip_ping_filter:
						if i not in ip_to_scanport:
							ip_to_scanport.append(i)
				
				if (len(ip_arp_filter) > 0) and (len(ip_ping_filter) == 0):
					ip_to_scanport = ip_arp_filter

				if (len(ip_arp_filter) == 0) and (len(ip_ping_filter) > 0):
					ip_to_scanport = ip_ping_filter
				
				if (len(ip_to_scanport) > 0):
					ip_input_scanport = ip_to_scanport[0]
					for i in range(1,len(ip_to_scanport)):
						ip_input_scanport = ip_input_scanport + "," + ip_to_scanport[i]
								
				
	
				if (len(ip_arp_filter) == 0) and (len(ip_ping_filter) == 0):
					
					ip_input_scanport = input_timeout("""[?] Target IP Address For Simple Port Scan [One or More by ","]: """)
					if (str(ip_input_scanport) == "back"):
						back2=1
						continue
					check_ip=0
					if (str(ip_input_scanport) == ""):
						check_ip = 1
						ip_input_scanport = " "
					while (check_ip == 0):
						if back2==1:
							break
						ips=[]
						if ("," in str(ip_input_scanport)):
							ips=ip_input_scanport.split(",")
						else:
							ips.append(str(ip_input_scanport))
					
						for i in ips:
							if(is_valid_ipv4_address_2(i)==False):
								check_ip=0
								ip_input_scanport = input_timeout("""[?] Target IP Address For Simple Port Scan [One or More by ","]: """)
								if (str(ip_input_scanport) == ""):
									check_ip = 1
									ip_input_scanport = " "
								if  (str(ip_input_scanport) == "back"):
									back2=1
								break
							else:
								check_ip=1
					if  (str(ip_input_scanport) == "back"):
						back2=1
						continue
				if (ip_input_scanport != " "):
					port_scan = input_timeout("""[?] Port Scan [21,22,23,25,53,80,110,111,135,139,143,443,445,
                 993,995,1723,3306,3389,5900,8080,6633,6653,8000]: """)
					if (str(port_scan) == "back"):
						back2=1
						continue
					if (str(port_scan) == ""):
						port_scan="21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,6633,6653,8000"
					while(is_valid_port(port_scan)==False):
						port_scan = input_timeout("""[?] Port Scan [21,22,23,25,53,80,110,111,135,139,143,443,445,
                 993,995,1723,3306,3389,5900,8080,6633,6653,8000]: """)
						if (str(port_scan) == ""):
							port_scan="21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,6633,6653,8000"
						if (str(port_scan) == "back"):
							back2=1
							break
					if (str(port_scan) == "back"):
						back2=1
						continue
					
					port_scan = str(port_scan)
					print("\n")
					command3="python3.6 portscanner/scan_port.py -t "+ ip_input_scanport +" -p "+port_scan +" -a" + " -e"
					os.system(command3)
					print("\n")
					print("[**] Phantom host scan")
					port_phantom = input_timeout("[?] Port For Phantom Host Scan [21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,6633,6653,8000]: ")
					if (str(port_phantom) == "back"):
						back2=1
						continue
					if (str(port_phantom) == ""):
						port_phantom="21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,6633,6653,8000"
					while(is_valid_port(port_phantom)==False):
						port_phantom = input_timeout("[?] Port For Phantom Host Scan [21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,6633,6653,8000]: ")
						if (str(port_phantom) == ""):
							port_phantom="21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,6633,6653,8000"
						if (str(port_phantom) == "back"):
							back2=1
							break
					if (str(port_phantom) == "back"):
						back2=1
						continue
					print("\n")
					phantom_ip = input_timeout("[?] Phantom IP Address: ")
					if (str(phantom_ip) == "back"):
						back2=1
						continue
					if (str(phantom_ip) == ""):
						phantom_ip = " "
					while(is_valid_ipv4_address_2(phantom_ip)==False and phantom_ip != " "):
						print("\n")
						phantom_ip = input_timeout("[?] Phantom IP Address: ")
						if (str(phantom_ip) == ""):
							phantom_ip = " "
						if (str(phantom_ip) == "back"):
							back2=1
							break
					if (str(phantom_ip) == "back"):
						back2=1
						continue
					print("\n")
					phantom_mac = input_timeout("[?] Phantom Host MAC Address: ")
					if (str(phantom_mac) == "back"):
						back2=1
						continue
					if (str(phantom_mac) == ""):
						phantom_mac = " "
					while(is_valid_macaddr802(phantom_mac)==False and phantom_mac != " "):
						print("\n")
						phantom_mac = input_timeout("[?] Phantom Host MAC Address: ")
						if (str(phantom_mac) == ""):
							phantom_mac = " "
						if (str(phantom_mac) == "back"):
							back2=1
							break
					if (str(phantom_mac) == "back"):
						back2=1
						continue
					iface=str(iface)
					port_phantom=str(port_phantom)
					phantom_ip=str(phantom_ip)
					phantom_mac=str(phantom_mac)
					if (phantom_ip != " "):
					
						if (phantom_mac==" "):
							command31="python3.6 sdnpwn/phantom_host_scan.py --iface "+ iface+" --target-ip "+ip_input_scanport +" --ports "+port_phantom+" --phantom-ip "+phantom_ip + " --export"
						if (phantom_mac!=" "):
							command31="python3.6 sdnpwn/phantom_host_scan.py --iface "+ iface+" --target-ip "+ip_input_scanport +" --ports "+port_phantom+" --phantom-ip "+phantom_ip+" --phantom-mac "+phantom_mac+ " --export"
					
				
						os.system(command31)
					else:
						print("\n")
						print("[#] Ignored phantom host scan")
				else:
					print("\n")
					print("[#] Ignored simple host scan")
					print("[#] Ignored phantom host scan")







				
				#Get interfaces for multi_controller_detect
				list_ifaces = netifaces.interfaces()
				iface_multi_controller=list_ifaces[0]					
				for i in range(1,len(list_ifaces)):
					iface_multi_controller = iface_multi_controller + "," + list_ifaces[i]
				print("\n")
				print("[*] Controller Detect")
				print("[**] Multi controller detect")
				command4="python3.6 controllerdetect/multi_controller_detect.py -i "+ iface_multi_controller + " -e"
				os.system(command4)

				print("\n")
				print("[**] Controller detect base on LLDP traffic")
				command5="python3.6 controllerdetect/controller_detect.py -l -i "+ iface + " -e"
				os.system(command5)
				
				try:
					path = ("./report/controller_detect/report_multi_controller_detect.xlsx")
					wb = xlrd.open_workbook(path)
					sheet = wb.sheet_by_index(0)
					check_c = sheet.cell_value(1,0)
				except:
					check_c = "No controller detected"


				
				if check_c == "No controller detected":
					print("\n")
					print("[**] Controller detect base on Northbound interface")
					ip_controller_input = input_timeout("[?] Controller IP Address: ")
					if (str(ip_controller_input) == "back"):
						back2=1
						continue
					if (str(ip_controller_input) == ""):
						ip_controller_input = " "
						
					while(is_valid_ipv4_address_2(ip_controller_input)==False and ip_controller_input != " "):
						ip_controller_input = input_timeout("[?] Controller IP Address: ")
						if (str(ip_controller_input) == ""):
							ip_controller_input = " "
						if (str(ip_controller_input) == "back"):
							back2=1
							break
					if (str(ip_controller_input) == "back"):
						back2=1
						continue
				else:
					path = ("./report/controller_detect/report_multi_controller_detect.xlsx")
					wb = xlrd.open_workbook(path)
					sheet = wb.sheet_by_index(0)
					ip_controller_fromexcel = []
					for i in range(1,sheet.nrows):
    						ip_controller_fromexcel.append(sheet.cell_value(i, 0))
					ip_controller_input = ip_controller_fromexcel[0]
					if len(ip_controller_fromexcel) > 1:
						for i in range(1,len(ip_controller_fromexcel)):
							ip_controller_input = ip_controller_input + "," + ip_controller_fromexcel[i]
				ip_controller_input=str(ip_controller_input)

				if (str(ip_controller_input) != " "):
					print("\n")
					print("[**] Controller detect base on Northbound interface")
					port = input_timeout("[?] Port Scan [8080,9000,8181]: ")
					if (str(port) == "back"):
						back2=1
						continue
					if (str(port) == ""):
						port="8080,9000,8181"
					while(is_valid_port(port)==False):
						port = input_timeout("[?] Port Scan [8080,9000,8181]: ")
						if (str(port) == ""):
							port="8080,9000,8181"
						if (str(port) == "back"):
							back2=1
							break
					if (str(port) == "back"):
						back2=1
						continue
					
					command6="python3.6 controllerdetect/controller_detect.py -t "+ ip_controller_input+" -p "+port + " -v -e"
					os.system(command6)
				else:
					print("\n")
					print("[#] Ignored Controller detect base on Northbound interface")

				print("\n")
				print("[*] SDN rule recontruct")
				port_rule = input_timeout("[?] Port For Recontruct Rule: ")
				if (str(port_rule) == "back"):
					back2=1
					continue
				if (str(port_rule) == ""):
					port_rule="[]"
				while(is_valid_port(port_rule)==False and port_rule != "[]"):
					port_rule = input_timeout("[?] Port For Recontruct Rule: ")
					if (str(port_rule) == ""):
						port_rule="[]"
					if (str(port_rule) == "back"):
						back2=1
						break
				if (str(port_rule) == "back"):
					back2=1
					continue
				port_rule = str(port_rule)

				command7="python sdnmap/main.py "+ ip_network + " icmp "+ iface + " "  + port_rule + " -e" + " > ./sdnmap/temp_icmp.txt"
				os.system(command7)
				os.system("python3.6 export_sdnmap.py icmp")


				command8="python sdnmap/main.py "+ ip_network + " tcp "+ iface + " "  + port_rule + " -e" + " > ./sdnmap/temp_tcp.txt"
				os.system(command8)
				os.system("python3.6 export_sdnmap.py tcp")
				print("Finish!")				
					

def main():
	Session1()


if __name__ == '__main__':
        main()
