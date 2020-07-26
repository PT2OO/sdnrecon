from __future__ import division, print_function
import argparse
import errno
import signal
import json
import math
import random
import select
import os
import socket
import time
import sys
from xlsxwriter import Workbook

# some of these are tricky to configure
TCP_ASYNC_LIMIT = 256      # number of tcp ports to scan concurrently
TCP_CONNECT_POLLTIME = 12  # seconds poll waits for async tcp connects
UDP_ASYNC_LIMIT = 256      # max udp ports to scan concurrently
UDP_RETRIES = 8            # default number of udp retransmissions
UDP_WAIT = 1               # default wait seconds before retry + receive
UDP_ICMP_RATE_LIMIT = 1    # wait seconds after inferred icmp unreachable
# advanced udp scanning accuracy improves when you match server icmp rate limit
# because you will get less false positives ('maybe opens') from timeouts


class Probe():
    """
    simple probe state, one per ip:port per scan type
    """
    def __init__(self, ip, port, _type=socket.SOCK_STREAM):
        self.type = _type
        self.ip = ip
        self.port = port
        self.status = None
        self.socket = socket.socket(socket.AF_INET, _type)

    def handle_udp_econnrefused(self):
        # even numbered sends will fail with econnrefused
        # this is used to detect icmp unreachable errors
        self.status = False
        self.socket.close()
        verbose('udp port closed', self.port)

    def handle_udp_receive(self):
        self.status = True
        self.socket.close()
        verbose('udp port open', self.port)


def usage():
	print("Option    Description                                                Required")
	print("-------  ---------------------------------------------------------  ---------")
	print("-t", "       Target to scan                                             Yes")
	print("-v", "       Enable verbose output                                      No")
	print("-p", "       Port to scan                                               No") 
	print("-a", "       Use advanced udp scan to detect                            No")
	print("-e", "       Export result to file .txt                                 No")

def signal_handler(signal, frame):
  #Handle Ctrl+C here
  print("")
  print("Stopping...")
  exit(0)


def udp_scan(ip, ports):
    """
    only scan for obviously responsive udp ports
    returns: open_ports
    """
    open_ports = udp_scan_ex(ip, ports,
                             8,    # send packets at start
                             0,    # no retries, since we sent packets
                             8,    # wait seconds before trying to receive
                             0,    # override icmp rate limit wait
                             )[0]
    return open_ports


def udp_scan_ex(ip, ports, initial_sends=1, retries=UDP_RETRIES, wait=UDP_WAIT,
                icmp_rate_limit=UDP_ICMP_RATE_LIMIT):
    """
    scan for open+filtered udp ports
    returns: open_ports, maybe_open_ports
    """
    verbose('udp scanning %d ports' % (len(ports)))

    probes = []
    for port in ports:
        probe = Probe(ip, port, socket.SOCK_DGRAM)
        probes.append(probe)
        sock = probe.socket

        sock.setblocking(0)
        sock.connect((probe.ip, probe.port))  # allow icmp unreachable detect

        # initial_sends allows us to implement udp_scan as a simple wrapper
        # at the expense of slightly complicating udp_scan_ex
        # initial_sends = (initial_sends & ~1) + 1  # always odd
        for i in range(initial_sends):
            if probe.status is not None:
                continue
            try:
                sock.send(b'\x00')
            except socket.error as ex:
                if ex.errno == errno.ECONNREFUSED:
                    probe.handle_udp_econnrefused()
                    break
                else:
                    raise

    for i in range(retries+1):

        time.sleep(wait)

        for probe in probes:
            if probe.status is not None:
                continue
            sock = probe.socket
            try:
                sock.send(b'\x01')
            except socket.error as ex:
                # 2nd send icmp trick to detect closed ports
                # print ex, '* 2nd send', errno.errorcode[ex.errno]
                if ex.errno == errno.ECONNREFUSED:
                    probe.handle_udp_econnrefused()
                    # sleep to deal with icmp error rate limiting
                    time.sleep(icmp_rate_limit)
                    continue
                else:
                    raise

            try:
                sock.recvfrom(8192)
                probe.handle_udp_receive()
                continue
            except socket.error as ex:
                if ex.errno == errno.ECONNREFUSED:
                    verbose('udp recv failed',
                            errno.errorcode[ex.errno], ex, probe.port)
                    continue
                elif ex.errno != errno.EAGAIN:
                    verbose('udp recv failed',
                            errno.errorcode[ex.errno], ex, probe.port)
                    raise

    open_ports = []
    maybe_open_ports = []
    for probe in probes:
        if probe.status is False:
            continue
        elif probe.status:
            verbose('udp port open', probe.port)
            open_ports.append(probe.port)
        else:
            verbose('udp port maybe open', probe.port)
            maybe_open_ports.append(probe.port)
            probe.socket.close()

    return open_ports, maybe_open_ports


def tcp_scan(ip, ports):
    verbose('tcp scanning %d ports' % (len(ports)))

    open_ports = []
    probes = []
    fileno_map = {}  # {fileno:probe}

    poll = select.epoll(len(ports))
    for port in ports:
        probe = Probe(ip, port)
        sock = probe.socket
        fileno_map[sock.fileno()] = probe

        sock.setblocking(0)
        result = sock.connect_ex((probe.ip, probe.port))

        if result == 0:
            verbose('tcp port immediate connect', port)
            open_ports.append(port)
        elif result == errno.EINPROGRESS:
            # print('pending', probe.port, errno.errorcode[result])
            poll.register(probe.socket,
                          select.EPOLLOUT | select.EPOLLERR | select.EPOLLHUP)
            probes.append(probe)
        else:
            verbose('tcp connect fail', port, result, errno.errorcode[result])

    if len(probes) > 0:
        time.sleep(1)

        events = poll.poll(TCP_CONNECT_POLLTIME)

        for fd, flag in events:
            probe = fileno_map[fd]
            # print(probe.port, fd, flag)

            error = probe.socket.getsockopt(socket.SOL_SOCKET,
                                            socket.SO_ERROR)
            if error:
                verbose('tcp connection bad', probe.port, error)
            else:
                verbose('tcp connection good', probe.port)
                open_ports.append(probe.port)

    for probe in probes:
        probe.socket.close()

    poll.close()

    return open_ports


def segment(fn, ip, ports, async_limit):
    loops = int(math.ceil(len(ports)/async_limit))
    open_ports = []
    for i in range(loops):
        start = i*async_limit
        stop = (i+1)*async_limit
        result = fn(ip, ports[start:stop])
        if type(result) == tuple:
            open_ports.extend(result[0])
            open_ports.extend(result[1])
        else:
            open_ports.extend(result)
    return open_ports

def create_xlsx_file(file_path: str, headers: dict, items: list):
    with Workbook(file_path) as workbook:
        worksheet = workbook.add_worksheet()
        worksheet.write_row(row=0, col=0, data=headers.values())
        header_keys = list(headers.keys())
        for index, item in enumerate(items):
            row = map(lambda field_id: item.get(field_id, ''), header_keys)
            worksheet.write_row(row=index + 1, col=0, data=row)

def main(target, ports, advanced_udp=False):
    result = dict(target=target, status='')

    signal.signal(signal.SIGINT, signal_handler)
    valid_target = False
    try:
        # re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$',target)
        ip = socket.inet_ntoa(socket.inet_aton(target))
        result['status'] = 'valid ip'
        valid_target = True
    except socket.error:
        # "If it is not an IP, assume it is a FQDN"
        try:
            ip = socket.gethostbyname(target)
            result['status'] = 'fqdn resolves'
            valid_target = True
        except socket.gaierror:
            ip = target
            result['status'] = 'fqdn does not resolve'

    if valid_target:
        random.shuffle(ports)

        verbose('scanning', ip)

        verbose('starting tcp scan, total ports: %d' % (len(ports)))
        tcp_ports = segment(tcp_scan, ip, ports, TCP_ASYNC_LIMIT)
        result['tcp'] = sorted(tcp_ports)

        verbose('starting udp scan, total ports: %d' % (len(ports)))
        if advanced_udp:
            estimated = round(len(ports)/60)+1
            verbose('performing udp scan in advanced mode')
            verbose('rough estimated udp completion: %d minutes' % (estimated))
            udp_ports = segment(udp_scan_ex, ip, ports, UDP_ASYNC_LIMIT)
        else:
            udp_ports = segment(udp_scan, ip, ports, UDP_ASYNC_LIMIT)
        result['udp'] = sorted(udp_ports)

    verbose('--- output ---')
    print(json.dumps(result, sort_keys=True, indent=4, separators=(',', ': ')))
    return result

if __name__ == '__main__':
    
    if (len(sys.argv) < 1):
        usage()
        exit()
    else:
        params = sys.argv
        filter(None, params)
        params.pop(0)
        list_targets=[]
        export = False	
        if ("-t" in params):
            try:
                target = params[params.index("-t")+1]
            except:
                usage()
                exit()
        else:
            usage()
            exit()
        if ("," in target):
            list_targets=target.split(",")
        else:
            list_targets.append(target)
		
        if ("-v" in params):
            verbose = print
        else:
            verbose = lambda *args: None
        if ("-e" in params):
            export = True
        if ("-p" in params):
            try:
               option_port = (params[params.index("-p")+1]).lower()
            except:
               usage()
               exit()
            if (option_port.isdigit() == True):
                ports = []
                ports.append(int(option_port))
            elif ("-" in option_port):
                ports = []
                for i in range(1, 65536):
                    ports.append(int(i))
            elif ("," in option_port):
                ports = []
                for p in option_port.split(","):
                    ports.append(int(p))
		
        advanced_udp = False
        if ("-a" in params):
             advanced_udp = True

    headers = {'ip': 'IP', 'status': 'Status', 'tcp': 'Open TCP Port', 'udp': 'Open UDP Port'}
    items = []

    for t in list_targets:
        result=main(t, ports, advanced_udp)
        if (export == True):
            output = {'ip': 'a', 'status': 'a', 'tcp': 'a', 'udp': 'a'}
            if len(result['tcp']) != 0:
                tcp=str(result['tcp'][0])
                for i in range(1,len(result['tcp'])):
                    tcp= tcp + str(result['tcp'][i])
            else:
                tcp=""

            if len(result['udp']) != 0:
                udp=str(result['udp'][0])
                for i in range(1,len(result['udp'])):
                    udp= udp + str(result['udp'][i])
            else:
                udp=""
            output['ip']= str(result['target'])
            output['status']= str(result['status'])
            output['tcp']= tcp
            output['udp']= udp
            items.append(output)
    if (export == True):
        path = os.getcwd()[0:(int(os.getcwd().find("sdnrecon")))]
        filename= path+"sdnrecon/report/port_scan/report_simple_port_scan.xlsx"
        create_xlsx_file(filename, headers, items)
        print("[##] Result saved to " + "/sdnrecon/report/port_scan/report_simple_port_scan.xlsx")
        
    
    
        











