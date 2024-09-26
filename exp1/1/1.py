#import pcap
import dpkt
import time
import os
import chardet
from scapy.all import *


def detect_encoding(data):
    result = chardet.detect(data)
    encoding = result['encoding']
    return encoding

def decode_data(data):
    encoding = detect_encoding(data)
    try:
        return data.decode(encoding, errors='ignore')
    except:
        return data.decode('utf-8', errors='ignore')  # 默认 utf-8 解码

def capture_callback(ts, pkt_data):
    eth = dpkt.ethernet.Ethernet(pkt_data)
    # 判断是否为IP数据报
    if not isinstance(eth.data, dpkt.ip.IP):
        return

    ip = eth.data

    # 判断是否为TCP数据报
    if not isinstance(ip.data, dpkt.tcp.TCP):
        return

    ip_dst = '.'.join([str(x) for x in list(ip.dst)])
    ip_src = '.'.join([str(x) for x in list(ip.src)])
    if ip_dst != IP and ip_src != IP:
        return

    tcp = ip.data
    # 获取端口号
    if tcp.sport != PORT and tcp.dport != PORT:
        return

    # 判断为HTTP请求还是响应并解析包内容
    try:
        http = dpkt.http.Request(tcp.data)
        print("HTTP Request")
        print(f"Method: {http.method}")
        print(f"IP: {ip_dst}:{tcp.dport}")
        print(f"Host: {http.headers['host']}")
        print(f"URL: {http.uri}")
        print(f"Body: {decode_data(http.body)}")
        print()

    except Exception as e:
        try:
            http = dpkt.http.Response(tcp.data)
            print("HTTP Response")
            print(f"From: {ip_src}:{tcp.sport}")
            print(f"Data: {decode_data(http.body)}")
            print()
        except:
            return

def captureData(iface):
    # 打开网络接口进行数据包捕获
    pkt = pcap.pcap(name=iface, promisc=True, immediate=True, timeout_ms=50)
    filters = 'tcp port 80'
    pkt.setfilter(filters)

    pcap_filepath = 'pkts/pkts_{}.pcap'.format(time.strftime("%Y%m%d-%H%M%S", time.localtime()))
    os.makedirs('pkts', exist_ok=True)

    print('Start capturing on', iface)
    
    with open(pcap_filepath, 'wb') as pcap_file:
        writer = dpkt.pcap.Writer(pcap_file)

        try:
            pkt.loop(5, lambda ts, data: (writer.writepkt(data, ts), capture_callback(ts, data)))
        except KeyboardInterrupt:
            print('Capture stopped by user.')

def main():
    # 输一个默认的
    iface = "eno1"
    global IP, PORT
    # 默认是教务处的
    IP = '10.160.2.157'
    PORT = 80
    captureData(iface)

if __name__ == "__main__":
    main()
