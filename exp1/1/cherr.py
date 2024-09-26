import pcap
import dpkt
import time
import chardet
from scapy.all import *


global IP, PORT
IP = '4.215.232.129'
PORT = 80

def capture(iface):
    # 打开网络接口进行数据包捕获
    pkt = pcap.pcap(name=iface, promisc=True, immediate=True, timeout_ms=50)
    filters = 'tcp port 80'
    pkt.setfilter(filters)


    # 使用pypcap捕获数据包
    for ts, data in pkt:
        # 解析数据包
        eth = dpkt.ethernet.Ethernet(data)
        # 判断是否为IP数据包
        if not isinstance(eth.data, dpkt.ip.IP):
            continue
        ip = eth.data
        # 判断是否为TCP数据包
        if not isinstance(ip.data, dpkt.tcp.TCP):
            continue
        tcp = ip.data
        if len(tcp.data) == 0:
            continue
        # 判断是否为指定IP地址的数据包
        ip_dst = '.'.join([str(x) for x in list(ip.dst)])
        ip_src = '.'.join([str(x) for x in list(ip.src)])
        if ip_dst != IP and ip_src != IP:
            continue
        # 判断是否为HTTP请求数据包
        if tcp.dport != PORT and tcp.sport != PORT:
            continue
        
        # 打印分隔符
        print("=" * 50)
        # 判断是否是request数据包   
        if tcp.dport == 80:
            try:
                # 解析HTTP请求数据包
                request = dpkt.http.Request(tcp.data)
                # 获取请求的URL
                url = request.uri
                # 获取请求的方法
                method = request.method
                # 获取请求的版本
                version = request.version
                # 获取请求的头部
                headers = request.headers
                # 获取请求的时间戳
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
                # 获取请求的源IP地址
                src_ip = socket.inet_ntoa(ip.src)
                # 获取请求的目的IP地址
                dst_ip = socket.inet_ntoa(ip.dst)
                # 获取请求的源端口
                src_port = tcp.sport
                # 获取请求的目的端口
                dst_port = tcp.dport
                # 获取请求的数据包长度
                length = len(data)
                # 获取请求的数据包编码
                encoding = chardet.detect(request.body)['encoding']
                content=''
                try:
                    content = request.body.decode(encoding)
                except:
                    content = request.body.decode('utf-8')
                # 打印请求的信息
                print("URL: ", url)
                print("Method: ", method)
                print("Version: ", version)
                print("Headers: ", headers)
                print("Timestamp: ", timestamp)
                print("Source IP: ", src_ip)
                print("Destination IP: ", dst_ip)
                print("Source Port: ", src_port)
                print("Destination Port: ", dst_port)
                print("Length: ", length)
                print("Content: ", content)
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(e)
                continue
        # 如果是 response 数据包
        if tcp.sport == 80:
            try:
                # 解析HTTP响应数据包
                response = dpkt.http.Response(tcp.data)
                # 获取响应的状态码
                status = response.status
                # 获取响应的版本
                version = response.version
                # 获取响应的头部
                headers = response.headers
                # 获取响应的时间戳
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
                # 获取响应的源IP地址
                src_ip = socket.inet_ntoa(ip.src)
                # 获取响应的目的IP地址
                dst_ip = socket.inet_ntoa(ip.dst)
                # 获取响应的源端口
                src_port = tcp.sport
                # 获取响应的目的端口
                dst_port = tcp.dport
                # 获取响应的数据包长度
                length = len(data)
                # 获取响应的数据包编码
                encoding = chardet.detect(response.body)['encoding']
                content = response.body.decode(encoding)
                # 打印响应的信息
                print("Status: ", status)
                print("Version: ", version)
                print("Headers: ", headers)
                print("Timestamp: ", timestamp)
                print("Source IP: ", src_ip)
                print("Destination IP: ", dst_ip)
                print("Source Port: ", src_port)
                print("Destination Port: ", dst_port)
                print("Length: ", length)
                print("Encoding: ", encoding)
                print("Content: ", content)
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(e)
                continue
            

def main():
    # 输一个默认的
    iface = "eth0"
    
    capture(iface)

if __name__ == "__main__":
    main()
