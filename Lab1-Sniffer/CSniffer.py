#-*- coding:utf-8 -*-
# import pcap, dpkt
# import time, math, os

# sniffer = pcap.pcap(name=None, promisc=True, immediate=True, timeout_ms=50)

# for timestamp, raw

#!/usr/bin/env python

import getopt
import sys

import dpkt, socket
import pcap, hexdump
import datetime
from collections import OrderedDict  # 不让字典自动排序
from dpkt.compat import compat_ord

Ether_protocol_type = {0x800: 'IP', 0x806: 'ARP'}
# Protocol (ip_p) - http://www.iana.org/assignments/protocol-numbers
IP_protocol = {1: 'ICMP', 2: 'IGMP', 6:'TCP', 17:'UDP'}

class CSniffer:
    def __init__(self):
        self.devices = pcap.findalldevs()
        self.devices = [item for item in self.devices if self.devices.count(item) == 1]
    
    def set_device(self, name, ts=50, ts_in_ns=False):
        self.pc = pcap.pcap(name, timeout_ms=ts, timestamp_in_ns=ts_in_ns)

    def mac_addr(self, address):  # 6位
        """Convert a MAC address to a readable/printable string

        Args:
            address (str): a MAC address in hex form (e.g. '\x01\x02\x03\x04\x05\x06')
        Returns:
            str: Printable/readable MAC address
        """
        return ':'.join('%02x' % compat_ord(b) for b in address)

    def inet_to_str(self, inet):
        """Convert inet object to a string

            Args:
                inet (inet struct): inet network address
            Returns:
                str: Printable/readable IP address
        """
        # First try ipv4 and then ipv6
        try:
            return socket.inet_ntop(socket.AF_INET, inet)
        except ValueError:
            return socket.inet_ntop(socket.AF_INET6, inet)

    def pcap_set(self, device_name, filter_rule):
        self.set_device(device_name)
        # # 构成过滤规则
        self.pc.setfilter(filter_rule)
        self.decode = {
            pcap.DLT_LOOP: dpkt.loopback.Loopback,
            pcap.DLT_NULL: dpkt.loopback.Loopback,
            pcap.DLT_EN10MB: dpkt.ethernet.Ethernet
        }[self.pc.datalink()]  # pc.datalink()  返回一个值表明链路层的头部

        print('listening on %s: %s' % (self.pc.name, self.pc.filter))

    def format_packet(self, timestamp, pkt):  #timestamp  packet 
        hex_rep = hexdump.hexdump(pkt, result='return')  # 二进制包的16进制和ascii表示
        ether_pkt = self.decode(pkt)
        Frames = OrderedDict()
        attach_info = ''
        # 以太II帧结构  ether_type > 1500
        #   |- - - - - - -｜ - ｜- - - - - -｜- - - - - -｜-     -｜- - - - - - - - -｜— - - -｜
        #   |premble 7    ｜sfd｜dst mac 6  ｜src mac 6  ｜len/typ｜Data&pad 46-1500 ｜FCS 4  ｜
        #   |- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -|
        #   |                  |                    物 理 层                                 ｜
        #   |                  |      报  头                      |  上层协议包       | FCS    |         
        #   46 = 64(min len) - (6+6+2+4) = 64 - 18 
        tmstmp               = str(datetime.datetime.utcfromtimestamp(timestamp))
        ether_dst_mac        = self.mac_addr(ether_pkt.dst)
        ether_src_mac        = self.mac_addr(ether_pkt.src)
        ether_type           = ether_pkt.type
        ether_protocol_frame = '' 
        ether_data_len       = '0'          
        if ether_pkt.data:
            ether_data_len = str(len(ether_pkt.data))  
        if ether_type in Ether_protocol_type:
            ether_protocol_frame = Ether_protocol_type[ether_type]
        Frames['以太网II型帧'] = ['时间戳: '+tmstmp, '目标Mac地址: '+ether_dst_mac, ' 源Mac地址: '+ether_src_mac, \
            '数据字段长度: '+ether_data_len, '帧内协议类型: '+ether_protocol_frame]
        
        if ether_type == 0x800:  # IP协议
            ip = ether_pkt.data
            
            # IP帧结构
            #  0|- - - - - - - - - - - - - - - - |- - - - - - - - - - - - - - - - |31
            #   |version|  IHL  |      TOS       |       Total  length            |
            #   |       Identification           |R D M|  Fragment offset         |
            #   |    TTL        |   Protocol     |      Header  checksum          |
            #   |                   Source            Address                     |
            #   |                   Dst               Address                     |
            #   |                          Options                                |
            #   |                              Data                               |
            #   |                             ......                              |
            #   |- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -|               
            # version, IHL, Total Len, Identi, DF, MF, TTL, Protocol, src_ip, dst_ip
            version      = str(ip._v_hl >> 4)  # ip._v_hl  4(version) + 4(IHL) 共8位
            ihl          = str(ip._v_hl & 0xf)
            total_len    = str(ip.len)
            iden         = str(ip.id)
            rf           = str((ip.off >> 15) & 0x1)  # ip.off - R D M + Fragment offset
            df           = str((ip.off >> 14) & 0x1)
            mf           = str((ip.off >> 13) & 0x1)
            offset       = str((ip.off & 0x1fff) << 3)
            ttl          = str(ip.ttl)
            protocol     = ''
            if ip.p in IP_protocol:
                protocol = IP_protocol[ip.p]
            src_ip       = self.inet_to_str(ip.src)
            dst_ip       = self.inet_to_str(ip.dst)

            Frames['IP帧'] = ['IP版本: '+version, '报头长度: '+ihl, '封包总长: '+total_len, '识别码: '+iden, \
                            '保留分段: '+rf, '不分段: '+df, '更多数据段: '+mf,'分割定位: '+offset, \
                            '延续时间: '+ttl, 'IP封包协议: '+protocol, '源IP: '+src_ip, '目的IP: '+dst_ip]
            
            if isinstance(ip.data, dpkt.tcp.TCP):
                tcp = ip.data
                # TCP帧结构
                # 0|- - - - - - - - - - - - - - - -|- - - - - - - - - - - - - - - -|31 
                #  |        src port               |          dst port             |
                #  |                          顺序号 seq                            |
                #  |                          确认号 ack                            |
                #  |  报头  |- - - - - -|u|a|p|r|s|f|   窗口大小  win size           |
                #  |  校验和 checksum               ｜   紧急指针 urgent pointer      |
                #  |                 选项+填充  0 / 多个32位字                        |
                #  |                       数据 0/多个字节                           |
                #  |- - - - - - - - - - - - - - - -|- - - - - - - - - - - - - - - -|    
                src_port = str(tcp.sport)
                dst_port = str(tcp.dport)
                seq_num  = str(tcp.seq)
                ack_num  = str(tcp.ack)
                urg      = str(int(bool(tcp.flags & 0x20)))
                ack      = str(int(bool(tcp.flags & 0x10)))
                psh      = str(int(bool(tcp.flags & 0x8)))
                rst      = str(int(bool(tcp.flags & 0x4)))
                syn      = str(int(bool(tcp.flags & 0x2)))
                fin      = str(int(bool(tcp.flags & 0x1)))
                win_size = str(tcp.win)

                Frames['TCP帧'] = ['源端口: '+src_port, '目的端口: '+dst_port, '序列号: '+seq_num, '确认号: '+ack_num, \
                                 'URG: '+urg, 'ACK: '+ack, 'PSH: '+psh, 'RST: '+rst, 'SYN: '+syn, 'FIN: '+fin, '窗口大小: '+win_size]
                attach_info = " ".join(Frames['TCP帧'])                 
                # Now see if we can parse the contents as a HTTP request
                if dst_port == str(80):
                    R = False
                    # HTTP报文格式
                    # 请求报文
                    # ｜ 请求方法 ｜空格｜ url ｜空格｜协议版本|回车符｜换行符｜  -- 请求行
                    # ｜头部字段名｜:|     值     |回车符｜换行符｜   -|
                    # ｜...           ...            .....   |   -|--> 请求头部
                    # ｜回车符｜换行符｜
                    # ｜  #################################  |  -- 请求正文
                    try:
                        request         = dpkt.http.Request(tcp.data)
                        request_list = []
                        method          = request.method
                        uri             = request.uri
                        ver             = str(request.version)
                        request_list = ['method: '+method, 'uri: '+uri, 'version: '+ver]
                        for i in request.headers:
                            request_list.append(i + ": " + request.headers[i])
                        # host            = request.headers['host']
                        # user_agent      = request.headers['user-agent']
                        # connection      = request.headers['connection']
                        # accept_charset  = request.headers['connection']
                        # accept_encoding = request.headers['accept-encoding']
                        # accept_language = request.headers['accept-language']
                        body            = request.body.decode("utf8", "ignore")
                        data            = request.data.decode("utf8", "ignore")
                        request_list.append("body: "+ body)
                        request_list.append("data: "+ data)

                        # Frames['HTTP请求报文'] = ['请求方法: '+method, '统一资源标识: '+uri, 'HTTP版本: '+ver, '请求服务器地址: '+host, '发送请求程序: '+user_agent,\
                        #                         '连接相关属性: '+connection, '可接受编码格式: '+accept_charset, '可接受数据压缩格式: '+accept_encoding, \
                        #                         '可接受语言: '+accept_language, '请求正文: '+body, '数据: '+data]
                        Frames['HTTP请求报文'] = request_list
                        protocol = 'HTTP'
                        R = True
                    except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                        pass
                    if not R:
                        # 响应报文
                        # ｜ 协议版本 ｜空格｜状态码｜空格｜状态码描述｜回车符｜换行符｜  -- 状态行
                        # ｜ 头部字段名 ｜:｜ 值     ｜回车符｜换行符｜  -｜
                        # ｜                   ...              |  -｜-->  响应头部
                        # ｜                   ...              |  -｜
                        # ｜回车符｜换行符｜
                        # ｜  ################################  ｜  -｜响应正文
                        try:
                            response        = dpkt.http.Response(tcp.data)
                            pro_ver         = str(response.version)
                            status_code     = str(response.status)
                            status_code_des = response.reason
                            response_list = ['protocol version: '+pro_ver, 'status code: '+status_code, 'response: '+response]
                            # server          = response.headers['server']
                            # content_type    = response.headers['content-type']
                            # content_len     = response.headers['content-length']
                            # content_charset = response.headers['content-charset']
                            # content_encode  = response.headers['content-encoding']
                            # content_lang    = response.headers['content-language']
                            for i in response.headers:
                                response_list.append(i + ': ' +response.headers[i])
                            body            = response.body
                            data            = response.data
                            response_list.append('body: '+body)
                            response_list.append('data: '+data)

                            # Frames['HTTP响应包'] = ['HTTP版本: '+pro_ver, '状态码: '+status_code, '状态码描述: '+status_code_des,  '服务器软件名称及版本: '+server,\
                            #                       '响应正文类型: '+content_type, '响应正文编码: '+content_len, '响应正文压缩格式: '+content_charset, '响应正文语言: '+content_lang,\
                            #                       '响应正文: '+body, '数据: '+data]
                            Frames['HTTP响应包'] = response_list
                            protocol = 'HTTP'
                        except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                            pass             
            elif isinstance(ip.data, dpkt.icmp.ICMP):
                icmp = ip.data
                # ICMP帧格式
                # 1|--------|--------|----------------|31
                #  | type   |  code  |   checksum     |
                #  |          header other part       |
                #  |              data                |
                #  |----------------------------------|   
                _type    = str(icmp.type)  
                code     = str(icmp.code)
                checksum = str(icmp.sum)
                data     = repr(icmp.data)
                Frames['ICMP帧'] = ['类型: '+_type, '代码: '+code, '校验和: '+checksum, '数据: '+data]
                attach_info = " ".join(Frames['ICMP帧'][0:3])
                
            elif isinstance(ip.data, dpkt.igmp.IGMP):
                igmp = ip.data
                # IGMP格式  有v1、v2、v3 三个不同的版本
                # IGMPv1
                # 1|--------|--------|----------------|31
                #  | vesion | type   |  checksum      |
                #  |           group  address         |
                #  |----------------------------------| 
                # IGMPv2
                # 1|--------|--------|----------------|31
                #  | type   |maxresp |  checksum      |
                #  |           group  address         |
                #  |----------------------------------|     
                # IGMPv3
                # 1|--------|--------|----------------|31
                #  |typ=0x11| maxresp|  checksum      |
                #  |           group  address         |
                #  |       other ...                  |
                #  |----------------------------------|    
                _type      = igmp.type
                max_resp   = str(igmp.maxresp)
                checksum   = str(igmp.sum)
                group_addr = self.inet_to_str(igmp.group)

                if igmp.type == 0x1:
                    Frames['IGMPv1帧'] = ['版本号: '+str(_type), '类型: '+max_resp, '校验和: '+checksum, '组播地址: '+group_addr]
                    attach_info = " ".join(Frames['IGMPv1帧'])
                elif len(igmp) > 64:
                    Frames['IGMPv3帧'] = ['报文类型: '+str(_type), '最大响应延迟时间: '+max_resp, '校验和: '+checksum, '组播地址: '+group_addr]
                    attach_info = " ".join(Frames['IGMPv3帧'])
                else:
                    Frames['IGMPv2帧'] = ['报文类型: '+str(_type), '最大响应延迟时间: '+max_resp, '校验和: '+checksum, '组播地址: '+group_addr]
                    attach_info = " ".join(Frames['IGMPv2帧'])
                    
            elif isinstance(ip.data, dpkt.udp.UDP):
                udp = ip.data
                # UDP帧结构
                # 0|----------------|----------------|
                #  | src port       |   dst  port    |
                #  |  udp len       |   udp checksum |
                #  |    data (if exist)              |
                #  |----------------|----------------|
                src_port = str(udp.sport)
                dst_port = str(udp.dport)
                udp_len  = '0'
                udp_data = ''
                if udp.data:
                    udp_len = str(len(udp.data))
                    try:
                        udp_data = udp.data.decode('utf8')
                    except Exception as e:
                        udp_data = repr(udp.data)
                Frames['UDP帧'] = ['源端口: '+src_port, '目的端口: '+dst_port, 'UDP长度: '+udp_len, '数据: '+udp_data]
                attach_info = " ".join(Frames['UDP帧'][0:3])
            else:
                pass
        elif eth_type == 0x806:  # ARP协议
            arp = ether_pkt.data
            protocol = 'ARP'
            # ARP帧
            # 1｜- - - - - -|- - - - - -|- -|- -|- -| - | - |- -|- - - - - -|- - - -|- - - - - -|- - - -|
            # 1｜ether_dhost|ether_shost|typ|hrd|pro|hln|pln|op | send_mac  |sendip | dst_mac   | dstip |
            #  |----------------------------------------------------------------------------------------|
            if arp.hrd == 0x1:
                hard_type = '以太网地址'
            else:
                hard_type = str(arp.hrd)
            if arp.pro == 0x0800:
                pro_type = 'IP地址'
            else: 
                pro_type = str(arp.pro)
            hard_len  = str(arp.hln)
            pro_len   = str(arp.pln)
            if op == 0x1:
                op = '1 - ARP请求'
            else:
                op = '2 - ARP应答'
            send_mac = self.mac_addr(arp.sha)
            src_ip  = self.inet_to_str(arp.spa)
            dst_mac  = self.mac_addr(arp.tha)
            dst_ip   = self.inet_to_str(arp.tpa)
            Frames['ARP帧'] = ['硬件类型: '+hard_type, '协议类型: '+pro_type, '硬件地址长度: '+hard_len, '协议地址长度: '+pro_len, \
                              '操作类型: '+op, '发送者硬件地址: '+send_mac, '发送者IP地址: '+src_ip, '目标硬件地址: '+dst_mac, '目标IP地址: '+dst_ip]
            attach_info = " ".join(Frames['ARP帧'])
            
        else:
            pass
              
        return [tmstmp, src_ip, dst_ip, protocol, attach_info, hex_rep, Frames]#data_format]



# def iter(pc, decode_fn):
#     for timestamp, pkt in pc:  
#         # print(format_packet(ts, pkt, decode_fn))
#         format_packet(timestamp, pkt, decode_fn)

# def loop(pc, decode_fn):  # pc - handle  decode_fn - 解析包的规则
#     def cb(timestamp, pkt, *args):
#         format_packet(timestamp, pkt, decode_fn)
#         # print(format_packet(ts, pkt, decode_fn))
#     pc.loop(0, cb)  # 接收到指定数量的包，调用回调函数

# def usage():
#     sys.stderr.write('Usage: %s [-i device] [-l] [-n] [pattern]' % sys.argv[0])
#     sys.stderr.write("""
# Options:
# \t-i device - Use the specific device.
# \t-l - Use pcap.loop() method.
# \t-n - Report timestamps in nanoseconds.
# Available devices:""")
#     sys.stderr.write('\t' + '\n\t'.join(pcap.findalldevs()))
#     sys.exit(1)

# def main():

#     # 得到设置参数  接收的是一个元组 [('-i', 'xx')]  i: 说明i是有值的
#     opts, args = getopt.getopt(sys.argv[1:], 'i:hln')
#     name = None  
#     use_loop = False
#     timestamp_in_ns = False
#     for o, a in opts:  # ('-i', 'xx')
#         if o == '-i':
#             name = a
#         elif o == '-l':
#             use_loop = True
#         elif o == '-n':
#             timestamp_in_ns = True
#         else:
#             usage()

#     # pcap handle
#     pc = pcap.pcap(name, timeout_ms=50, timestamp_in_ns=timestamp_in_ns)
#     # 构成过滤规则
#     pc.setfilter(' '.join(args))

#     decode = {
#         pcap.DLT_LOOP: dpkt.loopback.Loopback,
#         pcap.DLT_NULL: dpkt.loopback.Loopback,
#         pcap.DLT_EN10MB: dpkt.ethernet.Ethernet
#     }[pc.datalink()]  # pc.datalink()  返回一个值表明链路层的头部

#     print('listening on %s: %s' % (pc.name, pc.filter))  # 网卡名称  过滤规则
#     # 这里怎么实现多线程？
#     try:
#         if use_loop:
#             loop(pc, decode)
#         else:
#             iter(pc, decode)
#     except KeyboardInterrupt:
#         nrecv, ndrop, nifdrop = pc.stats()  #返回三元组 接收到的数量、丢弃的数量、因过滤规则丢弃的数量
#         print('\n%d packets received by filter' % nrecv)
#         print('%d packets dropped by kernel' % ndrop)

# if __name__ == '__main__':
#     main()