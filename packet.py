import json
from typing import Dict
import re
import time
# from html import create_table_page
import sys
from config import *
from mitm import Flow

"""
This class define packets.
It reads wireshark logs from wireshark.json file and create tcp and udp packet list. 
"""
# Packet Class
class Packet:
    def __init__(self,
                 frame_interface_id=None,
                 frame_time=None,
                 time_epoch=None,
                 frame_time_relative=None,
                 frame_number=None,
                 frame_len=None,
                 frame_protocols=None,
                 ip_version=None,
                 ip_hdr_len=None,
                 ip_len=None,
                 ip_ttl=None,
                 proto=None,
                 ip_src=None,
                 ip_dst=None,
                 src_port=None,
                 dst_port=None,
                 udp_checksum_status=None,
                 udp_length=None,
                 stream_number=None,
                 dns_qry_name=None,
                 http_host=None,
                 tcp_ack=None,
                 data_len=None,
                 tcp_hdr_len=None,
                 tcp_window_size=None,
                 tcp_analysis_out_of_order=None,
                 tcp_connection_fin=None,
                 tcp_connection_syn=None,
                 tcp_flags=None,
                 tcp_seq=None,
                 dns_id=None,
                 dns_resp_name=None,
                 dns_a=None,
                 dns_aaaa=None,
                 dns_resp_ttl=None,
                 dns_response_to=None,
                 dns_time=None,
                 http_prev_request_in=None,
                 http_request_version=None,
                 http_request=None,
                 http_request_number=None,
                 host=None,
                 flow_number=None,
                 is_dns=None,
                 packet_type=None,
                 init_connection=None,
                 color=None,
                 tag = None,
                 html_info=""
                 ):
        self.frame_interface_id = frame_interface_id
        self.packet_type = packet_type
        self.frame_time = frame_time
        self.time_epoch = time_epoch
        self.frame_time_relative = frame_time_relative,
        self.frame_number = frame_number
        self.frame_len = frame_len
        self.frame_protocols = frame_protocols

        self.ip_version = ip_version
        self.ip_hdr_len = ip_hdr_len
        self.ip_len = ip_len
        self.ip_ttl = ip_ttl
        self.proto = proto
        self.ip_src = ip_src
        self.ip_dst = ip_dst
        self.src_port = src_port
        self.dst_port = dst_port

        self.udp_checksum_status = udp_checksum_status
        self.udp_length = udp_length
        self.stream_number = stream_number
        self.dns_qry_name = dns_qry_name

        self.tcp_ack = tcp_ack
        self.data_len = data_len
        self.tcp_hdr_len = tcp_hdr_len
        self.tcp_window_size = tcp_window_size
        self.tcp_analysis_out_of_order = tcp_analysis_out_of_order
        self.tcp_connection_fin = tcp_connection_fin,
        self.tcp_connection_syn = tcp_connection_syn,
        self.tcp_flags = tcp_flags,
        self.tcp_seq = tcp_seq,

        self.dns_id = dns_id
        self.dns_qry_name = dns_qry_name
        self.dns_resp_name = dns_resp_name
        self.dns_a = dns_a
        self.dns_response_to = dns_response_to
        self.dns_time = dns_time
        self.is_dns = is_dns
        self.dns_aaaa = dns_aaaa,
        self.dns_resp_ttl = dns_resp_ttl,

        self.http_prev_request_in = http_prev_request_in
        self.http_request_version = http_request_version
        self.http_host = http_host
        self.http_request = http_request
        self.http_request_number = http_request_number

        self.host = host
        self.type = type
        self.flow_number = flow_number
        self.init_connection = init_connection
        self.color = color
        self.tag = tag
        self.html_info = html_info

# Stream Class
class Stream:
    def __init__(self,
                 stream_type=None,
                 stream_number=None,
                 number_of_packets=None,
                 start_time=None,
                 packet_list=None,
                 host=None,
                 http_host=None,
                 ip_src=None,
                 ip_dst=None,
                 src_port=None,
                 dst_port=None,
                 is_dns=None,
                 initiated_connection_time=None,
                 html_info=None
                 ):
        if packet_list is None:
            packet_list = []
        self.stream_type = stream_type
        self.stream_number = stream_number
        self.number_of_packets = number_of_packets
        self.start_time = start_time
        self.packet_list = packet_list
        self.ip_src = ip_src
        self.ip_dst = ip_dst
        self.src_port = src_port
        self.dst_port = dst_port
        self.host = host
        self.http_host = http_host
        self.is_dns = is_dns
        self.initiated_connection_time = initiated_connection_time
        self.html_info = html_info

''' Read Wireshark or Tshark file
Todo
- 
'''
# Read wireshark file and create the packet list
def create_packet_list(file_name:str):
    # extract packets from wireshark or tshark
    if file_name.__contains__("wireshark"):
        lst_packets = create_packet_list_wireshark(file_name)
        return lst_packets

    # extract packets if captured file is exported from tshark
    if file_name.__contains__("tshark"):
        lst_packets = create_packet_list_tshark(file_name)
        return lst_packets

def create_packet_list_wireshark(file_name:str):
    print("Extracting packets from wireshark file: %s"%(str(file_name)))
    # Check existence of the File
    is_file_exist(file_name)

    # load the content of the json file
    try:
        with open(file_name) as wireshark_file:
            wireshark_info = json.load(wireshark_file)
            wireshark_file.close()
    except ValueError as e:
        print(e)
        print("Error: %s is not in the appropriate JSON format.\n\n")%(file_name)
        exit(0)

    # Parse the Wireshark JSON File to extract packets
    print("\nReading wireshark.json ...")

    lst_packets: Dict[str, Packet] = {}
    for i in wireshark_info:
        p = Packet()
        for j in i:
            if str(j) == "_source":
                for k in i[j]:  # Layers
                    if k=="layers":
                        for l in i[j][k]:
                            if l=="frame":
                                for m in i[j][k][l]:
                                    temp = i[j][k][l][m]
                                    if str(m) == "frame.interface_id":
                                        p.frame_interface_id = temp
                                        continue
                                    if str(m) == "frame.time":
                                        p.frame_time = temp
                                        continue
                                    if str(m) == ("frame.time_epoch"):
                                        p.time_epoch = temp
                                        continue
                                    if str(m) == ("frame.time_relative"):
                                        p.frame_time_relative = temp
                                        continue
                                    if str(m) == ("frame.number"):
                                        p.frame_number = temp
                                        continue
                                    if str(m) == ("frame.len"):
                                        p.frame_len = temp
                                        continue
                                    if str(m) == ("frame.protocols"):
                                        if temp == "eth:ethertype:arp":
                                            p.packet_type = "ARP"
                                        p.frame_protocols = temp
                                        continue

                            if l=="eth":
                                continue

                            if l=="ip":
                                for m in i[j][k][l]:
                                    temp = i[j][k][l][m]
                                    if str(m) == ("ip.version"):
                                        p.ip_version = temp
                                        continue
                                    if str(m) == ("ip.hdr_len"):
                                        p.ip_hdr_len = temp
                                        continue
                                    if str(m) == ("ip.len"):
                                        p.ip_len = temp
                                        continue
                                    if str(m) == ("ip.ttl"):
                                        p.ip_ttl = temp
                                        continue
                                    if str(m) == ("ip.proto"):
                                        p.proto = temp
                                        continue
                                    if str(m) == ("ip.src"):
                                        p.ip_src = temp
                                        continue
                                    if str(m) == ("ip.dst"):
                                        p.ip_dst = temp
                                        continue

                            if l=="udp":
                                for m in i[j][k][l]:
                                    temp = i[j][k][l][m]
                                    if str(m) == ("udp.srcport"):
                                        p.src_port = temp
                                        continue
                                    if str(m) == ("udp.dstport"):
                                        p.dst_port = temp
                                        continue
                                    if str(m) == ("udp.length"):
                                        p.udp_length = temp
                                        continue
                                    if str(m) == ("udp.stream"):
                                        p.stream_number = temp
                                        p.packet_type = "UDP"
                                        continue
                                    if str(m) == ("udp.checksum.status"):
                                        p.udp_checksum_status = temp
                                        continue

                            if l=="tcp":
                                for m in i[j][k][l]:
                                    temp = i[j][k][l][m]
                                    if str(m) == ("tcp.srcport"):
                                        p.src_port = temp
                                        continue
                                    if str(m) == ("tcp.dstport"):
                                        p.dst_port = temp
                                        continue
                                    if str(m) == ("tcp.stream"):
                                        p.stream_number = temp
                                        p.packet_type = "TCP"
                                        continue
                                    if str(m) == ("tcp.ack"):
                                        p.tcp_ack = temp
                                        continue
                                    if str(m) == ("tcp.hdr_len"):
                                        p.tcp_hdr_len = temp
                                        continue
                                    if str(m) == ("tcp.window_size"):
                                        p.tcp_window_size = temp
                                        continue
                                    if str(m) == ("tcp.flags"):
                                        p.tcp_flags = temp
                                        continue
                                    if str(m) == ("tcp.seq"):
                                        p.tcp_seq = temp
                                        continue

                            if l=="data":
                                for m in i[j][k][l]:
                                    temp = i[j][k][l][m]
                                    if str(m) == ("data.len"):
                                        p.data_len = temp
                                        continue

                            if l=="dns":
                                p.packet_type="DNS"
                                for m in i[j][k][l]:
                                    temp = i[j][k][l][m]
                                    if str(m) == ("dns.id"):
                                        p   .dns_id = temp
                                        p.is_dns = True
                                        continue
                                    if str(m) == ("dns.qry.name"):
                                        p.dns_qry_name = temp
                                        continue
                                    if str(m) == ("dns.resp.name"):
                                        p.dns_resp_name = temp
                                        continue
                                    if str(m) == ("dns.a"):
                                        p.dns_a = temp
                                        continue
                                    if str(m) == ("dns.aaaa"):
                                        p.dns_aaaa = temp
                                        continue
                                    if str(m) == ("dns.response_to"):
                                        p.dns_response_to = temp
                                        continue
                                    if str(m) == ("dns.resp.ttl"):
                                        p.dns_resp_ttl = temp
                                        continue
                                    if str(m) == ("dns.time"):
                                        p.dns_time = temp
                                        continue

                            if l=="ssdp":
                                for m in i[j][k][l]:
                                    temp = i[j][k][l][m]
                                    if str(m) == ("http.host"):
                                        p.http_host = temp
                                        # p.host = temp
                                        continue
                                    if str(m) == "http.request":
                                        p.http_request = temp
                                        continue
                                    if str(m) == "http.request_number":
                                        p.http_request_number = temp
                                        continue
                                    if str(m) == "http.prev_request_in":
                                        p.http_request_number = temp
                                        continue

                            if l=="ssl":
                                for m in i[j][k][l]:
                                    if m=="ssl.record":
                                        for mm in i[j][k][l][m]:
                                            if mm == "ssl.handshake":
                                                for mmm in i[j][k][l][m][mm]:
                                                    if str(mmm).__contains__("Extension: server_name"):
                                                        for mmmm in i[j][k][l][m][mm][mmm]:
                                                            if mmmm == "Server Name Indication extension":
                                                                for lll in i[j][k][l][m][mm][mmm][mmmm]:
                                                                    if lll == "ssl.handshake.extensions_server_name":
                                                                        p.host = str(i[j][k][l][m][mm][mmm][mmmm][lll])
        p.html_info = ""
        lst_packets[str(p.frame_number)] = p
    print("Packet list created. \n")
    return (lst_packets)

def create_packet_list_tshark(file_name):
    if os.path.exists(file_name):
        try:
            with open(file_name) as wireshark_file:
                wireshark_info = json.load(wireshark_file)
        except:
            print("Error: %s is not in the appropriate JSON format.\n\n")%(file_name)
            exit(0)
    else:
        print("Error: %s is not exists in ", str(os.getcwd()))%(file_name)
        print("Please put the flows.json and %s next to the wiman.py\n\n")%(file_name)
        exit(0)
    # Parse the Wireshark JSON File to extract packets
    print("\nReading tshark.json ...")
    lst_packets: Dict[str, Packet] = {}
    for i in wireshark_info:
        p = Packet()
        for j in i:
            if str(j) == "_source":
                for k in i[j]:  # Layers
                    for m in i[j][k]:
                        temp = str(i[j][k][m])
                        temp = temp[2:-2]
                        if str(m) == "frame.interface_id":
                            p.frame_interface_id = temp
                            continue
                        if str(m) == "frame.time":
                            p.frame_time = temp
                            continue
                        if str(m) == ("frame.time_epoch"):
                            p.time_epoch = temp
                            continue
                        if str(m) == ("frame.time_relative"):
                            p.frame_time_relative = temp
                            continue
                        if str(m) == ("frame.number"):
                            p.frame_number = temp
                            continue
                        if str(m) == ("frame.len"):
                            p.frame_len = temp
                            continue
                        if str(m) == ("frame.protocols"):
                            p.frame_protocols = temp
                            continue

                        if str(m) == ("ip.version"):
                            p.ip_version = temp
                            continue
                        if str(m) == ("ip.hdr_len"):
                            p.ip_hdr_len = temp
                            continue
                        if str(m) == ("ip.len"):
                            p.ip_len = temp
                            continue
                        if str(m) == ("ip.ttl"):
                            p.ip_ttl = temp
                            continue
                        if str(m) == ("ip.proto"):
                            p.proto = temp
                            continue
                        if str(m) == ("ip.src"):
                            p.ip_src = temp
                            continue
                        if str(m) == ("ip.dst"):
                            p.ip_dst = temp
                            continue

                        if str(m) == ("udp.srcport"):
                            p.src_port = temp
                            continue
                        if str(m) == ("udp.dstport"):
                            p.dst_port = temp
                            continue
                        if str(m) == ("udp.length"):
                            p.udp_length = temp
                            continue
                        if str(m) == ("udp.stream"):
                            p.stream_number = temp
                            p.packet_type = "UDP"
                            continue
                        if str(m) == ("udp.checksum.status"):
                            p.udp_checksum_status = temp
                            continue

                        if str(m) == ("tcp.srcport"):
                            p.src_port = temp
                            continue
                        if str(m) == ("tcp.dstport"):
                            p.dst_port = temp
                            continue
                        if str(m) == ("tcp.stream"):
                            p.stream_number = temp
                            p.packet_type = "TCP"
                            continue
                        if str(m) == ("tcp.ack"):
                            p.tcp_ack = temp
                            continue
                        if str(m) == ("data.len"):
                            p.data_len = temp
                            continue
                        if str(m) == ("tcp.hdr_len"):
                            p.tcp_hdr_len = temp
                            continue
                        if str(m) == ("tcp.window_size"):
                            p.tcp_window_size = temp
                            continue
                        if str(m) == ("tcp.flags"):
                            p.tcp_flags = temp
                            continue
                        if str(m) == ("tcp.seq"):
                            p.tcp_seq = temp
                            continue

                        if str(m) == ("dns.id"):
                            p.dns_id = temp
                            p.is_dns = True
                            continue
                        if str(m) == ("dns.qry.name"):
                            p.dns_qry_name = temp
                            continue
                        if str(m) == ("dns.resp.name"):
                            p.dns_resp_name = temp
                            continue
                        if str(m) == ("dns.a"):
                            p.dns_a = temp
                            continue
                        if str(m) == ("dns.aaaa"):
                            p.dns_aaaa = temp
                            continue
                        if str(m) == ("dns.response_to"):
                            p.dns_response_to = temp
                            continue
                        if str(m) == ("dns.resp.ttl"):
                            p.dns_resp_ttl = temp
                            continue
                        if str(m) == ("dns.time"):
                            p.dns_time = temp
                            continue

                        if str(m) == ("http.host"):
                            p.http_host = temp
                            # p.host = temp
                            continue
                        if str(m) == ("http.request.method"):
                            p.http_request_method = temp
                            continue
                        if str(m) == ("http.request.version"):
                            p.http_request_version = temp
                            continue
                        if str(m) == "http.request":
                            p.http_request = temp
                            continue
                        if str(m) == "http.request_number":
                            p.http_request_number = temp
                            continue
                        if str(m) == ("ssl.handshake.extensions_server_name"):
                            p.host = temp
                            continue
                        if str(m) == ("frame.protocols"):
                            if temp == "eth:ethertype:arp":
                                p.packet_type = "ARP"
                            p.frame_protocols = temp
                            continue

        lst_packets[str(p.frame_number)] = p
    print("Packet list created.\n")
    wireshark_file.close()
    return (lst_packets)

def clear_packet_list(ip, lst_packets:Dict[str, Packet]):
    lst_temp = {}
    for p in lst_packets:
        if (lst_packets[p].ip_src == ip) or (lst_packets[p].ip_dst == ip):
            lst_temp[lst_packets[p].frame_number] = p
    return lst_temp

# Print out packet's info by frame number
def show_packet_info(lst_packets:Dict[str, Packet], packet_number):
    for i in lst_packets[str(packet_number)].__dict__:
        print(i)

# Seperate packets to sent and received list
def get_sent_and_recieved_packets(lst_packets:Dict[str, Packet], mitm_port):
    lst_sent_packets = {}
    lst_recieved_packets = {}

    # find sender and receiver by using the port number
    # we do not use ip because maybe user uses one system as both client and MITM systems
    for p in lst_packets:
        if lst_packets[p].src_port == "8080" or lst_packets[p].src_port == "8080":
            lst_recieved_packets[lst_packets[p].frame_number] = lst_packets[p]
        elif lst_packets[p].dst_port == "8080" or lst_packets[p].dst_port == "8080":
            lst_sent_packets[lst_packets[p].frame_number] = lst_packets[p]
        else:
            pass
            # print(str(lst_packets[p].frame_number))

    return lst_sent_packets, lst_recieved_packets

"""
create_table_page(title_page, id, headers:list, data:dict )
"""
# Send importatnt packet info to show in wireshark trace
def get_wireshark_log_html(lst_packets:Dict[str, Packet]):
    headers = ["Number", "Time Epoch", "Relative Time", "Type",
               "Src IP", "Dst IP", "Src Port", "Dst Port", "Length (byte)", "Version",
               "TTL", "Windows Size", "Ack", "Fin", "Syn", "Out of order"]
    data_test = {}
    n = 0
    for i in lst_packets:
        temp = []
        temp.append(lst_packets[i].frame_number)
        temp.append(lst_packets[i].time_epoch)
        temp.append(lst_packets[i].frame_time_relative)
        temp.append(lst_packets[i].packet_type)
        temp.append(lst_packets[i].ip_src)
        temp.append(lst_packets[i].ip_dst)
        temp.append(lst_packets[i].src_port)
        temp.append(lst_packets[i].dst_port)
        temp.append(lst_packets[i].frame_len)
        temp.append(lst_packets[i].ip_version)
        temp.append(lst_packets[i].ip_ttl)
        temp.append(lst_packets[i].tcp_window_size)
        temp.append(lst_packets[i].tcp_ack)
        temp.append(lst_packets[i].tcp_connection_fin)
        temp.append(lst_packets[i].tcp_connection_syn)
        temp.append(lst_packets[i].tcp_analysis_out_of_order)

        data_test[str(lst_packets[i].frame_number)] = temp
        n+=1
        if n>1000:
            break
    return headers, data_test
    # create_table_page("Wireshark_Log", headers, data_test)


def export_data_json_for_wireshark_table(lst_packets:Dict[str, Packet], file_name):
    headers = ["frame_number",  "time_epoch", "packet_type", "ip_src", "ip_dst", "src_port", "dst_port", "tcp_window_size", "frame_len", "ip_version", "stream_number"]
    values = []

    info = {}
    for i in lst_packets:
        temp = []
        temp.append(lst_packets[i].frame_number)
        local_time = epoch_to_regular(lst_packets[i].time_epoch)
        temp.append(local_time)
        temp.append(lst_packets[i].packet_type)
        temp.append(lst_packets[i].ip_src)
        temp.append(lst_packets[i].ip_dst)
        temp.append(lst_packets[i].src_port)
        temp.append(lst_packets[i].dst_port)
        temp.append(lst_packets[i].frame_len)
        temp.append(lst_packets[i].ip_version)
        temp.append(lst_packets[i].tcp_window_size)
        # temp.append(lst_packets[i].tag)
        temp.append(lst_packets[i].stream_number)
        values.append(temp)
        info['data'] = values
    json_data = json.dumps(info)
    try:
        if not os.path.exists("output/"):
            os.makedirs("output/")
        path = "output/" + file_name + ".json"
        if os.path.exists(path):
            os.remove(path)
        a = open(path, "a")
        a.write(json_data)
    except FileNotFoundError:
        print("Error in write output in output folder\n", sys.exc_info()[1])

def export_data_json_for_mitm_table(lst_flows:Dict[str, Flow], file_name, page_name):
    headers = ["flow_number",  "method", "status_code", "content_type", "content_length", "url","http_version",
               "client_ip", "server_ip", "mitm_ip", "client_port", "server_port", "mitm_port", "host",
               "date", "client_initiated_time", "server_initiated_time", "request_timestamp_start", "response_timestamp_start", "packet_list"]
    values = []

    info = {}
    for i in lst_flows:
        temp = []
        temp.append(lst_flows[i].flow_number)
        if page_name == "Full":
            pass
        elif page_name == "GET":
            if str(lst_flows[i].method) != "GET":
                continue
        elif page_name == "POST":
            if str(lst_flows[i].method) != "POST":
                continue
        elif page_name == "OTHER":
            if str(lst_flows[i].method) == "GET" or str(lst_flows[i].method) == "POST":
                continue

        temp.append(lst_flows[i].method)
        status_code =lst_flows[i].status_code
        if status_code=="200":
            status_code = '<font color="Green"> %s </font>'%status_code
        else:
            status_code = '<font color="Red"> %s </font>' % status_code
        temp.append(status_code)
        temp.append(lst_flows[i].content_type)
        content_length=lst_flows[i].content_length
        if content_length==None or content_length=="None":
            content_length=0
        temp.append(content_length)
        url = lst_flows[i].url
        url = '<a href=%s target="_blank" title="%s"> Link </a>' % (url, url)
        temp.append(url)
        temp.append(lst_flows[i].http_version)
        temp.append(lst_flows[i].client_ip)
        temp.append(lst_flows[i].mitm_ip)
        temp.append(lst_flows[i].server_ip)
        temp.append(lst_flows[i].client_port)
        temp.append(lst_flows[i].mitm_port)
        temp.append(lst_flows[i].server_port)
        temp.append(lst_flows[i].host)

        local_time = yycTime(lst_flows[i].request_timestamp_start)
        temp.append(local_time)

        temp.append(lst_flows[i].client_initiated_time)
        temp.append(lst_flows[i].server_initiated_time)
        temp.append(lst_flows[i].request_timestamp_start)
        temp.append(lst_flows[i].response_timestamp_start)
        # temp.append(lst_flows[i].packet_list)
        packet_list_url = "<a href=flow"+lst_flows[i].flow_number+".html"+"> Flow List </a>"
        temp.append(packet_list_url)
        values.append(temp)
        info['data'] = values
    json_data = json.dumps(info)
    try:
        if not os.path.exists("output/"):
            os.makedirs("output/")
        path = "output/" + file_name + page_name+ ".json"
        if os.path.exists(path):
            os.remove(path)
        a = open(path, "a")
        a.write(json_data)
    except FileNotFoundError:
        print("Error in write output in output folder\n", sys.exc_info()[1])

# Change Timestamp to Calgary Time
def yycTime(epochTime):
    epochTime = int(float(epochTime))
    e = time.gmtime(epochTime)
    t = time.localtime(epochTime)
    return time.strftime('%Y-%m-%d %H:%M:%S', t)

def epoch_to_regular(epochTime):
    r = str(float(epochTime) - int(float(epochTime)))
    r = r[2:8]
    # print(r )
    epochTime = int(float(epochTime))
    t = time.localtime(epochTime)
    r = str(time.strftime('%H:%M:%S', t)) + "." + str(r)
    return r

