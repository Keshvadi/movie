import collections
# Flow Class
import json
import os
import time
from decimal import Decimal
from os import getcwd
from typing import Dict

from addlink import lookup
from config import is_file_exist

# Flow Class
class Flow:
    def __init__(self,
                 flow_number=None,
                 request_number=None,
                 response_number=None,
                 method=None,
                 status_code=None,
                 content_type=None,
                 content_length=None,
                 http_version=None,
                 client_ip=None,
                 server_ip=None,
                 mitm_ip=None,
                 client_port=None,
                 server_port=None,
                 mitm_port=None,
                 host=None,
                 url=None,
                 reffer=None,
                 last_modified=None,
                 server=None,
                 user_agent=None,
                 tls_is_stablished=None,
                 tls_version=None,
                 cipher_name=None,
                 date=None,
                 client_initiated_time=None,
                 server_initiated_time=None,
                 request_timestamp_start=None,
                 request_timestamp_end=None,
                 response_timestamp_start=None,
                 response_timestamp_end=None,
                 reason=None,
                 dns_time=None,
                 has_response=False,
                 stream_number=None,
                 packet_list=None,
                 is_ad=False,
                 html_info=None
                 ):
        if packet_list is None:
            packet_list = []
        self.flow_number = flow_number
        self.request_number = request_number
        self.response_number = response_number
        self.method = method
        self.status_code = status_code
        self.content_type = content_type
        self.content_length = content_length
        self.http_version = http_version
        self.client_ip = client_ip
        self.server_ip = server_ip
        self.mitm_ip = mitm_ip
        self.client_port = client_port
        self.server_port = server_port
        self.mitm_port = mitm_port
        self.host = host
        self.url = url
        self.reffer = reffer
        self.last_modified = last_modified
        self.server = server
        self.user_agent = user_agent
        self.tls_is_stablished = tls_is_stablished
        self.tls_version = tls_version
        self.cipher_name = cipher_name
        self.date = date
        self.client_initiated_time = client_initiated_time
        self.server_initiated_time = server_initiated_time
        self.request_timestamp_start = request_timestamp_start
        self.request_timestamp_end = request_timestamp_end
        self.response_timestamp_start = response_timestamp_start
        self.response_timestamp_end = response_timestamp_end
        self.reason = reason
        self.dns_time = dns_time
        self.has_response = has_response
        self.stream_number = stream_number
        self.packet_list = packet_list
        self.is_ad = is_ad
        self.html_info = html_info

    def get_short_flow_info_html(self):
        return (
                "<br><br>Method = " + str(self.method) +
                "<br>Host = " + str(self.host) +
                "<br>Content Type = " + str(self.content_type) +
                "<br>Content Length = " + str(self.content_length) + " bits")

    def get_full_flow_info_html(self):
        try:
            localTime = time.strftime('%Y-%m-%d %H:%M:%S %b', time.localtime(Decimal(self.client_initiated_time)))
        except:
            localTime = None
        return (
                "<b>Method = </b>" + str(self.method) +
                '<br><b>Host = </b> <a href = "http://' + str(self.host) + '"> ' + str(self.host) + '</a>' +
                "<br><b>Status Code = </b>" + str(self.status_code) + "\n" +
                # "<br><b>Scheme = </b>" + str(self.scheme) + "\n" +
                '<br><b>URL = </b> <a href = "' + str(self.url) + '"> ' + str(self.url) + '</a>' +
                '<br><b>Reffer = </b> <a href = "' + str(self.reffer) + '"> ' + str(self.reffer) + '</a>' +
                "<br><b>HTTP Version = </b>" + str(self.http_version) + "\n" +
                "<br><b>Content Type = </b>" + str(self.content_type) +
                "<br><b>Content Length = </b>" + str(self.content_length) + "\n" +
                "<br><b>Last Modified = </b>" + str(self.last_modified) + "\n" +
                "<br><b>Server Type = </b>" + str(self.server) + "\n" +
                "<br><b>User Agent = </b>" + str(self.user_agent) + "\n" +
                "<br><br><b>Is TLS Stablished = </b>" + str(self.tls_is_stablished) + "\n" +
                "<br><b>TLS Version = </b>" + str(self.tls_version) + "\n" +
                "<br><b>Cipher Name = </b>" + str(self.cipher_name) + "\n" +
                "<br><br><b>Client IP = </b>" + str(self.client_ip)[7:] + "\n" +
                "<br><b>Server IP = </b>" + str(self.server_ip) + "\n" +
                "<br><b>MITM IP = </b>" + str(self.mitm_ip) + "\n" +
                "<br><br><b>Date = </b>" + str(self.date) +
                "<br> <b>Client Initiated Time = </b>" + str(self.client_initiated_time) + " (" + str(
            localTime) + ")" + "\n" +
                "<br> <b>Server Initiated Time = </b>" + str(self.server_initiated_time) + "\n" +
                "<br> <b>Request Start Time = </b>" + str(self.request_timestamp_start) + "\n" +
                "<br> <b>Request End Time = </b>" + str(self.request_timestamp_end) + "\n" +
                "<br> <b>Response Start Time = </b>" + str(self.response_timestamp_start) + "\n" +
                "<br> <b>Response End Time = </b>" + str(self.response_timestamp_end) + "\n" +
                "<br> <b>DNS Response Time = </b>" + str(self.dns_time) + "\n" +
                "<br><br><b>Number of Packets in Wireshark = </b>" + str(len(self.packet_list)) +
                '<br><a href="flow' + str(self.flow_number) + '.html"> <b>Packet List </b> </a>')

    def get_packet_list_html(self):
        text = ""
        for p in self.packet_list:
            text += '<a href = "Packet_'
            text += str(p)
            text += '.html"> Packet_'
            text += str(p)
            text += "</a>"
        return text

# Session Class
class session:
    def __init__(self,
                 init_number=None,
                 client_initiated_time=None,
                 server_initiated_time=None,
                 request_start_time = None,
                 request_end_time = None,
                 src_ip=None,
                 dst_ip=None,
                 mitm_ip=None,
                 src_port=None,
                 dst_port=None,
                 mitm_port=None,
                 dst_name=None,
                 flows_list=None,
                 src_tcp_stream=None,
                 dst_tcp_stream=None,
                 src_udp_stream=None,
                 dst_udp_stream=None,
                 src_dns_stream=None,
                 dst_dns_stream=None,
                 dns_q=None,
                 dns_a=None,
                 packet_list=None
                 ):
        if flows_list is None:
            flows_list = []
        if packet_list is None:
            packet_list = []
        self.init_number = init_number
        self.client_initiated_time = client_initiated_time
        self.server_initiated_time = server_initiated_time
        self.request_start_time = request_start_time
        self.request_end_time = request_end_time
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.mitm_ip = mitm_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.mitm_port = mitm_port
        self.dst_name = dst_name
        self.flows_list = flows_list
        self.src_tcp_stream = src_tcp_stream
        self.dst_tcp_stream = dst_tcp_stream
        self.src_udp_stream = src_udp_stream
        self.dst_udp_stream = dst_udp_stream
        self.src_dns_stream = src_dns_stream
        self.dst_dns_stream = dst_dns_stream
        self.dns_q = dns_q
        self.dns_a = dns_a
        self.packet_list = packet_list

    def get_info(self):
        return (
                "Number : " + str(self.init_number) + "\n" +
                "Client Init Time : " + str(self.client_initiated_time) + "\n" +
                "Destination Name : " + str(self.dst_name) + "\n" +
                "Destination IP : " + str(self.dst_ip) + "\n" +
                "Flowlist includes : " + str((self.flows_list))
        )

# Create flow list
def create_flow_list(req_file_name, res_file_name):
    # Read MITM's Request log file
    is_file_exist(req_file_name)
    is_file_exist(res_file_name)
    test_ad = lookup()
    try:
        with open(req_file_name) as requests_file:
            request_info = json.load(requests_file)
    except:
        # print("Error: %s is not in the currect JSON format.\n\n")%(req_file_name)
        exit(0)

    lst_flows = {}
    print("\nReading Client Requests ...")
    for i in request_info:
        f = Flow()
        # inside of each flow
        for j in i:
            # the None information will be compeleted by response log
            if str(j) == ("Request_Number"):
                f.flow_number = str(i[j])
                f.request_number = str(i[j])
                continue
            if str(j) == ("Method"):
                temp = str(i[j])
                if (temp != "None") and (temp != "") and (temp != None):
                    f.method = str(i[j])
                continue
            if str(j) == ("Content_Type"):
                temp = str(i[j])
                if (temp != "None") and (temp != "") and (temp != None):
                    content_type = find_content_type(temp)
                    f.content_type = content_type
                continue
            if str(j) == ("Content_Length"):
                temp = str(i[j])
                if (temp != "None") and (temp != "") and (temp != None) and (temp != "0"):
                    f.content_length = str(i[j])
                continue
            if str(j) == ("Client_IP"):
                temp = str(i[j])
                if (temp != "None") and (temp != "") and (temp != None):
                    if temp.startswith("::ffff:"):
                        temp = temp[7:]
                    f.client_ip = temp
                continue
            if str(j) == ("Server_IP"):
                temp = str(i[j])
                if (temp != "None") and (temp != "") and (temp != None):
                    if temp.startswith("::ffff:"):
                        temp = temp[7:]
                    f.server_ip = temp
                continue
            if str(j) == ("MITM_IP"):
                temp = str(i[j])
                if (temp != "None") and (temp != "") and (temp != None):
                    if temp.startswith("::ffff:"):
                        temp = temp[7:]
                    f.mitm_ip = temp
                continue
            if str(j) == ("Client_Port"):
                temp = str(i[j])
                if (temp != "None") and (temp != "") and (temp != None) and (temp != "0"):
                    f.client_port = str(i[j])
                continue
            if str(j) == ("Server_Port"):
                temp = str(i[j])
                if (temp != "None") and (temp != "") and (temp != None) and (temp != "0"):
                    f.server_port = str(i[j])
                continue
            if str(j) == ("MITM_Port"):
                temp = str(i[j])
                if (temp != "None") and (temp != "") and (temp != None) and (temp != "0"):
                    f.mitm_port = str(i[j])
                continue
            if str(j) == ("Host"):
                temp = str(i[j])
                if (temp != "None") and (temp != "") and (temp != None) and (temp != "0"):
                    f.host = str(i[j])
                continue
            if str(j) == ("URL"):
                temp = str(i[j])
                if (temp != "None") and (temp != "") and (temp != None) and (temp != "0"):
                    f.url = str(i[j])
                    if test_ad.match_url(f.url)==True:
                        f.is_ad = True

                continue
            if str(j) == ("Reffer"):
                temp = str(i[j])
                if (temp != "None") and (temp != "") and (temp != None) and (temp != "0"):
                    f.reffer = str(i[j])
                continue
            if str(j) == ("Last_Modified"):
                temp = str(i[j])
                if (temp != "None") and (temp != "") and (temp != None) and (temp != "0"):
                    f.last_modified = str(i[j])
                continue
            if str(j) == ("Server_Name"):
                temp = str(i[j])
                if (temp != "None") and (temp != "") and (temp != None) and (temp != "0"):
                    f.server = str(i[j])
                continue
            if str(j) == ("User_Agent"):
                temp = str(i[j])
                if (temp != "None") and (temp != "") and (temp != None) and (temp != "0"):
                    f.user_agent = str(i[j])
                continue
            if str(j) == ("Tls_Established"):
                temp = str(i[j])
                if (temp != "None") and (temp != "") and (temp != None) and (temp != "0"):
                    f.tls_is_stablished = str(i[j])
                continue
            if str(j) == ("Tls_Version"):
                temp = str(i[j])
                if (temp != "None") and (temp != "") and (temp != None) and (temp != "0"):
                    f.tls_version = str(i[j])
                continue
            if str(j) == ("Cipher_Name"):
                temp = str(i[j])
                if (temp != "None") and (temp != "") and (temp != None) and (temp != "0"):
                    f.cipher_name = str(i[j])
                continue
            if str(j) == ("Date"):
                temp = str(i[j])
                if (temp != "None") and (temp != "") and (temp != None) and (temp != "0"):
                    f.date = str(i[j])
                continue
            if str(j) == ("ClientInitiatedTime"):
                temp = str(i[j])
                if (temp != "None") and (temp != "") and (temp != None) and (temp != "0"):
                    f.client_initiated_time = str(i[j])
                continue
            if str(j) == ("ServerInitiatedTime"):
                temp = str(i[j])
                if (temp != "None") and (temp != "") and (temp != None) and (temp != "0"):
                    f.server_initiated_time = str(i[j])
                continue
            if str(j) == ("ReqestStartTime"):
                temp = str(i[j])
                if (temp != "None") and (temp != "") and (temp != None) and (temp != "0"):
                    f.request_timestamp_start = str(i[j])
                continue
            if str(j) == ("ReqestEndTime"):
                temp = str(i[j])
                if (temp != "None") and (temp != "") and (temp != None) and (temp != "0"):
                    f.request_timestamp_end = str(i[j])
                continue
            if str(j) == ("reason"):
                temp = str(i[j])
                if (temp != "None") and (temp != "") and (temp != None) and (temp != "0"):
                    f.reason = str(i[j])
                    f.http_version = str(i[j])
                continue
            # f.htmlInfo = f.getFlowInfoHTML()
        lst_flows[f.flow_number] = f
    requests_file.close()

    # Read Response.json and complete the flows
    check_json_file(res_file_name)
    try:
        with open(res_file_name) as response_file:
            response_info = json.load(response_file)
    except ValueError as e:
        print(e)
        # print("Error: %s is not in the currect JSON format.\n\n")%(res_file_name)
        exit(0)

    for i in response_info:
        temp_flow = Flow()
        # create a temp flow to complete flows from Request log
        for j in i:
            if str(j) == ("Response_Number"):
                temp_flow.response_number = str(i[j])
                continue
            if str(j) == ("Method"):
                temp_flow.method = str(i[j])
                continue
            if str(j) == ("Status_Code"):
                temp_flow.status_code = str(i[j])
                continue
            if str(j) == ("Content_Type"):
                temp = str(i[j])
                content_type = find_content_type(temp)
                temp_flow.content_type = content_type
                continue
            if str(j) == ("Content_Length"):
                temp_flow.content_length = str(i[j])
                continue
            if str(j) == ("Client_IP"):
                temp = str(i[j])
                if temp.startswith("::ffff:"):
                    temp = temp[7:]
                temp_flow.client_ip = temp
                continue
            if str(j) == ("Server_IP"):
                temp = str(i[j])
                if temp.startswith("::ffff:"):
                    temp = temp[7:]
                temp_flow.server_ip = temp
                continue
            if str(j) == ("MITM_IP"):
                temp = str(i[j])
                if temp.startswith("::ffff:"):
                    temp = temp[7:]
                temp_flow.mitm_ip = temp
                continue
            if str(j) == ("Client_Port"):
                temp_flow.client_port = str(i[j])
                continue
            if str(j) == ("Server_Port"):
                temp_flow.server_port = str(i[j])
                continue
            if str(j) == ("MITM_Port"):
                temp_flow.mitm_port = str(i[j])
                continue
            if str(j) == ("Host"):
                temp_flow.host = str(i[j])
                continue
            if str(j) == ("URL"):
                temp_flow.url = str(i[j])
                if test_ad.match_url(temp_flow.url) == True:
                    temp_flow.is_ad = True
                continue
            if str(j) == ("Reffer"):
                temp_flow.reffer = str(i[j])
                continue
            if str(j) == ("Last_Modified"):
                temp_flow.last_modified = str(i[j])
                continue
            if str(j) == ("Server_Name"):
                temp_flow.server = str(i[j])
                continue
            if str(j) == ("User_Agent"):
                temp_flow.user_agent = str(i[j])
                continue
            if str(j) == ("Tls_Established"):
                temp_flow.tls_is_stablished = str(i[j])
                continue
            if str(j) == ("Tls_Version"):
                temp_flow.tls_version = str(i[j])
                continue
            if str(j) == ("Cipher_Name"):
                temp_flow.cipher_name = str(i[j])
                continue
            if str(j) == ("Date"):
                temp_flow.date = str(i[j])
                continue
            if str(j) == ("ClientInitiatedTime"):
                temp_flow.client_initiated_time = str(i[j])
                continue
            if str(j) == ("ServerInitiatedTime"):
                temp_flow.server_initiated_time = str(i[j])
                continue
            if str(j) == ("ReqestStartTime"):
                temp_flow.request_timestamp_start = str(i[j])
                continue
            if str(j) == ("ReqestEndTime"):
                temp_flow.request_timestamp_end = str(i[j])
                continue
            if str(j) == ("ResponseStartTime"):
                temp_flow.response_timestamp_start = str(i[j])
                continue
            if str(j) == ("ResponseEndTime"):
                temp_flow.response_timestamp_end = str(i[j])
                continue
            if str(j) == ("reason"):
                temp_flow.reason = str(i[j])
                temp_flow.http_version = str(i[j])
                continue

        # find correspond request log for this response
        for f in lst_flows:
            if lst_flows[f].has_response == True:
                continue
            if (str(lst_flows[f].client_initiated_time) == str(temp_flow.client_initiated_time) and
                    lst_flows[f].request_timestamp_start == temp_flow.request_timestamp_start and
                    lst_flows[f].request_timestamp_end == temp_flow.request_timestamp_end):
                lst_flows[f].has_response = True
                lst_flows[f].response_number = temp_flow.response_number
                for i in lst_flows[f].__dict__:
                    if (lst_flows[f].__dict__[i] is None) or (lst_flows[f].__dict__[i] == "None"):
                        lst_flows[f].__dict__[i] = temp_flow.__dict__[i]
                break
    response_file.close()
    print("Flow list created. \n")

    return lst_flows

# Check JSON file for incorrect format
def check_json_file(file_name):
    # f = open(file_name)
    # temp = open("temp", "w+")
    #
    # for line in f:
    #     if line.__contains__('"'):
    #         line = line.replace('"', "'")
    #         temp.write(line)
    #     else:
    #         temp.write(line)
    # f.close()
    # temp.close()
    # os.remove(file_name)
    # os.renames("temp", file_name)
    return None

    # return f



'''
lst_flow functions
'''
# display all flow info
def get_flow_info(flow_num, lst_flows):
    for f in lst_flows:
        if lst_flows[f].flow_number == flow_num:
            for i in lst_flows[f].__dict__:
                print(lst_flows[f].request_number, ' - ', lst_flows[f].response_number, ' - ', i, ' - ', lst_flows[f].__dict__[i])


# Find initiated Lists
def find_initiated_time_list(lst_flows):
    init_number = 0
    print("\nStart Categorzing Flows based on the Connection Initiated Time...")
    lst_init = {}
    for f in lst_flows:
        for n in lst_init:
            if (lst_init[n].client_initiated_time == lst_flows[f].client_initiated_time) and (
                    lst_init[n].server_initiated_time == lst_flows[f].server_initiated_time):
                lst_init[n].flows_list.append(lst_flows[f].flow_number)
                break
        else:
            init_number += 1
            i = session()
            i.init_number = init_number
            i.client_initiated_time = lst_flows[f].client_initiated_time
            i.server_initiated_time = lst_flows[f].server_initiated_time
            i.request_start_time = lst_flows[f].request_timestamp_start
            i.request_end_time = lst_flows[f].request_timestamp_end
            i.src_ip = str(lst_flows[f].client_ip)
            i.dst_ip = str(lst_flows[f].server_ip)
            i.mitm_ip = str(lst_flows[f].mitm_ip)
            i.src_port = str(lst_flows[f].client_port)
            i.dst_port = str(lst_flows[f].server_port)
            i.mitm_port = str(lst_flows[f].mitm_port)
            i.dst_name = str(lst_flows[f].host)
            i.flows_list = []
            i.flows_list.append(str(lst_flows[f].flow_number))
            i.packet_list = []
            lst_init[init_number] = i
    print("Init List created.\n")
    return lst_init

# Search the flow list of the given InitTime
def search_init_time_by_client_init_time(lst_initiated_time:Dict[str, session], init_time):
    for i in lst_initiated_time:
        if lst_initiated_time[i].client_initiated_time == init_time:
            return (lst_initiated_time[i].flows_list)

# print(search_init_time_by_client_init_time("1547623123.6706681"))

# Search the InitTime of the given flow number
def search_init_time_by_flow_number(lst_initiated_time:Dict[str, session], flow_number):
    for i in lst_initiated_time:
        if flow_number in lst_initiated_time[i].flows_list:
            return lst_initiated_time[i].client_initiated_time

# print(search_init_time_by_flow_number("10"))

# Check all streams's flows
def find_unassigned_flows(lst_flows:Dict[str, Flow]):
    print("\n----------- unassigned Flows -----------")
    for f in lst_flows:
        if lst_flows[f].packet_list==[]:
            print(str(lst_flows[f].flow_number) + " - " + str(lst_flows[f].host))


class Content:
    def __init__(self, type = None, flow_list = [], overal_size= 0):
        self.type = type
        self.flow_list = flow_list
        self.overal_size = overal_size

"""
Sina - Sort output 
"""
def classify_content_type(lst_flows:Dict[str, Flow]):
    lst_content_type = {}
    for f in lst_flows:
        if lst_flows[f].content_type in lst_content_type:
            lst_content_type[lst_flows[f].content_type].flow_list.append(lst_flows[f].flow_number)
            if lst_flows[f].content_length == "None" or lst_flows[f].content_length == None :
                pass
            else:
                lst_content_type[lst_flows[f].content_type].overal_size += int(lst_flows[f].content_length)
        else:
            temp = Content()
            temp.type = lst_flows[f].content_type
            temp.flow_list = []
            temp.flow_list.append(lst_flows[f].flow_number)
            if lst_flows[f].content_length == "None" or lst_flows[f].content_length == None:
                temp.overal_size = 0
            else:
                temp.overal_size = int(lst_flows[f].content_length)
            lst_content_type[lst_flows[f].content_type] = temp

    return lst_content_type
# <a href="#" onClick="MyWindow=window.open('http://www.google.com','MyWindow',width=600,height=300); return false;">Click Here</a> <br>

def get_all_request_info(lst_flows:Dict[str, Flow]):
    headers = ["Request #", "Request Time", "Method", "Status Code", "Host", "Src IP", "Dst IP", "MITM IP", "Src Port", "Dst Port", "MITM Port", "Content", "Length", "Number of Packets","More detail"]
    flows_info = {}
    for f in lst_flows:
        flow_url = """
        <a href="#" onClick="MyWindow=window.open('flow%s.html','MyWindow',width=600,height=300); return false;">Click Here</a> <br>
        """%(lst_flows[f].flow_number)
        flows_info[lst_flows[f].flow_number] = [lst_flows[f].flow_number, lst_flows[f].request_timestamp_start, lst_flows[f].method, lst_flows[f].status_code,
                                                lst_flows[f].host, lst_flows[f].client_ip, lst_flows[f].server_ip, lst_flows[f].mitm_ip, lst_flows[f].client_port, lst_flows[f].server_port,
                                                lst_flows[f].mitm_port, lst_flows[f].content_type, lst_flows[f].content_length, len(lst_flows[f].packet_list),flow_url]
    return headers, flows_info

# lst_flows = create_flow_list("flows.json")
# lst_content_type = classify_content_type(lst_flows)
# for i in lst_content_type:
#     print(str(lst_content_type[i].type), ' - ', len(lst_content_type[i].flow_list), ' - ', lst_content_type[i].overal_size)
#
# def classify_status_code(lst_flows:Dict[str, Flow]):
#     pass

def find_content_type(content_type):
    if content_type == None:
        return "None"
    if content_type.__contains__("json"):
        return "json"
    if content_type.__contains__("text/html"):
        return "text/html"
    if content_type.__contains__("javascript"):
        return "javascript"
    if content_type.__contains__("jpeg"):
        return "image"
    if content_type.__contains__("image"):
        return "image"
    if content_type.__contains__("video"):
        return "video"
    if content_type.__contains__("text/plain"):
        return "plain text"
    if content_type.__contains__("text/css"):
        return "text/css"
    if content_type.__contains__("audio"):
        return "audio"
    return content_type
