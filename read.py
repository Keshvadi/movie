'''
Here we read Requests and Responses flows from MITMProxy.
To run it:
    > ./mitmproxy -s read.py
After capturing all flows, it creates two json file: request.json and response.json

we use them to create lst_flow in the main program.
The reason that we have both request and response is that some request are without response. and request file is not complete by itself.
Main Program merges both files to have a complete list of succesfull and failed flows.
'''

import typing
import json
import os
import mitmproxy
from mitmproxy import ctx
import mitmproxy.addonmanager
import mitmproxy.connections
import mitmproxy.http
import mitmproxy.log
import mitmproxy.log
import mitmproxy.tcp
import mitmproxy.proxy.protocol
import mitmproxy.flow
import mitmproxy.websocket

# remove previious outputs
if os.path.exists("flows.json"):
  os.remove("flows.json")
if os.path.exists("request.json"):
    os.remove("request.json")
if os.path.exists("response.json"):
    os.remove("response.json")

class Record:
    def __init__(self):
        self.num = 0
        self.req_number = 0

    def request(self, flow:mitmproxy.http.HTTPFlow):
        b = open("request.json", "a")
        self.req_number +=1
        # first line of JSON  should start with [
        if self.req_number > 1:
            b.write(',\n{\n"Request_Number": ' + '"' + str(self.req_number) + '",')
        else:
            b.write("[\n")
            b.write('\n{\n"Request_Number": ' + '"' + str(self.req_number) + '",')\

        try:
            b.write('\n"Method": ' + '"' + str(flow.request.method) + '",')
        except:
            pass

        try:
            b.write('\n"Request_Content_Type": ' + '"' + str(remove_bad_character(flow.request.headers.get('Content-Type'))) + '",')
        except:
            pass

        try:
            b.write('\n"Request_Content_Length": ' + '"' + str(remove_bad_character(flow.request.headers.get('content-length'))) + '",')
        except:
            pass

        try:
            b.write('\n"Client_IP": ' + '"' + str(flow.client_conn.ip_address[0]) + '",')
        except:
            pass

        try:
            b.write('\n"Server_IP": ' + '"' + str(flow.server_conn.ip_address[0]) + '",')
        except:
            pass

        try:
            b.write('\n"MITM_IP": ' + '"' + str(flow.server_conn.source_address[0]) + '",')
        except:
            pass

        try:
            b.write('\n"Client_Port": ' + '"' + str(flow.client_conn.ip_address[1]) + '",')
        except:
            pass

        try:
            b.write('\n"Server_Port": ' + '"' + str(flow.server_conn.ip_address[1]) + '",')
        except:
            pass

        try:
            b.write('\n"MITM_Port": ' + '"' + str(flow.server_conn.source_address[1]) + '",')
        except:
            pass

        try:
            b.write('\n"Host": ' + '"' + str(remove_bad_character(flow.request.host)) + '",')
        except:
            pass

        try:
            b.write('\n"URL": ' + '"' + str(remove_bad_character(flow.request.url)) + '",')
        except:
            pass

        try:
            b.write('\n"Reffer": ' + '"' + str(flow.request.headers.get('Referer')) + '",')
        except:
            pass

        try:
            b.write('\n"Request_Server_Name": ' + '"' + str(flow.request.headers.get('Server')) + '",')
        except:
            pass

        try:
            b.write('\n"User_Agent": ' + '"' + str(remove_bad_character(flow.request.headers.get('User-Agent'))) + '",')
        except:
            pass

    # Time
        try:
            b.write('\n"Date": ' + '"' + str(flow.request.headers.get('Date')) + '",')
        except:
            pass

        try:
            b.write('\n"ClientInitiatedTime": ' + '"' + str(flow.client_conn.timestamp_start) + '",')
        except:
            pass

        try:
            b.write('\n"ServerInitiatedTime": ' + '"' + str(flow.server_conn.timestamp_start) + '",')
        except:
            pass

        try:
            b.write('\n"ReqestStartTime": ' + '"' + str(flow.request.timestamp_start) + '",')
        except:
            pass

        try:
            b.write('\n"ReqestEndTime": ' + '"' + str(flow.request.timestamp_end) + '",')
        except:
            pass

        try:
            b.write('\n"Request_Stream": ' + '"' + str(flow.request.stream) + '",')
        except:
            pass

        try:
            b.write('\n"Request_Path": ' + '"' + str(remove_bad_character(flow.request.path)) + '",')
        except:
            pass

        try:
            b.write('\n"reason": ' + '"' + str(remove_bad_character(flow.request.http_version)) + '"')
        except:
            b.write('\n"reason": ' + '"' + 'Nothing"')

        b.write('\n}')

    def response(self, flow:mitmproxy.http.HTTPFlow):
        a = open("response.json", "a")
        self.num +=1
        if self.num > 1:
            a.write(',\n{\n"Response_Number": ' + '"' + str(self.num) + '",')
        else:
            a.write("[\n")
            a.write('\n{\n"Response_Number": ' + '"' + str(self.num) + '",')

        try:
            a.write('\n"Method": ' + '"' + str(remove_bad_character(flow.request.method)) + '",')
            if flow.request.method=="POST":
                try:
                    flow_content = str(flow.response.content)
                    while flow_content.__contains__('"'):
                        flow_content = flow_content.replace('"', "'")
                    while flow_content.__contains__('\\'):
                        flow_content = flow_content.replace('\\', "/")
                    a.write('\n"Content": ' + '"' + str(flow_content) + '",')
                except:
                    pass
        except:
            pass

        try:
            a.write('\n"Status_Code": ' + '"' + str(remove_bad_character(flow.response.status_code)) + '",')
        except:
            pass

        try:
            a.write('\n"Content_Type": ' + '"' + str(remove_bad_character(flow.response.headers.get('Content-Type'))) + '",')
        except:
            pass

        try:
            a.write('\n"Content_Length": ' + '"' + str(remove_bad_character(flow.response.headers.get('content-length'))) + '",')
        except:
            pass

        try:
            a.write('\n"Client_IP": ' + '"' + str(flow.client_conn.ip_address[0]) + '",')
        except:
            pass

        try:
            a.write('\n"Server_IP": ' + '"' + str(flow.server_conn.ip_address[0]) + '",')
        except:
            pass

        try:
            a.write('\n"MITM_IP": ' + '"' + str(flow.server_conn.source_address[0]) + '",')
        except:
            pass

        try:
            a.write('\n"Client_Port": ' + '"' + str(flow.client_conn.ip_address[1]) + '",')
        except:
            pass

        try:
            a.write('\n"Server_Port": ' + '"' + str(flow.server_conn.ip_address[1]) + '",')
        except:
            pass

        try:
            a.write('\n"MITM_Port": ' + '"' + str(flow.server_conn.source_address[1]) + '",')
        except:
            pass

        try:
            a.write('\n"Host": ' + '"' + str(remove_bad_character(flow.request.host)) + '",')
        except:
            pass

        try:
            a.write('\n"URL": ' + '"' + str(flow.request.url) + '",')
        except:
            pass

        try:
            a.write('\n"Reffer": ' + '"' + str(flow.request.headers.get('Referer')) + '",')
        except:
            pass

        try:
            a.write('\n"Last_Modified": ' + '"' + str(flow.response.headers.get('Last-Modified')) + '",')
        except:
            pass

        try:
            a.write('\n"Server_Name": ' + '"' + str(remove_bad_character(flow.response.headers.get('Server'))) + '",')
        except:
            pass

        try:
            a.write('\n"User_Agent": ' + '"' + str(remove_bad_character(flow.request.headers.get('User-Agent'))) + '",')
        except:
            pass

        try:
            a.write('\n"Tls_Established": ' + '"' + str(flow.server_conn.tls_established) + '",')
        except:
            pass

        try:
            a.write('\n"Tls_Version": ' + '"' + str(flow.server_conn.tls_version) + '",')
        except:
            pass

        try:
            a.write('\n"Cipher_Name": ' + '"' + str(flow.client_conn.cipher_name) + '",')
        except:
            pass

    # Time
        try:
            a.write('\n"Date": ' + '"' + str(flow.response.headers.get('Date')) + '",')
        except:
            pass

        try:
            a.write('\n"ClientInitiatedTime": ' + '"' + str(flow.client_conn.timestamp_start) + '",')
        except:
            pass

        try:
            a.write('\n"ServerInitiatedTime": ' + '"' + str(flow.server_conn.timestamp_start) + '",')
        except:
            pass

        try:
            a.write('\n"ReqestStartTime": ' + '"' + str(flow.request.timestamp_start) + '",')
        except:
            pass

        try:
            a.write('\n"ReqestEndTime": ' + '"' + str(flow.request.timestamp_end) + '",')
        except:
            pass

        try:
            a.write('\n"ResponseStartTime": ' + '"' + str(flow.response.timestamp_start) + '",')
        except:
            pass

        try:
            a.write('\n"ResponseEndTime": ' + '"' + str(flow.response.timestamp_end) + '",')
        except:
            pass

        try:
            a.write('\n"reason": ' + '"' + str(flow.request.http_version) + '"')
        except:
            a.write('\n"reason": ' + '"' + 'Nothing"')

        a.write('\n}')


    def done(self):
        a = open("response.json", "a")
        b = open("request.json", "a")
        a.write('\n]')
        b.write('\n]')


addons = [
    Record()
]


def remove_bad_character(flow_content:str):
    while flow_content.__contains__('"'):
        flow_content = flow_content.replace('"', "'")
    while flow_content.__contains__('\\'):
        flow_content = flow_content.replace('\\', "/")
    return (flow_content)