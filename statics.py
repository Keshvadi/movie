import matplotlib.pyplot as plt
import numpy as np
from hurry.filesize import size
from packet import *
from mitm import *
from player import *


'''
Statics
    Reports the captured file information.
'''
class Static:
    def __init__(self, key, value, unit):
        self.key = key
        self.value = value
        self.unit = unit

    def return_value(self, key):
        return self.value

def general_wireshark_staticss(lst_sent_packets:Dict[str, Packet], lst_received_packets:Dict[str, Packet]):
    wireshark_statics = {}

    # number_of_packets = len(lst_packets)  # Number of packets
    number_of_received_packets = len(lst_received_packets)
    number_of_sent_packets = len(lst_sent_packets)

    start_time, stop_time = find_first_last_packet(lst_sent_packets, lst_received_packets)

    # start_time = lst_sent_packets[str(first_packet)].time_epoch  # Start Time
    start_time = format(float(start_time), '.2f')

    start_time_yyc = yycTime(start_time) # Start Time
    temp = Static("Capturing Start Time", start_time_yyc + ' - Timestamp: '+start_time, "Time")
    wireshark_statics["start_time_yyc"] = (temp.__dict__.values())

    # stop_time = lst_packets[str(stop_time)].time_epoch  # End Time
    stop_time = format(float(stop_time), '.2f')

    stop_time_yyc = yycTime(stop_time) # End Time
    temp = Static("Capturing Stop Time", stop_time_yyc+ ' - Timestamp: '+stop_time, "Time")
    wireshark_statics["stop_time_yyc"] = (temp.__dict__.values())

    duration = Decimal(stop_time) - Decimal(start_time)  # Duration (seconds)
    temp = Static("Capturing Duration", str(format(float(duration), '.2f')) + " sec", "sec")
    wireshark_statics["duration"] = (temp.__dict__.values())

    # total_bytes = get_total_bytes(lst_packets) # Total bytes
    # temp = Static("Total bytes", total_bytes, "byte")
    # wireshark_statics["total_bytes"] = (temp.__dict__.values())
    temp = Static("Sent Packets", str(number_of_sent_packets)+" packets", "packet")
    wireshark_statics["number_of_sent_packets"] = temp.__dict__.values()
    temp = Static("Received Packets", str(number_of_received_packets)+" packets", "packet")
    wireshark_statics["number_of_received_packets"] = temp.__dict__.values()
    total_sent_bytes = get_total_bytes(lst_sent_packets) # Total bytes
    temp = Static("Total Sent Bytes", size(total_sent_bytes) + ' (%s)'%(str(total_sent_bytes)) + " byte", "byte")
    wireshark_statics["total_sent_bytes"] = (temp.__dict__.values())
    total_received_bytes = get_total_bytes(lst_received_packets) # Total bytes
    temp = Static("Total Received Bytes", size(total_received_bytes) + ' (%s)'%(str(total_received_bytes)) + " byte", "byte")
    wireshark_statics["total_received_bytes"] = (temp.__dict__.values())

    total_received_bits = 8 * total_received_bytes # Total bits
    total_sent_bits = 8 * total_sent_bytes # Total bits

    # temp = Static("Total bits", total_bits, "bit")
    # wireshark_statics["total_bits"] = (temp.__dict__.values())
    bit_rate = Decimal(total_received_bits) / duration  # Data bit rate (bits/sec)
    temp = Static("Average Throughput", str((format((bit_rate), '.1f'))) + " bits/sec", "bits/sec")
    wireshark_statics["bit_rate"] = (temp.__dict__.values())

    packet_rate = Decimal(len(lst_received_packets)) / duration  # Packet rate (packets/sec)
    temp = Static("Received Packet Rate", str(format(packet_rate, '.1f'))+" packets/sec", "packets/sec")
    wireshark_statics["received_packet_rate"] = (temp.__dict__.values())


    # average_packet_size = Decimal(total_received_bytes) / len(lst_received_packets)# Average packet size (bytes)
    # temp = Static("Average Received Packet Size", str((size(average_packet_size)) + ' (%s)'%(str((format(average_packet_size, '.1f')))))+" byte", "byte")
    # wireshark_statics["average_packet_size"] = (temp.__dict__.values())

    headers = ["Info", "Value", "Unit"]
    return headers, wireshark_statics

def general_mitm_statics (lst_flows:Dict[str, Flow], lst_initiated_time:Dict[str, session]):
    mitm_statics = {}

    # Initiated requests
    number_of_initiated_connection = len(lst_initiated_time)
    # mitm_statics["number_of_initiated_connection"] = ['<a href="mitmFull.html"> Number of initiated connection </a>', number_of_initiated_connection, "connection"]

    # number of requests
    number_of_requests = len(lst_flows)
    mitm_statics["number_of_requests"] = ['<a href="mitmFull.html"> Number of Flows </a>', number_of_requests, "request"]

    # number of get, post, and other type request
    number_of_get_requests, number_of_post_requests, number_of_other_requests = get_number_of_get_requests(lst_flows)
    mitm_statics["number_of_get_requests"] = ['<a href="mitmGET.html"> Number of GET requests </a>', number_of_get_requests, "request"]
    mitm_statics["number_of_post_requests"] = ['<a href="mitmPOST.html"> Number of POST requests </a>', number_of_post_requests, "request"]
    mitm_statics["number_of_other_requests"] = ['<a href="mitmOTHER.html"> Number of OTHER requests </a>', number_of_other_requests, "request"]

    # content_type = classify_content_type(lst_flows)
    # status_code = classify_status_code(lst_flows)
    headers = ["Info", "Value", "Unit"]

    return headers, mitm_statics


def general_player_staticss(lst_players:Dict[int, Player]):
    headers = ["Info", "Value", "Unit"]
    players = {}
    player_number = 0
    for player in lst_players:
        player_statics = {}

        # Read Player Events
        # QoE metrics
        quality_changes = -1
        audio_rebuffering = 0
        video_rebuffering = 0
        pause_time = 0
        stop_time = 0
        play_time = 0
        video_playing_duration = 0

        for j in lst_players[player].events:
            if j.key=="origin_url":
                origin_url = j.value
                continue
            if j.key=="frame_url":
                frame_url = j.value
                continue
            if j.key=="url":
                url = j.value
                continue
            if j.key=="event":
                if j.value=="PLAY":
                    play_time = str(format(float(j.time)/1000, '.6f'))
                    continue
            if j.key=="event":
                if j.value=="PAUSE":
                    pause_time = str(format(float(j.time)/1000, '.6f'))
                    continue
            if j.key=="event":
                if j.value=="WEBMEDIAPLAYER_DESTROYED":
                    stop_time = str(format(float(j.time)/1000, '.6f'))
                    continue
            if j.key=="pipeline_state":
                if j.value=="kStopping":
                    if stop_time==0:
                        stop_time = str(format(float(j.time)/1000, '.6f'))
                continue
            if j.key=="pipeline_state":
                if j.value=="kStopped":
                    if stop_time==0:
                        stop_time = str(format(float(j.time)/1000, '.6f'))
                continue
            if j.key=="audio_buffering_state":
                if j.value=="BUFFERING_HAVE_NOTHING":
                    audio_rebuffering +=1
                    continue
            if j.key=="video_buffering_state":
                if j.value=="BUFFERING_HAVE_NOTHING":
                    video_rebuffering +=1
                    continue
            if j.key=="height":
                quality_changes +=1
                continue

            if float(pause_time)>0:
                video_playing_duration=str(float(pause_time) - float(play_time))
            elif float(stop_time)>0:
                video_playing_duration=str(float(stop_time)-float(play_time))
            else:
                video_playing_duration = "Not Available"


        title = lst_players[player].frame_title
        audio_codec_name = lst_players[player].audio_codec_name
        video_codec_name = lst_players[player].video_codec_name

        height = lst_players[player].height
        width = lst_players[player].width
        duration = lst_players[player].duration


        player_statics["title"] = ["Title", title, "-"]
        player_statics["Original URL"] = ["Origin URL", ('<a href="%s">%s</a>')%(origin_url, origin_url), ""]
        player_statics["Frame URL"] = ["Frame URL", ('<a href="%s">%s</a>')%(frame_url, frame_url), ""]
        player_statics["Streaming URL"] = ["Streaming URL", ('<a href="%s">%s</a>')%(url, url), ""]
        player_statics["audio_codec_name"] = ["Audio Codec", audio_codec_name, "-"]
        player_statics["video_codec_name"] = ["Video Codec", video_codec_name, "-"]
        player_statics["First Resolution"] = ["First Resolution (Height x Width)", str(height) + 'x' + str(width), "px"]
        # player_statics["height"] = ["Height", height, "px"]
        # player_statics["width"] = ["Width", width, "px"]
        player_statics["Video Duration"] = ["Video Duration", duration, "Sec"]
        player_statics["Video Playing Duration"] = ["Video Playing Duration", video_playing_duration, "Sec"]
        player_statics["Pause Time"] = ["Pause Time", pause_time, "Sec"]
        player_statics["Stop Time"] = ["Stop Time", stop_time, "Sec"]

        player_statics["QoE Metrics"] = ["<b>QoE Metrics</b>", "", ""]
        player_statics["Play Start Time"] = ["Play Start Time", play_time, "Sec"]
        player_statics["Audio Rebuffering"] = ["Audio Rebuffering", str(audio_rebuffering) + ' times', ""]
        player_statics["Video Rebuffering"] = ["Video Rebuffering", str(video_rebuffering)+ ' times', ""]
        player_statics["Quality Switches"] = ["Quality Switches", str(quality_changes)+ ' times', ""]


        player_number+=1
        players[player_number] = player_statics
    return headers, players

def general_comparison_statics (first_lst_sent_packets: Dict[str, Packet], first_lst_received_packets: Dict[str, Packet],
                                second_lst_sent_packets: Dict[str, Packet], second_lst_received_packets: Dict[str, Packet],
                                first_lst_flows:Dict[str, Flow], second_lst_flows:Dict[str, Flow],
                                first_lst_player:Dict[str, Player], second_lst_player:Dict[str, Player]):
    # save all log in comparison_statics
    comparison_statics:Dict[str, Static] = {}

    # export info from Wireshark 1 and Wireshark 2

    total_received_bytes_first= get_total_bytes(first_lst_received_packets)  # Total bytesroger
    total_received_bytes_second = get_total_bytes(second_lst_received_packets)  # Total bytes

    total_sent_bytes_first= get_total_bytes(first_lst_sent_packets)  # Total bytes
    total_sent_bytes_second = get_total_bytes(second_lst_sent_packets)  # Total bytes

    first_first_packet, first_last_packet = find_first_last_packet(first_lst_sent_packets, first_lst_received_packets)
    second_first_packet, second_last_packet = find_first_last_packet(second_lst_sent_packets, second_lst_received_packets)
    first_duration = find_duration(first_lst_sent_packets, first_lst_received_packets)
    second_duration = find_duration(second_lst_sent_packets, second_lst_received_packets)

    first_bit_rate = Decimal(total_received_bytes_first*8) / first_duration  # Data bit rate (bits/sec)
    second_bit_rate = Decimal(total_received_bytes_second*8) / second_duration  # Data bit rate (bits/sec)
    # Expert info From Palyer 1 and 2
    # Expert info From Palyer 1 and 2
    quality_changes_first = -1
    quality_changes_second = -1
    audio_rebuffering_first = 0
    audio_rebuffering_second = 0
    video_rebuffering_first = 0
    video_rebuffering_second = 0
    pause_time_first = 0
    pause_time_second = 0
    stop_time_first = 0
    stop_time_second = 0
    play_time_first = 0
    play_time_second = 0

    for player in first_lst_player:
        for j in first_lst_player[player].events:
            if j.key=="origin_url":
                origin_url_first = j.value
                continue
            if j.key=="frame_url":
                frame_url_first = j.value
                continue
            if j.key=="url":
                url_first = j.value
                continue
            if j.key=="event":
                if j.value=="PLAY":
                    play_time_first = str(format(float(j.time)/1000, '.6f'))
                    continue
            if j.key=="event":
                if j.value=="PAUSE":
                    pause_time_first = str(format(float(j.time)/1000, '.6f'))
                    continue
            if j.key=="event":
                if j.value=="WEBMEDIAPLAYER_DESTROYED":
                    stop_time_first = str(format(float(j.time)/1000, '.6f'))
                    continue
            if j.key=="audio_buffering_state":
                if j.value=="BUFFERING_HAVE_NOTHING":
                    audio_rebuffering_first +=1
                    continue
            if j.key=="video_buffering_state":
                if j.value=="BUFFERING_HAVE_NOTHING":
                    video_rebuffering_first +=1
                    continue
            if j.key=="height":
                quality_changes_first +=1
                continue
            video_playing_duration = "Not Available"
            video_playing_duration_first = ""
            if float(pause_time_first)>0:
                video_playing_duration_first=str(float(pause_time_first) - float(play_time_first))
            if float(stop_time_first)>0:
                video_playing_duration_first=str(float(stop_time_first)-float(play_time_first))

    for player in second_lst_player:
        for j in second_lst_player[player].events:
            if j.key=="origin_url":
                origin_url_second = j.value
                continue
            if j.key=="frame_url":
                frame_url_second = j.value
                continue
            if j.key=="url":
                url_second = j.value
                continue
            if j.key=="event":
                if j.value=="PLAY":
                    play_time_second = str(format(float(j.time)/1000, '.6f'))
                    continue
            if j.key=="event":
                if j.value=="PAUSE":
                    pause_time_second = str(format(float(j.time)/1000, '.6f'))
                    continue
            if j.key=="event":
                if j.value=="WEBMEDIAPLAYER_DESTROYED":
                    stop_time_second = str(format(float(j.time)/1000, '.6f'))
                    continue
            if j.key=="audio_buffering_state":
                if j.value=="BUFFERING_HAVE_NOTHING":
                    audio_rebuffering_second +=1
                    continue
            if j.key=="video_buffering_state":
                if j.value=="BUFFERING_HAVE_NOTHING":
                    video_rebuffering_second +=1
                    continue
            if j.key=="height":
                quality_changes_second +=1
                continue
            video_playing_duration_second = "Not Available"
            if float(pause_time_second)>0:
                video_playing_duration_second=str(float(pause_time_second) - float(play_time_second))
            if float(stop_time_second)>0:
                video_playing_duration_second=str(float(stop_time_second)-float(play_time_second))


    '''
    to do
    currect this section for all flows.
    '''
    player=1
    # print(first_lst_player[player].frame_title)
    title_first = str(first_lst_player[player].frame_title)
    audio_codec_name_first = first_lst_player[player].audio_codec_name
    video_codec_name_first = first_lst_player[player].video_codec_name
    height_first = first_lst_player[player].height
    width_first = first_lst_player[player].width
    duration_first = first_lst_player[player].duration

    title_second = second_lst_player[player].frame_title
    audio_codec_name_second = second_lst_player[player].audio_codec_name
    video_codec_name_second = second_lst_player[player].video_codec_name
    height_second = second_lst_player[player].height
    width_second = second_lst_player[player].width
    duration_second = second_lst_player[player].duration

    comparison_statics["title"] = [title_first, title_second, "-"]
    comparison_statics["Original URL"] = [('<a href="%s">%s</a>')%(origin_url_first, origin_url_first),('<a href="%s">%s</a>')%(origin_url_second, origin_url_second), ""]
    comparison_statics["Frame URL"] = [('<a href="%s">%s</a>')%(frame_url_first, frame_url_first), ('<a href="%s">%s</a>')%(frame_url_second, frame_url_second), ""]
    comparison_statics["video_codec_name"] = [video_codec_name_first, video_codec_name_second, "-"]
    comparison_statics["audio_codec_name"] = [audio_codec_name_first, audio_codec_name_second, "-"]
    comparison_statics["First Resolution (Height x Width)"] = [str(height_first) + '&times;' + str(width_first) + ' px &times; px', str(height_second) + '&times;' + str(width_second) + ' px &times; px', "px x px"]
    comparison_statics["Video Duration"] = [str(duration_first) + " sec", str(duration_second) + " sec", "Sec"]
    comparison_statics["Video Playing Duration"] = [str(video_playing_duration_first) + " sec", str(video_playing_duration_second) + " sec", "Sec"]
    comparison_statics["Traffic Capturing Duration"] = [str(format((first_duration), '.2f')) + " sec", str(format((second_duration), '.2f'))+ " sec", "sec"]
    comparison_statics["Sent Packets"] = [len(first_lst_sent_packets), len(second_lst_sent_packets), "Packet"]
    comparison_statics["Sent Packet Rate"] = [str(format((Decimal(len(first_lst_sent_packets)) / first_duration), '.2f')) + "packet/sec",
                                              str(format((Decimal(len(second_lst_sent_packets)) / second_duration), '.2f'))+ "packet/sec",
                                                  "Packets/Sec"]
    comparison_statics["Received Packets"] = [len(first_lst_received_packets), len(second_lst_received_packets), "Packet"]
    comparison_statics["Received Packet Rate"] = [str(format((Decimal(len(first_lst_received_packets)) / first_duration), '.2f')) + " packet/sec",
                                                  str(format((Decimal(len(second_lst_received_packets)) / second_duration), '.2f')) + " packet/sec",
                                                  "Packets/Sec"]
    comparison_statics["Sent Bytes"] = [size(total_sent_bytes_first) + ' (%s)' % (str(total_sent_bytes_first)),
                                            size(total_sent_bytes_second) + ' (%s)' % (str(total_sent_bytes_second)), "byte"]
    comparison_statics["Received Bytes"] = [size(total_received_bytes_first) + ' (%s)' % (str(total_received_bytes_first)),
                                            size(total_received_bytes_second) + ' (%s)' % (str(total_received_bytes_second)), "byte"]
    comparison_statics["Throughput"] = [str(size(first_bit_rate))+ "bit/sec", str(size(second_bit_rate))+ "bit/sec", "Bits/Sec"]
    comparison_statics["Number of Flows"] = [len(first_lst_flows), len(second_lst_flows), "Flow"]


    comparison_statics["<b>QoE Metrics</b>"] = ["", "", ""]
    comparison_statics["Play Start Time"] = [str(play_time_first) + "sec", str(play_time_second) + "sec", "Sec"]
    comparison_statics["Audio Rebuffering Events"] = [str(audio_rebuffering_first) + ' times', str(audio_rebuffering_second) + ' times', ""]
    comparison_statics["Video Rebuffering Events"] = [str(video_rebuffering_first)+ ' times', str(video_rebuffering_second)+ ' times', ""]
    comparison_statics["Quality Switches"] = [str(quality_changes_first)+ ' times', str(quality_changes_second)+ ' times', ""]

    headers = ["Info", "Network Traffic #1", "Network Traffic #2", "Unit"]
    return headers, comparison_statics

    # Initiated requests
    number_of_initiated_connection = len(lst_initiated_time)
    # mitm_statics["number_of_initiated_connection"] = ['<a href="mitmFull.html"> Number of initiated connection </a>', number_of_initiated_connection, "connection"]

    # number of requests
    number_of_requests = len(lst_flows)
    comparison_statics["number_of_requests"] = ['<a href="mitmFull.html"> Number of Flows </a>', number_of_requests, "request"]

    # number of get, post, and other type request
    number_of_get_requests, number_of_post_requests, number_of_other_requests = get_number_of_get_requests(lst_flows)
    comparison_statics["number_of_get_requests"] = ['<a href="mitmGET.html"> Number of GET requests </a>', number_of_get_requests, "request"]
    comparison_statics["number_of_post_requests"] = ['<a href="mitmPOST.html"> Number of POST requests </a>', number_of_post_requests, "request"]
    comparison_statics["number_of_other_requests"] = ['<a href="mitmOTHER.html"> Number of OTHER requests </a>', number_of_other_requests, "request"]

    # content_type = classify_content_type(lst_flows)
    # status_code = classify_status_code(lst_flows)
    headers = ["Info", "Value", "Unit"]

    return headers, comparison_statics

def find_first_last_packet(lst_sent_packets:Dict[str, Packet], lst_received_packets:Dict[str, Packet]):
    first=-1
    last = -1

    for p in lst_sent_packets:
        if first==-1:
            first = Decimal(lst_sent_packets[p].time_epoch)
        last = Decimal(lst_sent_packets[p].time_epoch)

    temp_first = -1
    temp_last = -1
    for p in lst_received_packets:
        if temp_first==-1:
            temp_first = Decimal(lst_received_packets[p].time_epoch)
            if temp_first<first:
                first=temp_first
        temp_last = Decimal(lst_received_packets[p].time_epoch)
    if temp_last<last:
        last = temp_last
    return first, last

def find_duration(lst_sent_packets:Dict[str, Packet], lst_received_packets:Dict[str, Packet]):
    first_time = 0
    last_time = 0
    first=-1
    last = -1
    for p in lst_sent_packets:
        if first==-1:
            first = int(lst_sent_packets[p].frame_number)
            first_time = lst_sent_packets[p].frame_time_relative
        last = int(lst_sent_packets[p].frame_number)
        last_time = lst_sent_packets[p].frame_time_relative

    temp_first = -1
    temp_last = -1
    for p in lst_received_packets:
        if temp_first==-1:
            temp_first = int(lst_received_packets[p].frame_number)
            if temp_first<first:
                first=temp_first
                first_time = lst_received_packets[p].frame_time_relative
        temp_last = int(lst_received_packets[p].frame_number)
    if temp_last<last:
        last = temp_last
        last_time = lst_received_packets[p].frame_time_relative

    duration = Decimal(last_time) - Decimal(first_time)  # Duration (seconds)

    return duration


def get_wireshark_graphs():
    txt = '''
            <img src="sent_bytes_pdf.jpg" width="33%"> <img src="received_bytes_pdf.jpg" width="33%"><img src="sent_received_bytes_pdf.jpg" width="33%">
            <br>
            <img src="sent_packets_pdf.jpg" width="33%"> <img src="received_packets_pdf.jpg" width="33%"><img src="sent_received_packets_pdf.jpg" width="33%">
            <br>
            <img src="sent_bytes_cdf.jpg" width="33%"> <img src="received_bytes_cdf.jpg" width="33%"><img src="sent_received_bytes_cdf.jpg" width="33%">
            <br>
            <img src="sent_packets_cdf.jpg" width="33%"> <img src="received_packets_cdf.jpg" width="33%"><img src="sent_received_packets_cdf.jpg" width="33%">
    '''
    return txt
def get_mitm_graphs(lstFlows:Dict[str, Flow]):
    txt = '''
    <img src="flow_data_type.jpg" width="40%" vspace="20"> <img src="flow_data_size.jpg" width="40%" vspace="20">
    <br>
    <img src="flow_time.jpg" width="40%"> <img src="flow_method.jpg" width="40%" vspace="20">
    <br>
    <img src="flow_cdf.jpg" width="44%">  
    '''
    return txt

def get_comparision_graphs():
    txt = '''
    <h3>Sent/Received Bytes</h3>
    <img src="sent_bytes_both.jpg" width="40%" vspace="60"> <img src="received_bytes_both.jpg" width="40%" vspace="60">
    <br>
    <h3>Sent/Received Packets</h3>
    <img src="sent_packets_both.jpg" width="40%" vspace="60"> <img src="received_packets_both.jpg" width="40%" vspace="60">
    <br>
    <h3>Generated Flows</h3>
    <img src="flow_both.jpg" width="44%">  
    <br>
    <h3>Flow Data Sizes</h3>
    <img src="flow_data_size1.jpg" width="40%" vspace="60"> <img src="flow_data_size2.jpg" width="40%" vspace="60">
    <br>
    <h3>Flow Data Types</h3>
    <img src="flow_data_type1.jpg" width="40%" vspace="60"> <img src="flow_data_type2.jpg" width="40%" vspace="60">
    <br> 
    <h3>Flow Methods</h3>
    <img src="flow_method1.jpg" width="33%" vspace="100"><img src="flow_method2.jpg" width="33%" vspace="100">
    '''
    return txt


'''
Here we draw CDF and PDF graphs for packets.
The graphs will be saved as a jpg pictures.
The name of saved files will be:
received_packets_cdf.jpg    //CDF Received Packets
'''
def create_charts(lst_packets:Dict[str, Packet], lst_sent_packets:Dict[str, Packet], lst_received_packets:Dict[str, Packet], lst_flows:Dict[str, Flow]):
    '''
    In this function we create statsitic charts for sent/received packets, flows
    '''
    # font
    font = {'size': 12, 'weight': 'bold'}
    plt.rc('font', **font)
    plt.rcParams["figure.figsize"] = (6, 4)

    '''
    Sent/Received Packet Graphs
    '''
    # CDF received bytes per Sec
    last_sec = 0
    for p in lst_received_packets:
        last_sec = lst_received_packets[p].frame_time_relative

    lst_received_bytes_per_sec = {}  # {<sec, bytes in the sec>}
    for i in range(int(float(last_sec))+1):
        lst_received_bytes_per_sec[i] = 0

    for p in lst_received_packets:
        sec = int(float(lst_received_packets[p].frame_time_relative))
        if sec in lst_received_bytes_per_sec:
            lst_received_bytes_per_sec[sec] += int(float(lst_received_packets[p].frame_len))
        else:
            lst_received_bytes_per_sec[sec] = int(float(lst_received_packets[p].frame_len))

    lst_pdf_bytes_received_per_sec = []
    for i in lst_received_bytes_per_sec:
        lst_pdf_bytes_received_per_sec.append(lst_received_bytes_per_sec[i])

    # CDF Plot (Packets per Second)
    try:
        sum = np.sum(lst_pdf_bytes_received_per_sec)
        cum_lst_cdf = np.cumsum(lst_pdf_bytes_received_per_sec)
        cum_lst_cdf = cum_lst_cdf / sum
        cdf_bytes_received = cum_lst_cdf
        plt.title("CDF - Bytes Received")
        plt.ylabel("CDF (Byte)", fontsize=16, labelpad=20)
        plt.xlabel("Time (Sec)", fontsize=16, labelpad=20)
        plt.plot(range(len(cdf_bytes_received)), cdf_bytes_received, color='blue', label="Received")
        plt.legend(loc='upper left')
        plt.tight_layout()
        plt.savefig(str(os.getcwd()) + "/output/received_bytes_cdf.jpg")
        plt.close()

        # Received Bytes per Second
        pdf_bytes_received = lst_pdf_bytes_received_per_sec
        plt.title("Bytes Received per Second")
        plt.ylabel("Byte", fontsize=16, labelpad=20)
        plt.xlabel("Time (Sec)", fontsize=16, labelpad=20)
        plt.plot(range(len(pdf_bytes_received)), pdf_bytes_received, color='blue', label="Received")
        plt.legend(loc='upper right')
        plt.tight_layout()
        plt.savefig(str(os.getcwd()) + "/output/received_bytes_pdf.jpg")
        plt.close()

    except:
        pass

    # sort packets in time second
    lst_pdf_packets_received_per_sec = {}  # {<sec, number of packets in the sec>}
    for i in range(int(float(last_sec))+1):
        lst_pdf_packets_received_per_sec[i] = 0

    for p in lst_received_packets:
        sec = int(float(lst_received_packets[p].frame_time_relative))
        if sec in lst_pdf_packets_received_per_sec:
            lst_pdf_packets_received_per_sec[sec] += 1
        else:
            lst_pdf_packets_received_per_sec[sec] = 1

    lst_pdf_packets_received = []
    for i in lst_pdf_packets_received_per_sec:
        lst_pdf_packets_received.append(lst_pdf_packets_received_per_sec[i])

    try:
        # CDF Plot (Packets per Second)
        sum = np.sum(lst_pdf_packets_received)
        cum_lst_cdf = np.cumsum(lst_pdf_packets_received)
        cum_lst_cdf = cum_lst_cdf / sum
        cdf_packets_received = cum_lst_cdf
        plt.title("CDF - Packets Received")
        plt.ylabel("CDF (Packet)", fontsize=16, labelpad=20)
        plt.xlabel("Time (Sec)", fontsize=16, labelpad=20)
        plt.plot(range(len(cdf_packets_received)), cdf_packets_received, color='blue', label="Received")
        plt.legend(loc='upper left')
        plt.tight_layout()
        plt.savefig(str(os.getcwd()) + "/output/received_packets_cdf.jpg")
        plt.close()
    except:
        pass

    # PDf Received Packets (Packets per Second)
    #     lst_pdf = lst_cdf / sum
    try:
        pdf_packets_received = lst_pdf_packets_received
        plt.title("Packets Received per Second")
        plt.ylabel("Packet", fontsize=16, labelpad=20)
        plt.xlabel("Time (Sec)", fontsize=16, labelpad=20)
        plt.plot(range(len(pdf_packets_received)), pdf_packets_received, color='blue', label="Received")
        plt.legend(loc='upper right')
        plt.tight_layout()
        plt.savefig(str(os.getcwd()) + "/output/received_packets_pdf.jpg")
        plt.close()
    except:
        pass

    # CDF sent bytes per Sec
    for p in lst_sent_packets:
        last_sec = lst_sent_packets[p].frame_time_relative

    lst_sent_bytes_per_sec = {}  # {<sec, bytes in the sec>}
    for i in range(int(float(last_sec))+1):
        lst_sent_bytes_per_sec[i] = 0

    for p in lst_sent_packets:
        sec = int(float(lst_sent_packets[p].frame_time_relative))
        if sec in lst_sent_bytes_per_sec:
            lst_sent_bytes_per_sec[sec] += int(float(lst_sent_packets[p].frame_len))
        else:
            lst_sent_bytes_per_sec[sec] = int(float(lst_sent_packets[p].frame_len))

    lst_pdf_bytes_sent_per_sec = []
    for i in lst_sent_bytes_per_sec:
        lst_pdf_bytes_sent_per_sec.append(lst_sent_bytes_per_sec[i])

    # CDF Plot (Packets per Second)
    try:
        sum = np.sum(lst_pdf_bytes_sent_per_sec)
        cum_lst_cdf = np.cumsum(lst_pdf_bytes_sent_per_sec)
        cum_lst_cdf = cum_lst_cdf / sum
        cdf_bytes_sent = cum_lst_cdf
        plt.title("CDF - Bytes Sent")
        plt.ylabel("CDF (Byte)", fontsize=16, labelpad=20)
        plt.xlabel("Time (Sec)", fontsize=16, labelpad=20)
        plt.plot(range(len(cdf_bytes_sent)), cdf_bytes_sent, color='red', label="Sent")
        plt.legend(loc='upper left')
        plt.tight_layout()
        plt.savefig(str(os.getcwd()) + "/output/sent_bytes_cdf.jpg")
        plt.close()

        # sent Bytes per Second
        pdf_bytes_sent = lst_pdf_bytes_sent_per_sec
        plt.title("Bytes Sent per Second")
        plt.ylabel("Byte", fontsize=16, labelpad=20)
        plt.xlabel("Time (Sec)", fontsize=16, labelpad=20)
        plt.plot(range(len(pdf_bytes_sent)), pdf_bytes_sent, color='red', label="Sent")
        plt.legend(loc='upper right')
        plt.tight_layout()
        plt.savefig(str(os.getcwd()) + "/output/sent_bytes_pdf.jpg")
        plt.close()
    except:
        pass

    # sort packets in time second
    lst_pdf_packets_sent_per_sec = {}  # {<sec, number of packets in the sec>}
    for i in range(int(float(last_sec))+1):
        lst_pdf_packets_sent_per_sec[i] = 0

    for p in lst_sent_packets:
        sec = int(float(lst_sent_packets[p].frame_time_relative))
        if sec in lst_pdf_packets_sent_per_sec:
            lst_pdf_packets_sent_per_sec[sec] += 1
        else:
            lst_pdf_packets_sent_per_sec[sec] = 1

    lst_pdf_packets_sent = []
    for i in lst_pdf_packets_sent_per_sec:
        lst_pdf_packets_sent.append(lst_pdf_packets_sent_per_sec[i])

    # CDF Plot (Packets per Second)
    try:
        sum = np.sum(lst_pdf_packets_sent)
        cum_lst_cdf = np.cumsum(lst_pdf_packets_sent)
        cum_lst_cdf = cum_lst_cdf / sum
        cdf_packets_sent = cum_lst_cdf
        plt.title("CDF - Packets Sent")
        plt.ylabel("CDF (Packet)", fontsize=16, labelpad=20)
        plt.xlabel("Time (Sec)", fontsize=16, labelpad=20)
        plt.plot(range(len(cdf_packets_sent)), cdf_packets_sent, color='red', label="Sent")
        plt.legend(loc='upper left')
        plt.tight_layout()
        plt.savefig(str(os.getcwd()) + "/output/sent_packets_cdf.jpg")
        plt.close()

        # PDf sent Packets (Packets per Second)
        #     lst_pdf = lst_cdf / sum
        pdf_packets_sent = lst_pdf_packets_sent
        plt.title("Packets Sent per Second")
        plt.ylabel("Packet", fontsize=16, labelpad=20)
        plt.xlabel("Time (Sec)", fontsize=16, labelpad=20)
        plt.plot(range(len(pdf_packets_sent)), pdf_packets_sent, color='red', label="Sent")
        plt.legend(loc='upper right')
        plt.tight_layout()
        plt.savefig(str(os.getcwd()) + "/output/sent_packets_pdf.jpg")
        plt.close()

        # Charts for both Sent/Received Packets
        plt.title("CDF - Bytes Sent/Received")
        plt.ylabel("CDF (Bytes)", fontsize=16, labelpad=20)
        plt.xlabel("Time (Sec)", fontsize=16, labelpad=20)
        plt.plot(range(len(cdf_bytes_received)), cdf_bytes_received, color='blue', label = "Received")
        plt.plot(range(len(cdf_bytes_sent)), cdf_bytes_sent, color='red', label="Sent")
        plt.legend(loc='upper left')
        plt.tight_layout()
        plt.savefig(str(os.getcwd()) + "/output/sent_received_bytes_cdf.jpg")
        # plt.show()
        plt.close()

        plt.title("Sent/Received Bytes per Second")
        plt.ylabel("Byte", fontsize=16, labelpad=30)
        plt.xlabel("Time (Sec)", fontsize=16, labelpad=30)
        plt.plot(range(len(pdf_bytes_received)), pdf_bytes_received, color='blue', label="Received")
        plt.plot(range(len(pdf_bytes_sent)), pdf_bytes_sent, color='red', label="Sent")
        plt.legend(loc='upper right')
        plt.savefig(str(os.getcwd()) + "/output/sent_received_bytes_pdf.jpg")
        plt.close()

        plt.title("CDF - Packets Sent/Received")
        plt.ylabel("CDF (Packet)", fontsize=16, labelpad=20)
        plt.xlabel("Time (Sec)", fontsize=16, labelpad=20)
        plt.plot(range(len(cdf_packets_received)), cdf_packets_received, color='blue', label = "Received")
        plt.plot(range(len(cdf_packets_sent)), cdf_packets_sent, color='red', label="Sent")
        plt.legend(loc='upper left')
        plt.tight_layout()
        plt.savefig(str(os.getcwd()) + "/output/sent_received_packets_cdf.jpg")
        # plt.show()
        plt.close()

        plt.title("Sent/Received Packets per Second")
        plt.ylabel("Packet", fontsize=16, labelpad=20)
        plt.xlabel("Time (Sec)", fontsize=16, labelpad=20)
        plt.plot(range(len(pdf_packets_received)), pdf_packets_received, color='blue', label="Received")
        plt.plot(range(len(pdf_packets_sent)), pdf_packets_sent, color='red', label="Sent")
        plt.legend(loc='upper right')
        plt.savefig(str(os.getcwd()) + "/output/sent_received_packets_pdf.jpg")
        plt.close()
    except:
        pass

    '''
    Flow Traffic Charts
    Here we draw generated flows charts. They are:
    2. flow_time.jpg --> A line chart of flows
    3. flow_time_cdf.jpg --> A line chart of CDF of flows
    4. flow_files.jpg --> A Pie Chart of the data types of flows
    1. flows_types.jpg --> A pie chart of Flow types

    '''
    # 2. Flow per Sec
    # Initialization
    lst_sec_flow = {} # {<sec, number of flows in that sec>}

    for f in lst_flows:
        fisrt_flow_time = float(lst_flows[f].request_timestamp_start)
        break

    for f in lst_flows:
        last_flow_time = lst_flows[f].request_timestamp_start

    for i in range(int(float(last_flow_time) - (fisrt_flow_time))):
        lst_sec_flow[i]=0

    for f in lst_flows:
        sec = int(float(lst_flows[f].request_timestamp_start) - fisrt_flow_time)
        if sec in lst_sec_flow:
            lst_sec_flow[sec] += 1
        else:
            lst_sec_flow[sec] = 1
    lst_flow_cdf = []

    for i in lst_sec_flow:
        lst_flow_cdf.append(lst_sec_flow[i])

    # 1. CDF Flow per Second
    try:
        sum = np.sum(lst_flow_cdf)
        cum_lst_flow_cdf = np.cumsum(lst_flow_cdf)
        cum_lst_flow_cdf = cum_lst_flow_cdf / sum
        plt.title("CDF - Generated Flows")
        plt.ylabel("CDF (Flow)", fontsize=16, labelpad=20)
        plt.xlabel("Time (Sec)", fontsize=16, labelpad=20)
        plt.plot(range(len(cum_lst_flow_cdf)), cum_lst_flow_cdf, color='green', label="Flow")
        plt.legend(loc='upper left')
        plt.tight_layout()
        plt.savefig(str(os.getcwd()) + "/output/flow_cdf.jpg")
        plt.close()

        # 2. Flow CDF
        lst_flow_pdf = lst_flow_cdf
        plt.title("Flows Generated per Second")
        plt.ylabel("Flow", fontsize=16, labelpad=20)
        plt.xlabel("Time (Sec)", fontsize=16, labelpad=20)
        plt.plot(range(len(lst_flow_pdf)), lst_flow_pdf, color='green', label="Flow")
        plt.legend(loc='upper right')
        plt.tight_layout()
        plt.savefig(str(os.getcwd()) + "/output/flow_time.jpg")
        # plt.show()
        plt.close()
    except:
        pass

    # 3. Flow Types - Pie Chart
    labels = ["GET", "POST", "Others"]
    sizes = [0, 0, 0]
    for f in lst_flows:
        if lst_flows[f].method=="GET":
            sizes[0] +=1
        elif lst_flows[f].method == "POST":
            sizes[1] +=1
        else:
            sizes[2] +=1
    for lbl in range(len(labels)):
        labels[lbl] += (": " + str(sizes[lbl]))
    fig, ax = plt.subplots(figsize=(6, 4), subplot_kw=dict(aspect="equal"))
    ax.pie(sizes, labels=labels)
    ax.set_title("Flow Methods", fontsize=16)
    plt.tight_layout()
    plt.savefig(str(os.getcwd()) + "/output/flow_method.jpg")
    plt.close()

    # 4. Flow Data Type - Pie Chart
    labels = ["video", "audio", "image", "text/html", "javascript", "json", "other"]
    sizes = [0, 0, 0, 0, 0, 0, 0]
    for f in lst_flows:
        temp = find_content_type(lst_flows[f].content_type)
        if temp == "video":
            sizes[0] +=1
        elif temp == "audio":
            sizes[1] +=1
        elif temp == "image":
            sizes[2] +=1
        elif temp == "text/html":
            sizes[3] +=1
        elif temp == "javascript":
            sizes[4] +=1
        elif temp == "json":
            sizes[5] +=1
        else:
            sizes[6] +=1
    for lbl in range(len(labels)):
        labels[lbl] += (": " + str(sizes[lbl]))
    fig, ax = plt.subplots(figsize=(6, 4), subplot_kw=dict(aspect="equal"))
    autotexts = ax.pie(sizes, labels=labels)
    ax.set_title("Flow's Data Type", fontsize=16)
    # plt.setp(autotexts, size=8, weight="bold")
    plt.tight_layout()
    plt.savefig(str(os.getcwd()) + "/output/flow_data_type.jpg")
    plt.close()

    # 5. Flow Data Size - Pie Chart
    labels = ["video", "audio", "image", "text/html", "javascript", "json", "other"]
    sizes = [0, 0, 0, 0, 0, 0, 0]
    for f in lst_flows:
        temp = find_content_type(lst_flows[f].content_type)
        if temp == "video":
            try:
                sizes[0] +=int(lst_flows[f].content_length)
            except:
                pass
        elif temp == "audio":
            try:
                sizes[1] +=int(lst_flows[f].content_length)
            except:
                pass
        elif temp == "image":
            try:
                sizes[2] +=int(lst_flows[f].content_length)
            except:
                pass
        elif temp == "text/html":
            try:
                sizes[3] +=int(lst_flows[f].content_length)
            except:
                pass
        elif temp == "javascript":
            try:
                sizes[4] +=int(lst_flows[f].content_length)
            except:
                pass
        elif temp == "json":
            try:
                sizes[5] +=int(lst_flows[f].content_length)
            except:
                pass
        else:
            try:
                sizes[6] +=int(lst_flows[f].content_length)
            except:
                pass


    for lbl in range(len(labels)):
        labels[lbl] += (": " + size(sizes[lbl]))
    fig, ax = plt.subplots(figsize=(6,4), subplot_kw=dict(aspect="equal"))
    wedges, texts = ax.pie(sizes)
    ax.legend(wedges, labels,
              title="Flow Data Size",
              loc="center left",
              bbox_to_anchor=(1, 0, 0.5, 1))
    # plt.setp(autotexts, size=8, weight="bold")

    ax.set_title("Flow's Data Size", fontsize=16)
    # plt.setp(autotexts, size=8, weight="bold")
    plt.tight_layout()
    plt.savefig(str(os.getcwd()) + "/output/flow_data_size.jpg")
    plt.close()

    '''
    Ad charts
    '''
    lst_sec_ad_flow = {} # {<sec, number of flows in that sec>}
    # lst_ad_flow = {}
    # # for f in lst_flows:
    # #     if lst_flows[f].is_ad==True:
    # #         lst_ad_flow[lst_flows[f].flow_number] = f
    # # print(len(lst_ad_flow))
    # # for i in lst_ad_flow:
    # #     print(lst_flows[lst_ad_flow[i]].flow_number)
    # #     print(lst_flows[lst_ad_flow[i]].url)
    # # # exit()
    # # for f in lst_flows:
    # #     fisrt_flow_time = float(lst_flows[f].request_timestamp_start)
    # #     break
    #
    # for f in lst_flows:
    #     if lst_flows[f].is_ad==True:
    #         sec = int(float(lst_flows[f].request_timestamp_start) - fisrt_flow_time)
    #         if sec in lst_sec_flow:
    #             lst_sec_flow[sec] += 1
    #         else:
    #             lst_sec_flow[sec] = 1
    #     lst_flow_cdf = []
    #     for i in lst_sec_flow:
    #         lst_flow_cdf.append(lst_sec_flow[i])
    #
    # # 1. CDF Flow per Second
    # sum = np.sum(lst_flow_cdf)
    # cum_lst_flow_cdf = np.cumsum(lst_flow_cdf)
    # cum_lst_flow_cdf = cum_lst_flow_cdf / sum
    # plt.title("CDF of Flows")
    # plt.ylabel("CDF (Flow)", fontsize=16, labelpad=20)
    # plt.xlabel("Time (Sec)", fontsize=16, labelpad=20)
    # plt.plot(range(len(cum_lst_flow_cdf)), cum_lst_flow_cdf, color='green', label="Flow")
    # plt.legend(loc='upper left')
    # plt.tight_layout()
    # plt.savefig(str(os.getcwd()) + "/output/flow_cdf.jpg")
    # plt.close()
    #
    # # 2. Flow CDF
    # lst_flow_pdf = lst_flow_cdf
    # plt.title("Flows Generated per Second")
    # plt.ylabel("Flow", fontsize=16, labelpad=20)
    # plt.xlabel("Time (Sec)", fontsize=16, labelpad=20)
    # plt.plot(range(len(lst_flow_pdf)), lst_flow_pdf, color='green', label="Flow")
    # plt.legend(loc='upper right')
    # plt.tight_layout()
    # plt.savefig(str(os.getcwd()) + "/output/flow_time.jpg")
    # # plt.show()
    # plt.close()
    #
    # # 3. Flow Types - Pie Chart
    # labels = ["GET", "POST", "Others"]
    # sizes = [0, 0, 0]
    # for f in lst_flows:
    #     if lst_flows[f].is_ad==None:
    #         continue
    #     if lst_flows[f].method=="GET":
    #         sizes[0] +=1
    #     elif lst_flows[f].method == "POST":
    #         sizes[1] +=1
    #     else:
    #         sizes[2] +=1
    # for lbl in range(len(labels)):
    #     labels[lbl] += (": " + str(sizes[lbl]))
    # fig, ax = plt.subplots(figsize=(8, 6), subplot_kw=dict(aspect="equal"))
    # ax.pie(sizes, labels=labels)
    # ax.set_title("Flow Methods", fontsize=16)
    # plt.tight_layout()
    # plt.savefig(str(os.getcwd()) + "/output/flow_method.jpg")
    # plt.close()
    #
    # # 4. Flow Data Type - Pie Chart
    # labels = ["video", "audio", "image", "text/html", "javascript", "json", "other"]
    # sizes = [0, 0, 0, 0, 0, 0, 0]
    # for f in lst_flows:
    #     temp = find_content_type(lst_flows[f].content_type)
    #     if temp == "video":
    #         sizes[0] +=1
    #     elif temp == "audio":
    #         sizes[1] +=1
    #     elif temp == "image":
    #         sizes[2] +=1
    #     elif temp == "text/html":
    #         sizes[3] +=1
    #     elif temp == "javascript":
    #         sizes[4] +=1
    #     elif temp == "json":
    #         sizes[5] +=1
    #     else:
    #         sizes[6] +=1
    # for lbl in range(len(labels)):
    #     labels[lbl] += (": " + str(sizes[lbl]))
    # fig, ax = plt.subplots(figsize=(8, 6), subplot_kw=dict(aspect="equal"))
    # autotexts = ax.pie(sizes, labels=labels)
    # ax.set_title("Flow's Data Type", fontsize=16)
    # # plt.setp(autotexts, size=8, weight="bold")
    # plt.tight_layout()
    # plt.savefig(str(os.getcwd()) + "/output/flow_data_type.jpg")
    # plt.close()
    #
    # # 5. Flow Data Size - Pie Chart
    # labels = ["video", "audio", "image", "text/html", "javascript", "json", "other"]
    # sizes = [0, 0, 0, 0, 0, 0, 0]
    # for f in lst_flows:
    #     temp = find_content_type(lst_flows[f].content_type)
    #     if temp == "video":
    #         try:
    #             sizes[0] +=int(lst_flows[f].content_length)
    #         except:
    #             pass
    #     elif temp == "audio":
    #         try:
    #             sizes[1] +=int(lst_flows[f].content_length)
    #         except:
    #             pass
    #     elif temp == "image":
    #         try:
    #             sizes[2] +=int(lst_flows[f].content_length)
    #         except:
    #             pass
    #     elif temp == "text/html":
    #         try:
    #             sizes[3] +=int(lst_flows[f].content_length)
    #         except:
    #             pass
    #     elif temp == "javascript":
    #         try:
    #             sizes[4] +=int(lst_flows[f].content_length)
    #         except:
    #             pass
    #     elif temp == "json":
    #         try:
    #             sizes[5] +=int(lst_flows[f].content_length)
    #         except:
    #             pass
    #     else:
    #         try:
    #             sizes[6] +=int(lst_flows[f].content_length)
    #         except:
    #             pass
    #
    #
    # for lbl in range(len(labels)):
    #     labels[lbl] += (": " + size(sizes[lbl]))
    # fig, ax = plt.subplots(figsize=(8, 6), subplot_kw=dict(aspect="equal"))
    # wedges, texts = ax.pie(sizes)
    # ax.legend(wedges, labels,
    #           title="Flow Data Size",
    #           loc="center left",
    #           bbox_to_anchor=(1, 0, 0.5, 1))
    # # plt.setp(autotexts, size=8, weight="bold")
    #
    # ax.set_title("Flow's Data Size", fontsize=16)
    # # plt.setp(autotexts, size=8, weight="bold")
    # plt.tight_layout()
    # plt.savefig(str(os.getcwd()) + "/output/flow_data_size.jpg")
    # plt.close()





def create_charts_comparision(first_lst_sent_packets, first_lst_received_packets, second_lst_sent_packets, second_lst_received_packets, first_lst_flows, second_lst_flows, first_lst_player, second_lst_player):
    '''
    In this function we create statsitic charts for Comparision part.
    '''
    # Charts font size
    # font = {'weight' : 'bold', 'size': 16}
    font = {'size': 16}
    plt.rc('font', **font)
    plt.rcParams["figure.figsize"] = (12, 8)

    '''
    Sent / Received Packet Graphs
    '''
    # Received Packets
    lst_sec_received_first = {}  # {<sec, number of packets in the sec>}
    for p in first_lst_received_packets:
        last_sec = first_lst_received_packets[p].frame_time_relative
    for i in range(int(float(last_sec))+1):
        lst_sec_received_first[i] = 0

    for p in first_lst_received_packets:
        sec = int(float(first_lst_received_packets[p].frame_time_relative))
        if sec in lst_sec_received_first:
            lst_sec_received_first[sec] += 1
        else:
            lst_sec_received_first[sec] = 1
    lst_cdf_received_first = []
    for i in lst_sec_received_first:
        lst_cdf_received_first.append(lst_sec_received_first[i])

    lst_sec_received_second = {}  # {<sec, number of packets in the sec>}
    for p in second_lst_received_packets:
        last_sec = second_lst_received_packets[p].frame_time_relative
    for i in range(int(float(last_sec))+1):
        lst_sec_received_second[i] = 0

    for p in second_lst_received_packets:
        sec = int(float(second_lst_received_packets[p].frame_time_relative))
        if sec in lst_sec_received_second:
            lst_sec_received_second[sec] += 1
        else:
            lst_sec_received_second[sec] = 1
    lst_cdf_received_second = []
    for i in lst_sec_received_second:
        lst_cdf_received_second.append(lst_sec_received_second[i])


    try:
        plt.title("Packets Received per Second")
        plt.ylabel("Packet", fontsize=16, labelpad=20)
        plt.xlabel("Time (Sec)", fontsize=16, labelpad=20)
        plt.plot(range(len(lst_cdf_received_first)), lst_cdf_received_first, color='blue', label="First")
        plt.plot(range(len(lst_cdf_received_second)), lst_cdf_received_second, color='red', label="Second")
        plt.legend(loc='upper left')
        plt.tight_layout()
        plt.savefig(str(os.getcwd()) + "/output/received_packets_both.jpg")
        # plt.show()
        plt.close()
    except:
        pass

    # Sent Packets
    lst_sec_sent_first = {}  # {<sec, number of packets in the sec>}
    for p in first_lst_sent_packets:
        last_sec = first_lst_sent_packets[p].frame_time_relative
    for i in range(int(float(last_sec))+1):
        lst_sec_sent_first[i] = 0

    for p in first_lst_sent_packets:
        sec = int(float(first_lst_sent_packets[p].frame_time_relative))
        if sec in lst_sec_sent_first:
            lst_sec_sent_first[sec] += 1
        else:
            lst_sec_sent_first[sec] = 1
    lst_cdf_sent_first = []
    for i in lst_sec_sent_first:
        lst_cdf_sent_first.append(lst_sec_sent_first[i])

    lst_sec_sent_second = {}  # {<sec, number of packets in the sec>}
    for p in second_lst_sent_packets:
        last_sec = second_lst_sent_packets[p].frame_time_relative
    for i in range(int(float(last_sec))+1):
        lst_sec_sent_second[i] = 0

    for p in second_lst_sent_packets:
        sec = int(float(second_lst_sent_packets[p].frame_time_relative))
        if sec in lst_sec_sent_second:
            lst_sec_sent_second[sec] += 1
        else:
            lst_sec_sent_second[sec] = 1
    lst_cdf_sent_second = []
    for i in lst_sec_sent_second:
        lst_cdf_sent_second.append(lst_sec_sent_second[i])

    try:
        plt.title("Sent Packets per Second")
        plt.ylabel("Packet", fontsize=16, labelpad=20)
        plt.xlabel("Time (Sec)", fontsize=16, labelpad=20)
        plt.plot(range(len(lst_cdf_sent_first)), lst_cdf_sent_first, color='blue', label="First")
        plt.plot(range(len(lst_cdf_sent_second)), lst_cdf_sent_second, color='red', label="Second")
        plt.legend(loc='upper left')
        plt.tight_layout()
        plt.savefig(str(os.getcwd()) + "/output/sent_packets_both.jpg")
        # plt.show()
        plt.close()
    except:
        pass

    '''
    Sent/Received Bytes
    '''
    # Received Byets
    lst_bytes_received_first = {}
    for p in first_lst_received_packets:
        last_sec = first_lst_received_packets[p].frame_time_relative
    for i in range(int(float(last_sec))+1):
        lst_bytes_received_first[i] = 0

    for p in first_lst_received_packets:
        sec = int(float(first_lst_received_packets[p].frame_time_relative))
        if sec in lst_bytes_received_first:
            lst_bytes_received_first[sec] += int(float(first_lst_received_packets[p].frame_len))
        else:
            lst_bytes_received_first[sec] = int(float(first_lst_received_packets[p].frame_len))
    lst_pdf_received_first = []
    for i in lst_bytes_received_first:
        lst_pdf_received_first.append(lst_bytes_received_first[i])

    lst_byte_received_second = {}  # {<sec, number of packets in the sec>}
    for p in second_lst_received_packets:
        last_sec = second_lst_received_packets[p].frame_time_relative
    for i in range(int(float(last_sec))+1):
        lst_byte_received_second[i] = 0
    for p in second_lst_received_packets:
        sec = int(float(second_lst_received_packets[p].frame_time_relative))
        if sec in lst_byte_received_second:
            lst_byte_received_second[sec] += int(float(second_lst_received_packets[p].frame_len))
        else:
            lst_byte_received_second[sec] = int(float(second_lst_received_packets[p].frame_len))
    lst_pdf_received_second = []
    for i in lst_byte_received_second:
        lst_pdf_received_second.append(lst_byte_received_second[i])

    try:
        plt.title("Bytes Received per Second")
        plt.ylabel("Byte", fontsize=16, labelpad=20)
        plt.xlabel("Time (Sec)", fontsize=16, labelpad=20)
        plt.plot(range(len(lst_pdf_received_first)), lst_pdf_received_first, color='blue', label="Traffic 1")
        plt.plot(range(len(lst_pdf_received_second)), lst_pdf_received_second, color='red', label="Traffic 2")
        plt.legend(loc='upper left')
        plt.tight_layout()
        plt.savefig(str(os.getcwd()) + "/output/received_bytes_both.jpg")
        # plt.show()
        plt.close()
    except:
        pass


    # Sent Byets
    lst_bytes_sent_first = {}
    for p in first_lst_sent_packets:
        last_sec = first_lst_sent_packets[p].frame_time_relative
    for i in range(int(float(last_sec))+1):
        lst_bytes_sent_first[i] = 0
    for p in first_lst_sent_packets:
        sec = int(float(first_lst_sent_packets[p].frame_time_relative))
        if sec in lst_bytes_sent_first:
            lst_bytes_sent_first[sec] += int(float(first_lst_sent_packets[p].frame_len))
        else:
            lst_bytes_sent_first[sec] = int(float(first_lst_sent_packets[p].frame_len))
    lst_pdf_sent_first = []
    for i in lst_bytes_sent_first:
        lst_pdf_sent_first.append(lst_bytes_sent_first[i])

    lst_byte_sent_second = {}  # {<sec, number of packets in the sec>}
    for p in second_lst_sent_packets:
        last_sec = second_lst_sent_packets[p].frame_time_relative
    for i in range(int(float(last_sec))+1):
        lst_byte_sent_second[i] = 0
    for p in second_lst_sent_packets:
        sec = int(float(second_lst_sent_packets[p].frame_time_relative))
        if sec in lst_byte_sent_second:
            lst_byte_sent_second[sec] += int(float(second_lst_sent_packets[p].frame_len))
        else:
            lst_byte_sent_second[sec] = int(float(second_lst_sent_packets[p].frame_len))
    lst_pdf_sent_second = []
    for i in lst_byte_sent_second:
        lst_pdf_sent_second.append(lst_byte_sent_second[i])

    try:
        plt.title("Bytes Sent per Second")
        plt.ylabel("Byte", fontsize=16, labelpad=20)
        plt.xlabel("Time (Sec)", fontsize=16, labelpad=20)
        plt.plot(range(len(lst_pdf_sent_first)), lst_pdf_sent_first, color='blue', label="Traffic 1")
        plt.plot(range(len(lst_pdf_sent_second)), lst_pdf_sent_second, color='red', label="Traffic 2")
        plt.legend(loc='upper left')
        plt.tight_layout()
        plt.savefig(str(os.getcwd()) + "/output/sent_bytes_both.jpg")
        # plt.show()
        plt.close()
    except:
        pass

    lst_sec_flow_first = {}  # {<sec, number of flows in that sec>}
    # for p in first_lst_flows:
    #     last_sec = float(first_lst_flows[p].request_timestamp_start)
    # for i in range(int((last_sec))):
    #     lst_sec_flow_first[i] = 0

    for f in first_lst_flows:
        fisrt_flow_time = float(first_lst_flows[f].request_timestamp_start)
        break
    for f in first_lst_flows:
        last_flow_time = float(first_lst_flows[f].request_timestamp_start)

    for i in range(int(float(last_flow_time) - float(fisrt_flow_time))):
        lst_sec_flow_first[i] = 0

    for f in first_lst_flows:
        sec = int(float(first_lst_flows[f].request_timestamp_start) - fisrt_flow_time)
        if sec in lst_sec_flow_first:
            lst_sec_flow_first[sec] += 1
        else:
            lst_sec_flow_first[sec] = 1
    lst_flow_cdf_first = []
    for i in lst_sec_flow_first:
        lst_flow_cdf_first.append(lst_sec_flow_first[i])

    lst_sec_flow_second = {}  # {<sec, number of flows in that sec>}
    # for p in second_lst_flows:
    #     last_sec = float(second_lst_flows[p].request_timestamp_start)
    # for i in range(int(float(last_sec))):
    #     lst_sec_flow_second[i] = 0
    for f in second_lst_flows:
        fisrt_flow_time = float(second_lst_flows[f].request_timestamp_start)
        break
    for f in second_lst_flows:
        last_flow_time = float(second_lst_flows[f].request_timestamp_start)

    for i in range(int(float(last_flow_time) - float(fisrt_flow_time))):
        lst_sec_flow_second[i] = 0

    for f in second_lst_flows:
        sec = int(float(second_lst_flows[f].request_timestamp_start) - fisrt_flow_time)
        if sec in lst_sec_flow_second:
            lst_sec_flow_second[sec] += 1
        else:
            lst_sec_flow_second[sec] = 1
    lst_flow_cdf_second = []
    for i in lst_sec_flow_second:
        lst_flow_cdf_second.append(lst_sec_flow_second[i])

    # 3. Flow Types - Pie Chart
    labels = ["GET", "POST", "Others"]
    sizes = [0, 0, 0]
    for f in first_lst_flows:
        if first_lst_flows[f].method == "GET":
            sizes[0] += 1
        elif first_lst_flows[f].method == "POST":
            sizes[1] += 1
        else:
            sizes[2] += 1
    for lbl in range(len(labels)):
        labels[lbl] += (": " + str(sizes[lbl]))
    fig, ax = plt.subplots(figsize=(12, 8), subplot_kw=dict(aspect="equal"))
    ax.pie(sizes, labels=labels)
    ax.set_title("Flow Methods - First Player", fontsize=16)
    plt.tight_layout()
    plt.savefig(str(os.getcwd()) + "/output/flow_method1.jpg")
    plt.close()

    # for f in lst_sec_flow_first:
    #     print(f, ' - ', lst_sec_flow_first[f])
    # for f in lst_sec_flow_second:
    #     print(f, ' - ', lst_sec_flow_second[f])


    # 3. Flow Types - Player 2
    labels = ["GET", "POST", "Others"]
    sizes = [0, 0, 0]
    for f in second_lst_flows:
        if second_lst_flows[f].method == "GET":
            sizes[0] += 1
        elif second_lst_flows[f].method == "POST":
            sizes[1] += 1
        else:
            sizes[2] += 1
    for lbl in range(len(labels)):
        labels[lbl] += (": " + str(sizes[lbl]))
    fig, ax = plt.subplots(figsize=(12, 8), subplot_kw=dict(aspect="equal"))
    ax.pie(sizes, labels=labels)
    ax.set_title("Flow Methods - Second Player", fontsize=16)
    plt.tight_layout()
    plt.savefig(str(os.getcwd()) + "/output/flow_method2.jpg")
    plt.close()

    # 4. Flow Data Type - Pie Chart
    labels = ["video", "audio", "image", "text/html", "javascript", "json", "other"]
    sizes = [0, 0, 0, 0, 0, 0, 0]
    for f in first_lst_flows:
        temp = find_content_type(first_lst_flows[f].content_type)
        if temp == "video":
            sizes[0] += 1
        elif temp == "audio":
            sizes[1] += 1
        elif temp == "image":
            sizes[2] += 1
        elif temp == "text/html":
            sizes[3] += 1
        elif temp == "javascript":
            sizes[4] += 1
        elif temp == "json":
            sizes[5] += 1
        else:
            sizes[6] += 1
    for lbl in range(len(labels)):
        labels[lbl] += (": " + str(sizes[lbl]))
    fig, ax = plt.subplots(figsize=(12, 8), subplot_kw=dict(aspect="equal"))
    autotexts = ax.pie(sizes, labels=labels)
    ax.set_title("Flow's Data Type - Traffic 1", fontsize=16)
    # plt.setp(autotexts, size=8, weight="bold")
    plt.tight_layout()
    plt.savefig(str(os.getcwd()) + "/output/flow_data_type1.jpg")
    plt.close()

    # 4. Flow Data Type - Pie Chart
    labels = ["video", "audio", "image", "text/html", "javascript", "json", "other"]
    sizes = [0, 0, 0, 0, 0, 0, 0]
    for f in second_lst_flows:
        temp = find_content_type(second_lst_flows[f].content_type)
        if temp == "video":
            sizes[0] += 1
        elif temp == "audio":
            sizes[1] += 1
        elif temp == "image":
            sizes[2] += 1
        elif temp == "text/html":
            sizes[3] += 1
        elif temp == "javascript":
            sizes[4] += 1
        elif temp == "json":
            sizes[5] += 1
        else:
            sizes[6] += 1
    for lbl in range(len(labels)):
        labels[lbl] += (": " + str(sizes[lbl]))
    fig, ax = plt.subplots(figsize=(12, 8), subplot_kw=dict(aspect="equal"))
    autotexts = ax.pie(sizes, labels=labels)
    ax.set_title("Flow's Data Type - Traffic 2", fontsize=16)
    # plt.setp(autotexts, size=8, weight="bold")
    plt.tight_layout()
    plt.savefig(str(os.getcwd()) + "/output/flow_data_type2.jpg")
    plt.close()
    # exit()

    # 5. Flow Data Size - Pie Chart
    labels = ["video", "audio", "image", "text/html", "javascript", "json", "other"]
    sizes = [0, 0, 0, 0, 0, 0, 0]
    for f in first_lst_flows:
        temp = find_content_type(first_lst_flows[f].content_type)
        if temp == "video":
            try:
                sizes[0] += int(first_lst_flows[f].content_length)
            except:
                pass
        elif temp == "audio":
            try:
                sizes[1] += int(first_lst_flows[f].content_length)
            except:
                pass
        elif temp == "image":
            try:
                sizes[2] += int(first_lst_flows[f].content_length)
            except:
                pass
        elif temp == "text/html":
            try:
                sizes[3] += int(first_lst_flows[f].content_length)
            except:
                pass
        elif temp == "javascript":
            try:
                sizes[4] += int(first_lst_flows[f].content_length)
            except:
                pass
        elif temp == "json":
            try:
                sizes[5] += int(first_lst_flows[f].content_length)
            except:
                pass
        else:
            try:
                sizes[6] += int(first_lst_flows[f].content_length)
            except:
                pass

    for lbl in range(len(labels)):
        labels[lbl] += (": " + size(sizes[lbl]))
    fig, ax = plt.subplots(figsize=(12, 8), subplot_kw=dict(aspect="equal"))
    wedges, texts = ax.pie(sizes)
    ax.legend(wedges, labels,
              title="Flow Data Size",
              loc="center left",
              bbox_to_anchor=(1, 0, 0.5, 1))
    # plt.setp(autotexts, size=8, weight="bold")

    ax.set_title("Flow's Data Size - Traffic 1", fontsize=16)
    # plt.setp(autotexts, size=8, weight="bold")
    plt.tight_layout()
    plt.savefig(str(os.getcwd()) + "/output/flow_data_size1.jpg")
    plt.close()

    # 5. Flow Data Size - Pie Chart
    labels = ["video", "audio", "image", "text/html", "javascript", "json", "other"]
    sizes = [0, 0, 0, 0, 0, 0, 0]
    for f in second_lst_flows:
        temp = find_content_type(second_lst_flows[f].content_type)
        if temp == "video":
            try:
                sizes[0] += int(second_lst_flows[f].content_length)
            except:
                pass
        elif temp == "audio":
            try:
                sizes[1] += int(second_lst_flows[f].content_length)
            except:
                pass
        elif temp == "image":
            try:
                sizes[2] += int(second_lst_flows[f].content_length)
            except:
                pass
        elif temp == "text/html":
            try:
                sizes[3] += int(second_lst_flows[f].content_length)
            except:
                pass
        elif temp == "javascript":
            try:
                sizes[4] += int(second_lst_flows[f].content_length)
            except:
                pass
        elif temp == "json":
            try:
                sizes[5] += int(second_lst_flows[f].content_length)
            except:
                pass
        else:
            try:
                sizes[6] += int(second_lst_flows[f].content_length)
            except:
                pass

    for lbl in range(len(labels)):
        labels[lbl] += (": " + size(sizes[lbl]))
    fig, ax = plt.subplots(figsize=(12, 8), subplot_kw=dict(aspect="equal"))
    wedges, texts = ax.pie(sizes)
    ax.legend(wedges, labels,
              title="Flow Data Size",
              loc="center left",
              bbox_to_anchor=(1, 0, 0.5, 1))
    # plt.setp(autotexts, size=8, weight="bold")

    ax.set_title("Flow's Data Size - Traffic 2", fontsize=16)
    # plt.setp(autotexts, size=8, weight="bold")
    plt.tight_layout()
    plt.savefig(str(os.getcwd()) + "/output/flow_data_size2.jpg")
    plt.close()

    # 2. Flow CDF
    lst_flow_pdf_first = lst_flow_cdf_first
    lst_flow_pdf_second = lst_flow_cdf_second

    try:
        plt.title("Generated Flows per Second")
        plt.ylabel("Flow", fontsize=16, labelpad=20)
        plt.xlabel("Time (Sec)", fontsize=16, labelpad=20)
        plt.plot(range(len(lst_flow_pdf_first)), lst_flow_pdf_first, color='blue', label="Traffic 1")
        plt.plot(range(len(lst_flow_pdf_second)), lst_flow_pdf_second, color='red', label="Traffic 2")
        plt.legend(loc='upper right')
        plt.tight_layout()
        plt.savefig(str(os.getcwd()) + "/output/flow_both.jpg")
        # plt.show()
        plt.close()
    except:
        pass

    # '''
    # In this function we create statsitic charts for sent/received packets
    # '''
    # '''
    # Sent / Received Packet Graphs
    # '''
    # # Received Packets
    # lst_sec_received = {}  # {<sec, number of packets in the sec>}
    # for p in lst_received_packets:
    #     sec = int(float(lst_received_packets[p].frame_time_relative))
    #     if sec in lst_sec_received:
    #         lst_sec_received[sec] += 1
    #     else:
    #         lst_sec_received[sec] = 1
    # lst_cdf_received = []
    # for i in lst_sec_received:
    #     lst_cdf_received.append(lst_sec_received[i])
    #
    # # Sent Packets
    # lst_sec_sent = {}  # {<sec, number of packets in the sec>}
    # for p in lst_sent_packets:
    #     sec = int(float(lst_sent_packets[p].frame_time_relative))
    #     if sec in lst_sec_sent:
    #         lst_sec_sent[sec] += 1
    #     else:
    #         lst_sec_sent[sec] = 1
    # lst_cdf_sent = []
    # for i in lst_sec_sent:
    #     lst_cdf_sent.append(lst_sec_sent[i])
    #
    # # CDF - Packets per Second
    # sum_received = np.sum(lst_cdf_received)
    # cum_lst_cdf_received = np.cumsum(lst_cdf_received)
    # cum_lst_cdf_received = cum_lst_cdf_received / sum_received
    #
    # sum_sent = np.sum(lst_cdf_sent)
    # cum_lst_cdf_sent = np.cumsum(lst_cdf_sent)
    # cum_lst_cdf_sent = cum_lst_cdf_sent / sum_sent
    #
    # plt.title("Cumulative Distribution Function (CDF) of Sent/Received Packets")
    # plt.ylabel("CDF (Packet)", fontsize=16, labelpad=20)
    # plt.xlabel("Time (Sec)", fontsize=16, labelpad=20)
    # plt.plot(range(len(cum_lst_cdf_received)), cum_lst_cdf_received, color='blue', label = "Received")
    # plt.plot(range(len(cum_lst_cdf_sent)), cum_lst_cdf_sent, color='red', label="Sent")
    # plt.legend(loc='upper left')
    # plt.tight_layout()
    # plt.savefig(str(os.getcwd()) + "/output/sent_received_packets_cdf.jpg")
    # # plt.show()
    # plt.close()
    #
    # # PDf - Packets per Second
    # lst_pdf_received = lst_cdf_received
    # lst_pdf_sent = lst_cdf_sent
    # plt.title("Sent/Received Packet per Second)")
    # plt.ylabel("Packet", fontsize=16, labelpad=20)
    # plt.xlabel("Time (Sec)", fontsize=16, labelpad=20)
    # plt.plot(range(len(lst_pdf_received)), lst_pdf_received, color='blue', label="Sent")
    # plt.plot(range(len(lst_pdf_sent)), lst_pdf_sent, color='red', label="Received")
    # plt.legend(loc='upper right')
    # # plt.legend(('Male', 'Female'), ('Men', 'Women'))
    # # plt.tight_layout()
    # # plt.show()
    # plt.savefig(str(os.getcwd()) + "/output/sent_received_packets_pdf.jpg")
    # # plt.show()
    # plt.close()
    #
    # # Received - Byte per Sec
    # lst_bytes_received = {}  # {<sec, bytes in the sec>}
    # for p in lst_received_packets:
    #     sec = int(float(lst_received_packets[p].frame_time_relative))
    #     if sec in lst_bytes_received:
    #         lst_bytes_received[sec] += int(float(lst_received_packets[p].frame_len))
    #     else:
    #         lst_bytes_received[sec] = int(float(lst_received_packets[p].frame_len))
    # cdf_byte_received = []
    # for i in lst_bytes_received:
    #     cdf_byte_received.append(lst_bytes_received[i])
    #
    # # Sent - Byte
    # lst_bytes_sent = {}  # {<sec, bytes in the sec>}
    # for p in lst_sent_packets:
    #     sec = int(float(lst_sent_packets[p].frame_time_relative))
    #     if sec in lst_bytes_sent:
    #         lst_bytes_sent[sec] += int(float(lst_sent_packets[p].frame_len))
    #     else:
    #         lst_bytes_sent[sec] = int(float(lst_sent_packets[p].frame_len))
    # cdf_byte_sent = []
    # for i in lst_bytes_sent:
    #     cdf_byte_sent.append(lst_bytes_sent[i])
    #
    # # Received (Packets per Second)
    # sum_received = np.sum(cdf_byte_received)
    # cum_lst_cdf_received = np.cumsum(cdf_byte_received)
    # cum_lst_cdf_received = cum_lst_cdf_received / sum_received
    #
    # # Sent
    # sum_sent = np.sum(cdf_byte_sent)
    # cum_lst_cdf_sent = np.cumsum(cdf_byte_sent)
    # cum_lst_cdf_sent = cum_lst_cdf_sent / sum_sent
    #
    # plt.title("Cumulative Distribution Function (CDF) of Sent/Received Bytes")
    # plt.ylabel("CDF (Byte)", fontsize=16, labelpad=20)
    # plt.xlabel("Time (Sec)", fontsize=16, labelpad=20)
    # plt.plot(range(len(cum_lst_cdf_received)), cum_lst_cdf_received, color='blue', label="Received")
    # plt.plot(range(len(cum_lst_cdf_sent)), cum_lst_cdf_sent, color='red', label="Sent")
    # plt.legend(loc='upper left')
    # # s = plt.scatter(range(len(cum_lst_cdf)), cum_lst_cdf)
    # # s.set_urls(['http://www.bbc.co.uk/news', 'http://www.google.com', 'http://www.uofc.ca'])
    # plt.tight_layout()
    # plt.savefig(str(os.getcwd()) + "/output/sent_received_bytes_cdf.jpg")
    # # plt.show()
    # plt.close()
    #
    # # PDf received bytes per sec
    # lst_pdf_received = cdf_byte_received
    # lst_pdf_sent = cdf_byte_sent
    # plt.title("Sent/Received Byte per Second)")
    # plt.ylabel("Byte", fontsize=16, labelpad=20)
    # # plt.ylabel("Byte", labelpad=20)
    # plt.xlabel("Time (Sec)", fontsize=16, labelpad=20)
    # # plt.suptitle('test title', fontsize=20)
    # plt.plot(range(len(lst_pdf_received)), lst_pdf_received, color='blue', label="Received")
    # plt.plot(range(len(lst_pdf_sent)), lst_pdf_sent, color='red', label="Sent")
    # plt.legend(loc='upper right')
    # plt.tight_layout()
    # plt.savefig(str(os.getcwd()) + "/output/sent_received_bytes_pdf.jpg")
    # # plt.show()
    # plt.close()



# Classify flows by flow type (GET/POST/Other)
def get_number_of_get_requests(lst_flows:Dict[str, Flow]):
    lst_get_requests = []
    lst_post_requests = []
    lst_other_requests = []
    for f in lst_flows:
        if lst_flows[f].method == "GET":
            lst_get_requests.append(lst_flows[f].flow_number)
            continue
        if lst_flows[f].method == "POST":
            lst_post_requests.append(lst_flows[f].flow_number)
            continue
        lst_other_requests.append(lst_flows[f].flow_number)
        continue
        # print(lst_flows[f].client_initiated_time, " - " ,lst_flows[f].method)
    return len(lst_get_requests), len(lst_post_requests), len(lst_other_requests)

# Timestamp to regular time

def yycTime(epochTime):
    epochTime = int(float(epochTime))
    e = time.gmtime(epochTime)
    t = time.localtime(epochTime)
    return time.strftime('%Y-%m-%d %H:%M:%S', t)

def get_total_bytes(lst:Dict[str, Packet]):
    total_bytes = 0
    for p in lst:
        if lst[p].frame_len == None or lst[p].frame_len == "None":
            total_bytes+=0
        else:
            total_bytes += int(lst[p].frame_len)
            if int(lst[p].frame_len) > 15000:
                print(lst[p].frame_len, ' - ', lst[p].frame_number)
    return total_bytes

