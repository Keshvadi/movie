from typing import Dict, List

from charts import html_two_bar_chart
from html import *
from mitm import *
from packet import *
from player import *
from statics import *

def compare_videos(lst_sent_packets, lst_received_packets, lst_flows, lst_initiated_time, lst_players):
    html_text = ""

    # Chack comparision files
    result, msg = check_comparison_files()
    if result == False:
        page_text = '<h3 style="color:red"> Not Comparison.</h3>' + msg
        return page_text

    # Read wireshark files and extract packets
    # second_lst_packets = create_packet_list("wireshark2.json")
    second_lst_packets = create_packet_list("tshark2.json")

    first_lst_sent_packets, first_lst_received_packets = lst_sent_packets, lst_received_packets
    second_lst_sent_packets, second_lst_received_packets = get_sent_and_recieved_packets(second_lst_packets, "8080")

    # Read MTIM files and extract flows
    first_lst_flows = lst_flows
    second_lst_flows = create_flow_list("request2.json", "response2.json")

    # Read Player files and extract players' info
    first_lst_player = lst_players
    second_lst_player = create_player_log("media-internals2.txt")

    comparision = {}
    # Get Statics from Wireshark
    header, statistics = general_comparison_statics(first_lst_sent_packets, first_lst_received_packets, second_lst_sent_packets, second_lst_received_packets, first_lst_flows, second_lst_flows, first_lst_player, second_lst_player)
    # text = create_table_htmll(header, statistics, "10", [20] * len(header))
    text = create_table(header, statistics, "10", [20] * len(header))
    text+=get_comparision_graphs()
    create_charts_comparision(first_lst_sent_packets, first_lst_received_packets, second_lst_sent_packets, second_lst_received_packets, first_lst_flows, second_lst_flows, first_lst_player, second_lst_player)


    text += "</div> "
    return text


def create_table_htmll(headers:list, data:dict, table_id, table_width):
    data_packets = [["Network Traffic", "Data 1", "Data 2"]]
# ['Total', [23529, 23529, 'Packet'], [23529, 23529, 'Packet']]
    for line in data:
        if line == "Number of packets":
            temp = []
            temp.append("Total")
            for i in data[line]:
                temp.append(i)
            data_packets.append(temp)

        if line == "TCP":
            temp = []
            temp.append("TCP")
            for i in data[line]:
                temp.append(i)
            data_packets.append(temp)

        if line == "UDP":
            temp = []
            temp.append("UDP")
            for i in data[line]:
                temp.append(i)
            data_packets.append(temp)

        if line == "DNS":
            temp = []
            temp.append("DNS")
            for i in data[line]:
                temp.append(i)
            data_packets.append(temp)

        if line == "Other":
            temp = []
            temp.append("Other")
            for i in data[line]:
                temp.append(i)
            data_packets.append(temp)
    html_text = html_two_bar_chart("packet_bar", 'Captured Network Traffic', "Number of packets", "Protocol", "1000", "400",
                       data_packets)

    # # Add data related to the traffic info
    # for line in data:
    #     if line == "Total bytes":
    #         temp.append("Total bytes")
    #         for i in data[line]:
    #             temp.append(i)
    #         data_packets.append(temp)
    # html_text += create_table_html(["Network Traffic", "Data 1", "Data 2"], data_packets_table, 11, 100)


    html_text += "<hr>"



    return html_text

    # columns = len(table_width)
    # n = 0
    # text = '<table class="myTable" > \n'
    # text += "<tr> "
    # for i in headers:
    #     if str(i) == "Value":
    #         text+='<th onclick="sortNumTable(%s, %s)"> %s </th>'%(n, table_id, str(i))
    #     else:
    #         text+='<th onclick="sortTable(%s, %s)"> %s </th>'%(n, table_id, str(i))
    #     n+=1
    # text+="</tr> \n"
    #
    # for i in data:
    #     text += "<tr> "
    #     text += '<td style="font-weight:bold" width="%s%%"> %s </td>' % (25, str(i))
    #     n = 0
    #     for j in data[i]:
    #         text+='<td width="%s%%"> %s </td>'%(25, str(j))
    #         n+=1
    #     text+="</tr> \n"
    # text += "</table> \n"
    #
    #
    #
    # return text


def check_comparison_files():
    msg = ""
    # if not os.path.exists("wireshark.json"):
    #     msg+= "<br> wireshark1.json is not exist for comparision."
    # if not os.path.exists("wireshark2.json"):
    #     msg+= "<br> wireshark2.json is not exist for comparision."
    if not os.path.exists("request.json"):
        msg+= "<br> request.json is not exist for comparision."
    if not os.path.exists("request2.json"):
        msg+= "<br> request2.json is not exist for comparision."
    if not os.path.exists("response.json"):
        msg+= "<br> response.json is not exist for comparision."
    if not os.path.exists("response2.json"):
        msg+= "<br> response2.json is not exist for comparision."
    if not os.path.exists("media-internals.txt"):
        msg+= "<br> player1.txt is not exist for comparision."
    if not os.path.exists("media-internals2.txt"):
        msg+= "<br> player2.txt is not exist for comparision."

    if msg=="":
        return True, ""
    else:
        return False, msg


def compare_wiresharks(comparision:Dict[str, List], first_packets_statics:Dict[str, List], second_packets_statics:Dict[str, List]):
    text = '<table border="1"> \n'
    for i in first_packets_statics:
        text += "<tr> "
        n = 0
        for j in first_packets_statics[i]:
            text+='<td width="%s%%"> %s </td>'%((33), str(j))
            n+=1
        text+="</tr> \n"
    text += "</table> "
    print(text)
    return text
    # return comparision
def create_table(headers:list, data:dict, table_id, table_width):
    columns = len(table_width)
    n = 0
    text = '<table class="myTable" > \n'
    text += "<tr> "
    for i in headers:
        if str(i) == "Value":
            text+='<th onclick="sortNumTable(%s, %s)"> %s </th>'%(n, table_id, str(i))
        else:
            text+='<th onclick="sortTable(%s, %s)"> %s </th>'%(n, table_id, str(i))
        n+=1
    text+="</tr> \n"

    for i in data:
        text += "<tr> "
        text += '<td width="%s%%"> %s </td>' % (25, str(i))
        n = 0
        for j in data[i]:
            text+='<td width="%s%%"> %s </td>'%(int(table_width[n]), str(j))
            n+=1
        text+="</tr> \n"
    text += "</table> "
    return text