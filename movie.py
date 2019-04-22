from conjunction import *
from html import *
from statics import *

# Removing all previous html outputs
remove_previous_outputs()

# Retrieve Init information from config.py
mitm_port = get_mitm_port()
wireshark_file_name = get_wireshark_file_name()
tshark_file_name = get_tshark_file_name()
player_file_name = get_player_file_name()
request_file_name = get_request_file_name()
response_file_name = get_response_file_name()

# Read Wireshark file and create packets
if os.path.exists(tshark_file_name):
    lst_packets = create_packet_list(tshark_file_name)
    number_of_packets = len(lst_packets)
elif os.path.exists(wireshark_file_name):
    lst_packets = create_packet_list(wireshark_file_name)
    number_of_packets = len(lst_packets)
else:
    print("tshark.json or wireshark.json is missing. \nThere is not the packet trace file in this directory.")
    exit()


# Sepeate income/outgoing device packets from other traffic
lst_sent_packets, lst_received_packets = get_sent_and_recieved_packets(lst_packets, mitm_port)

# Read MITM proxy log and create the flow list
lst_flows = create_flow_list(request_file_name, response_file_name)
number_of_flows = len(lst_flows)

# Read Player Log and create Players
if get_enable_player()==True:
    lst_players = create_player_log(player_file_name)
    number_of_players = len(lst_players)
else:
    lst_players = {}

# Categorize flows into sessions
lst_initiated_time = find_initiated_time_list(lst_flows)

# Connect flows to packet and player
lst_tcp_streams, lst_udp_streams, lst_dns_streams = {}, {}, {}
lst_packets, lst_flows, lst_tcp_streams, lst_udp_streams, lst_dns_streams, lst_initiated_time = assign_streams_to_initiate_times(lst_packets, lst_flows, lst_tcp_streams, lst_udp_streams, lst_dns_streams, lst_initiated_time)

# Comparison section
is_comparision = get_is_comparision()
second_wireshark_file_name = get_second_wireshark_file_name()
second_tshark_file_name = get_second_tshark_file_name()
second_player_file_name = get_second_player_file_name()
second_mitm_request_file_name = get_second_mitm_request_file_name()
second_mitm_response_file_name = get_second_mitm_response_file_name()

# Create Statistics charts
create_charts(lst_packets, lst_sent_packets, lst_received_packets, lst_flows)

# Create outputs
make_main_page_html(lst_sent_packets, lst_received_packets, lst_flows, lst_initiated_time, lst_players)
create_wireshark_page(lst_packets)
create_mitm_page(lst_flows)
create_player_page(lst_players)
create_all_flow_pages_html(lst_packets, lst_flows)

# Open main page in browser
webbrowser.open('output/index.html')