# Classify packets in tcp, udp, and dns streams lists
def classify_packets_by_protocols(lst_packets:Dict[str, Packet]):
    number_of_tcp_packets = 0
    number_of_udp_packets = 0
    number_of_dns_packets = 0
    number_of_other_packets = 0
    lst_tcp_streams = {}
    lst_udp_streams = {}
    lst_dns_streams = {}
    lst_other_streams = {}

    for p in lst_packets:
        # TCP Streams
        if lst_packets[p].packet_type == "TCP":
            number_of_tcp_packets +=1
            if str(lst_packets[p].stream_number) in lst_tcp_streams:
                if lst_packets[p].host != None:
                    lst_tcp_streams[str(lst_packets[p].stream_number)].host = lst_packets[p].host
                if lst_packets[p].http_host != None:
                    lst_tcp_streams[str(lst_packets[p].stream_number)].http_host = lst_packets[p].http_host
                lst_tcp_streams[str(lst_packets[p].stream_number)].packet_list.append(lst_packets[p].frame_number)
            else:
                st = Stream()
                st.stream_type = "TCP"
                st.start_time = lst_packets[p].time_epoch
                st.ip_src = lst_packets[p].ip_src
                st.ip_dst = lst_packets[p].ip_dst
                st.src_port = lst_packets[p].src_port
                st.dst_port = lst_packets[p].dst_port
                st.stream_number = lst_packets[p].stream_number
                if (lst_packets[p].host != None):
                    st.host = lst_packets[p].host
                if lst_packets[p].http_host != None:
                    st.http_host = lst_packets[p].http_host
                st.packet_list = []
                st.packet_list.append(lst_packets[p].frame_number)
                lst_tcp_streams[str(lst_packets[p].stream_number)] = st
            continue

        # DNS Streams
        if lst_packets[p].is_dns:
            number_of_dns_packets+=1
            if lst_packets[p].dns_id == "0x00000000":
                continue
            if str(lst_packets[p].stream_number) in lst_dns_streams:
                lst_dns_streams[str(lst_packets[p].stream_number)].packet_list.append(lst_packets[p].frame_number)
            else:
                st = Stream()
                st.stream_type = "DNS"
                st.is_dns = True
                st.start_time = lst_packets[p].time_epoch
                st.ip_src = lst_packets[p].ip_src
                st.ip_dst = lst_packets[p].ip_dst
                st.src_port = lst_packets[p].src_port
                st.dst_port = lst_packets[p].dst_port
                st.stream_number = lst_packets[p].stream_number
                st.packet_list = []
                st.packet_list.append(lst_packets[p].frame_number)
                lst_dns_streams[str(lst_packets[p].stream_number)] = st
            continue

        # UDP Streams
        if lst_packets[p].packet_type == "UDP":
            number_of_udp_packets+=1
            if str(lst_packets[p].stream_number) in lst_udp_streams:
                if lst_packets[p].http_host != None:
                    st.http_host = lst_packets[p].http_host
                lst_udp_streams[str(lst_packets[p].stream_number)].packet_list.append(lst_packets[p].frame_number)
            else:
                st = Stream()
                st.stream_type = "UDP"
                st.start_time = lst_packets[p].time_epoch
                st.ip_src = lst_packets[p].ip_src
                st.ip_dst = lst_packets[p].ip_dst
                st.src_port = lst_packets[p].src_port
                st.dst_port = lst_packets[p].dst_port
                st.stream_number = lst_packets[p].stream_number
                if lst_packets[p].http_host != None:
                    st.http_host = lst_packets[p].http_host
                st.packet_list = []
                st.packet_list.append(lst_packets[p].frame_number)
                lst_udp_streams[str(lst_packets[p].stream_number)] = st
            continue
        number_of_other_packets +=1
        if str(lst_packets[p].stream_number) in lst_other_streams:
            if lst_packets[p].http_host != None:
                st.http_host = lst_packets[p].http_host
            lst_other_streams[str(lst_packets[p].stream_number)].packet_list.append(lst_packets[p].frame_number)
        else:
            st = Stream()
            st.stream_type = "Other"
            st.start_time = lst_packets[p].time_epoch
            st.ip_src = lst_packets[p].ip_src
            st.ip_dst = lst_packets[p].ip_dst
            st.src_port = lst_packets[p].src_port
            st.dst_port = lst_packets[p].dst_port
            st.stream_number = lst_packets[p].stream_number
            if lst_packets[p].http_host != None:
                st.http_host = lst_packets[p].http_host
            st.packet_list = []
            st.packet_list.append(lst_packets[p].frame_number)
            lst_other_streams[str(lst_packets[p].stream_number)] = st
    return lst_tcp_streams, lst_udp_streams, lst_dns_streams, lst_other_streams

# Classify packets in tcp, udp, and dns packetlists
def classify_packets_by_protocols_in_lst_packet(lst_packets:Dict[str, Packet]):
    lst_tcp_packet = []
    lst_udp_packet = []
    lst_dns_packet = []
    lst_other_packet = []

    for p in lst_packets:
        # TCP Streams
        if lst_packets[p].packet_type == "TCP":
            lst_tcp_packet.append(p)
            continue
        elif lst_packets[p].packet_type == "DNS":
            lst_dns_packet.append(p)
            continue
        elif lst_packets[p].packet_type == "UDP":
            lst_udp_packet.append(p)
            continue
        else:
            lst_other_packet.append(p)
            continue
    return lst_tcp_packet, lst_udp_packet, lst_dns_packet, lst_other_packet


# classify the pakckets based on the protocol
def classify_packets_by_protocols_full(lst_packets:Dict[str, Packet]):
    lst_protocol = {}
    for packet in lst_packets:
        temp = ""
        temp = str(lst_packets[packet].frame_protocols)
        if temp.startswith("eth:ethertype:"):
            temp = temp[14:100]
            index = temp.find(":x509sat")
            if index != -1:
                temp = temp[:index]
            while (temp.find("data:data:") != -1):
                temp = re.sub("data:data:", "data:", temp)
            if temp in lst_protocol:
                lst_protocol[temp].append(lst_packets[packet].frame_number)
            else:
                lst_protocol[temp] = []
                lst_protocol[temp].append(lst_packets[packet].frame_number)
    return lst_protocol
