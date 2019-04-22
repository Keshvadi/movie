from mitm import *
from packet import Packet

# # Devote Packets from wireshars to each Flow
# def devote(lstPacket, numberOfFlows):
#     result = {}
#
#     # lstdt keeps the delta time between packets
#     lstdt = {}
#
#     # first packet as first
#     for i in lstPacket:
#         first = i
#         break
#     # find time between packets and store in lstdt
#     for i in lstPacket:
#         dt = int(i) - int(first)
#         lstdt[i] = dt
#         first = i
#
#     # Copy lstdt in temp
#     temp = []
#     for i in lstdt:
#         temp.append(int(lstdt[i]))
#
#     # use temp to sort distinstic points and save in dist
#     dist = []
#     for i in range(numberOfFlows):
#         try:
#             dist.append(int(max(temp)))
#             temp.remove(max(temp))
#         except:
#             print("Error in: temp.remove(max(temp))")
#             pass
#
#     for i in range(numberOfFlows + 2):
#         result[i] = []
#     # put distint points in lstdt
#     n = 0
#     for i in lstdt:
#         if lstdt[i] in dist:
#             dist.remove(lstdt[i])
#             n += 1
#             result[n].append(i)
#         else:
#             result[n].append(i)
#     return result

def assign_streams_to_initiate_times(lst_packets:Dict[str, Packet],
                                     lst_flows:Dict[str, Flow],
                                     lst_tcp_streams:Dict[str, Packet],
                                     lst_udp_streams:Dict[str, Packet],
                                     lst_dns_streams:Dict[str, Packet],
                                     lst_initiated_time:Dict[str, session]):
    for connect in lst_initiated_time:
        # Check TCP Streams
        if lst_initiated_time[connect].src_ip == lst_initiated_time[connect].mitm_ip: # if Client Device is also the MITM device
            for stream in lst_tcp_streams:
                if lst_tcp_streams[stream].initiated_connection_time is None:
                    # if lst_tcp_streams[stream].initiated_connection_time is None:
                     if (
                            ((lst_initiated_time[connect].src_ip == lst_tcp_streams[stream].ip_src and
                              lst_initiated_time[connect].dst_ip == lst_tcp_streams[stream].ip_dst) or
                            (lst_initiated_time[connect].src_ip == lst_tcp_streams[stream].ip_dst and
                              lst_initiated_time[connect].dst_ip == lst_tcp_streams[stream].ip_src)) and
                            ((lst_initiated_time[connect].mitm_port == lst_tcp_streams[stream].src_port and
                              lst_initiated_time[connect].dst_port == lst_tcp_streams[stream].dst_port) or
                             (lst_initiated_time[connect].mitm_port == lst_tcp_streams[stream].dst_port and
                              lst_initiated_time[connect].dst_port == lst_tcp_streams[stream].src_port)) and
                            (Decimal(lst_initiated_time[connect].client_initiated_time) < Decimal(lst_tcp_streams[stream].start_time)) and
                            (lst_initiated_time[connect].dst_name == lst_tcp_streams[stream].host or
                            lst_initiated_time[connect].dst_name == lst_tcp_streams[stream].http_host)
                    ):
                        lst_tcp_streams[stream].initiated_connection_time = lst_initiated_time[connect].client_initiated_time
                        lst_initiated_time[connect].src_tcp_stream = lst_tcp_streams[stream].stream_number
                        break
            for stream in lst_tcp_streams:
                if lst_tcp_streams[stream].initiated_connection_time is None:
                    # if lst_tcp_streams[stream].initiated_connection_time is None:
                    if(lst_tcp_streams[stream].ip_src == lst_tcp_streams[stream].ip_dst):
                        if ((lst_initiated_time[connect].dst_name == lst_tcp_streams[stream].host or
                                 lst_initiated_time[connect].dst_name == lst_tcp_streams[stream].http_host) and
                                # ((Decimal(lst_initiated_time[connect].client_initiated_time) < Decimal(lst_tcp_streams[stream].start_time))) and
                                 (lst_tcp_streams[stream].src_port == "8080" or lst_tcp_streams[stream].dst_port =="8080")
                        ):
                            lst_tcp_streams[stream].initiated_connection_time = lst_initiated_time[connect].client_initiated_time
                            lst_initiated_time[connect].dst_tcp_stream = lst_tcp_streams[stream].stream_number
                            break

    ## test streams and initconnections
    # for stream in lst_tcp_streams:
    #     if lst_tcp_streams[stream].initiated_connection_time is None:
    #         print(lst_tcp_streams[stream].stream_number, " - ", lst_tcp_streams[stream].host, " - ", lst_tcp_streams[stream].http_host)
    # exit()
    # for connect in lst_initiated_time:
    #     print(lst_initiated_time[connect].client_initiated_time, " - ", lst_initiated_time[connect].src_tcp_stream, " - ", lst_initiated_time[connect].dst_tcp_stream)
    # exit()

        # Test This part
        # if lst_initiated_time[connect].src_ip != lst_initiated_time[connect].mitm_ip: # if MITM device is seperate from Client Device
        #             for stream in lst_tcp_streams:
        #                 if lst_tcp_streams[stream].initiated_connection_time is None:
        #                     # if lst_tcp_streams[stream].initiated_connection_time is None:
        #                      if (
        #                             ((lst_initiated_time[connect].src_ip == lst_tcp_streams[stream].ip_src and
        #                               lst_initiated_time[connect].dst_ip == lst_tcp_streams[stream].ip_dst) or
        #                             (lst_initiated_time[connect].src_ip == lst_tcp_streams[stream].ip_dst and
        #                               lst_initiated_time[connect].dst_ip == lst_tcp_streams[stream].ip_src)) and
        #                             ((lst_initiated_time[connect].mitm_port == lst_tcp_streams[stream].src_port and
        #                               lst_initiated_time[connect].dst_port == lst_tcp_streams[stream].dst_port) or
        #                              (lst_initiated_time[connect].mitm_port == lst_tcp_streams[stream].dst_port and
        #                               lst_initiated_time[connect].dst_port == lst_tcp_streams[stream].src_port)) and
        #                             (Decimal(lst_initiated_time[connect].client_initiated_time) < Decimal(lst_tcp_streams[stream].start_time)) and
        #                             (lst_initiated_time[connect].dst_name == lst_tcp_streams[stream].host or
        #                             lst_initiated_time[connect].dst_name == lst_tcp_streams[stream].http_host)
        #                     ):
        #                         lst_tcp_streams[stream].initiated_connection_time = lst_initiated_time[connect].client_initiated_time
        #                         lst_initiated_time[connect].src_tcp_stream = lst_tcp_streams[stream].stream_number
        #                         break

        # DNS Streams
        # if lst_initiated_time[connect].src_ip == lst_initiated_time[connect].mitm_ip: # if Client Device is also MITM device
        #     for stream in lst_dns_streams:
        #         if lst_dns_streams[stream].initiated_connection_time is None:
        #             temp = lst_dns_streams[stream].packet_list
        #             for p in temp:l
        #                 if lst_packets[p].dns_response_to is not None:
        #                     query_packet = lst_packets[p].frame_number
        #                     answer_packet = lst_packets[p].dns_response_to
        #                     requested_address = lst_packets[p].dns_qry_name
        #             if (
        #                 lst_initiated_time[connect].dst_name == lst_packets[query_packet].dns_qry_name
        #                     # (Decimal(lst_initiated_time[connect].client_initiated_time) < Decimal(lst_packets[query_packet].time_epoch)) and
        #                     # (Decimal(lst_initiated_time[connect].server_initiated_time) < Decimal(lst_packets[query_packet].time_epoch)) and
        #                     # (Decimal(lst_initiated_time[connect].client_initiated_time) < Decimal(lst_packets[answer_packet].time_epoch)) and
        #                     # (Decimal(lst_initiated_time[connect].server_initiated_time) < Decimal(lst_packets[answer_packet].time_epoch)) and
        #                     # (Decimal(lst_initiated_time[connect].request_start_time) > Decimal(lst_packets[query_packet].time_epoch)) and
        #                     # (Decimal(lst_initiated_time[connect].request_end_time) > Decimal(lst_packets[query_packet].time_epoch)) and
        #                     # (Decimal(lst_initiated_time[connect].request_start_time) > Decimal(lst_packets[answer_packet].time_epoch)) and
        #                     # (Decimal(lst_initiated_time[connect].request_end_time) > Decimal(lst_packets[answer_packet].time_epoch))
        #             ):
        #                 lst_dns_streams[stream].initiated_connection_time = lst_initiated_time[connect].client_initiated_time
        #                 lst_initiated_time[connect].src_dns_stream = lst_dns_streams[stream].stream_number
        #                 break
        # # # UDP Streams
        # if lst_initiated_time[connect].src_ip == lst_initiated_time[connect].mitm_ip: # if Client Device is also MITM device
        #     for stream in lst_udp_streams:
        #         if lst_udp_streams[stream].initiated_connection_time is None:
        #             # if lst_tcp_streams[stream].initiated_connection_time is None:
        #              if (
        #                     ((lst_initiated_time[connect].src_ip == lst_udp_streams[stream].ip_src and
        #                       lst_initiated_time[connect].dst_ip == lst_udp_streams[stream].ip_dst) or
        #                     (lst_initiated_time[connect].src_ip == lst_udp_sltreams[stream].ip_dst and
        #                       lst_initiated_time[connect].dst_ip == lst_udp_streams[stream].ip_src)) and
        #                     ((lst_initiat   ed_time[connect].mitm_port == lst_udp_streams[stream].src_port and
        #                       lst_initiated_time[connect].dst_port == lst_udp_streams[stream].dst_port) or
        #                      (lst_initiated_time[connect].mitm_port == lst_udp_streams[stream].dst_port and
        #                       lst_initiated_time[connect].dst_port == lst_udp_streams[stream].src_port)) and
        #                     (Decimal(lst_initiated_time[connect].client_initiated_time) < Decimal(lst_udp_streams[stream].start_time))
        #              ):
        #                  print("***********")
        #                  lst_udp_streams[stream].initiated_connection_time = lst_initiated_time[connect].client_initiated_time
        #                  lst_initiated_time[connect].src_udp_stream= lst_udp_streams[stream].stream_number
        #                  break
    '''
    Devide packets into the flows
    '''
    # Assign packets to each InitConnect
    for connect in lst_initiated_time:
        try:
            if lst_initiated_time[connect].src_tcp_stream != None:
                for i in lst_tcp_streams[(lst_initiated_time[connect].src_tcp_stream)].packet_list:
                    lst_initiated_time[connect].packet_list.append(int(lst_packets[i].frame_number))
            if lst_initiated_time[connect].dst_tcp_stream != None:
                for i in lst_tcp_streams[(lst_initiated_time[connect].dst_tcp_stream)].packet_list:
                    lst_initiated_time[connect].packet_list.append(int(lst_packets[i].frame_number))
        except:
            print("There is an error in devide packets into flows")
            # print(lst_initiated_time[connect].src_tcp_stream)
            # print(lst_initiated_time[connect].dst_tcp_stream)
        lst_initiated_time[connect].packet_list.sort()
    # # test
    # for connect in lst_initiated_time:
    #     print(lst_initiated_time[connect].server_initiated_time, '\n', lst_initiated_time[connect].packet_list, '\n ***************** \n')
    # exit()

    lst_flows, lst_packets = devote_packets_to_flows(lst_packets, lst_flows, lst_initiated_time)

    # for stream in lst_tcp_streams:
    #     if lst_tcp_streams[stream].stream_number == "31" or lst_tcp_streams[stream].stream_number == "26":
    #         for packet in lst_tcp_streams[stream].packet_list:
    #             if lst_packets[packet].ip_src != lst_packets[packet].ip_dst:
    #                 sum += int(lst_packets[str(packet)].frame_len)
    # print(sum)
    # exit()
    #
    n = 1
    # for connect in lst_initiated_time:
    #     for flow in lst_initiated_time[connect].flows_list:
    #         print(lst_flows[str(flow)].packet_list)
    #     n+=1
    #     if n>2:
    #         break
    #         exit()

    # for connect in lst_initiated_time:
    #     result = devote(lst_initiated_time[connect].packet_list, len(lst_initiated_time[connect].flows_list) - 1)
    #     n = 0
    #     for ff in lst_initiated_time[connect].flows_list:
    #         for f in lst_flows:
    #             if int(lst_flows[f].flow_number) == int(ff):
    #                 lst_flows[f].packet_list = result[n]
    #                 n += 1
    return lst_packets, lst_flows, lst_tcp_streams, lst_udp_streams, lst_dns_streams, lst_initiated_time

# # Show Flows with corresponded packets
# for ff in lstFlows:
#     print("\n\n"+str(lstFlows[ff].flowNumber))
#     print(lstFlows[ff].packetList)
#
def findFlowPackets(lst_flows:Dict[str, Flow], f):
    for ff in lst_flows:
        if str(f) == str(lst_flows[ff].flowNumber):
            return lst_flows[ff].packetList


def getFlowInfo(lst_flows:Dict[str, Flow], flowNumber):
    for f in lst_flows:
        if str(lst_flows[f].flow_number) == str(flowNumber):
            return lst_flows[f].getFlowInfo()

def devote_packets_to_flows(lst_packets:Dict[str, Packet],
                            lst_flows:Dict[str, Flow],
                            lst_initiated_time:Dict[str, session]):
    for connect in lst_initiated_time:

        # if these is just one flow, devote all packets to that flow
        if len(lst_initiated_time[connect].flows_list) <2:
            for flow in lst_initiated_time[connect].flows_list:
                for packet in lst_initiated_time[connect].packet_list:
                    lst_flows[flow].packet_list.append(lst_packets[str(packet)].frame_number)
                    lst_packets[str(packet)].flow_number = lst_flows[flow].flow_number
            continue

        # count flows with response
        success_flows = 0
        for flow in lst_initiated_time[connect].flows_list:
            if lst_flows[flow].status_code == "200":
                success_flows += 1

        # is there is just one success flow, devote all packets to that flow
        if success_flows==1:
            for flow in lst_initiated_time[connect].flows_list:
                if lst_flows[flow].status_code=="200":
                    for packet in lst_initiated_time[connect].packet_list:
                        if lst_packets[str(packet)].flow_number==None:
                            lst_flows[flow].packet_list.append(lst_packets[str(packet)].frame_number)
                            lst_packets[str(packet)].flow_number=lst_flows[flow].flow_number
            continue

        pre_flow = None
        last_packet = None
        for flow in lst_initiated_time[connect].flows_list:
            if lst_flows[flow].status_code == "200":
                if pre_flow==None:
                    pre_flow = flow
                    continue
            else:
                continue

            for packet in lst_initiated_time[connect].packet_list:
                if lst_packets[str(packet)].flow_number == None:
                    if Decimal(lst_packets[str(packet)].time_epoch) < Decimal(lst_flows[flow].request_timestamp_start):
                        lst_packets[str(packet)].flow_number = lst_flows[pre_flow].flow_number
                        lst_flows[pre_flow].packet_list.append(lst_packets[str(packet)].frame_number)
                    else:
                        # try:
                        #     pass
                        #     # temp = lst_flows[pre_flow].packet_list.pop()
                        #     # # print(temp)
                        #     # lst_flows[flow].packet_list.append(temp)
                        # except:
                        #     print(lst_initiated_time[connect].src_tcp_stream, " - ", lst_initiated_time[connect].dst_tcp_stream)
                        #     # print(e)
                        #     print(lst_flows[pre_flow].flow_number, " - ", lst_flows[flow].flow_number, " - ", lst_flows[flow].request_timestamp_start)
                        #     exit()
                        # # lst_packets[str(last_packet)].flow_number = pre_flow
                        # lst_flows[flow].packet_list.append(str(packet))
                        # lst_packets[str(packet)].flow_number = lst_flows[flow].flow_number
                        pre_flow = flow
                        break
                    # last_packet = str(packet)
        for packet in lst_initiated_time[connect].packet_list:
            if lst_packets[str(packet)].flow_number == None:
                lst_flows[flow].packet_list.append(lst_packets[str(packet)].frame_number)
                lst_packets[str(packet)].flow_number = lst_flows[flow].flow_number
    return lst_flows, lst_packets

