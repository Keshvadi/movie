import os
import sys
import webbrowser
import urllib.request

from comparison import *
from packet import *
from player import show_player_logs
from statics import *


''' Fix
This function removes all html files in the output folder.

todo:
- Remove other files like Javascript, CSS, ... files
- Check output folder first
'''
# Remove all previous html outputs
def remove_previous_outputs():
    try:
        make_output_folder()
        # if os.path.isdir("output")==False:
            # os.mkdir("output")
            # make_output_folder()
        print("\nRemoving Previous outputs ...")
        cwd = os.getcwd() + "/output"
        lstFiles = os.listdir(cwd)
        for i in lstFiles:
            if i.endswith(".html"):
                os.remove(os.path.join(cwd, i))
        print("Done ! \n")
    except:
        print("Error in removing prevoius htmls files")
        print(str(sys.exc_info()))


# This function create the main page with tabs
def make_main_page_html(lst_sent_packets, lst_received_packets, lst_flows, lst_initiated_time, lst_players):
    header = create_header("Program Name", "")
    body = "<body> \n"

    # Add tabs to the main page`
    # Wireshark tab with general statics
    temp_headers, temp_data = general_wireshark_staticss(lst_sent_packets, lst_received_packets)
    general_wireshark_text = create_table_html(temp_headers, temp_data, get_table_id(), [25, 60, 15])
    general_wireshark_text += get_wireshark_graphs()

    # MITM tab with general statics
    temp_headers, temp_data = general_mitm_statics(lst_flows, lst_initiated_time)
    general_mitm_text = create_table_html(temp_headers, temp_data, get_table_id(), [25, 60, 15])
    general_mitm_text += get_mitm_graphs(lst_flows)

    # Players tab with general statics for every Player
    temp_headers, temp_data = general_player_staticss(lst_players)
    general_player_text = ""
    for p in temp_data:
        temp_headers[0] = "Player " + str(p)
        general_player_text += create_table_html(temp_headers, temp_data[p], get_table_id(), [25, 60, 15])
    general_player_text += get_player_timeline(lst_players)

    # Comarision tab with general statics
    general_comparison_text = compare_videos(lst_sent_packets, lst_received_packets, lst_flows, lst_initiated_time, lst_players)

    body += make_general_tabs(4, ["Packet View", "Flow View", "Player View", "Comparison"], ['<a href="wireshark.html" target="_blank"> Captured Packets</a>', '<a href="mitmFull.html" target="_blank"> MITM Trace</a>', '<a href="player.html" target="_blank"> Player log</a>', ""], [general_wireshark_text, general_mitm_text, general_player_text, general_comparison_text])

    create_page(header, body, "index")

# Make default headear for HTML page
def create_header(title, other_header_parts):
    text="""
    <head>
    <meta charset="UTF-8">
    <link rel="stylesheet" type="text/css" href="wiman.css">
    <title>%s</title>
    <script src="wiman.js"></script>
    %s
    </head>
    """%(title, other_header_parts)
    return text

# Create Wireshark page by using JQury to show big table
def create_wireshark_page(lst_packets):
    export_data_json_for_wireshark_table(lst_packets, "wireshark_table")
    header = create_header_table("Wireshark Log", "wireshark_table.json", "")
    body = """
    <body>
        <table id="example" class="display">
            <thead>
                <tr>
                    <th>%s</th>
                    <th>%s</th>
                    <th>%s</th>
                    <th>%s</th>
                    <th>%s</th>
                    <th>%s</th>
                    <th>%s</th>
                    <th>%s</th>
                    <th>%s</th>
                    <th>%s</th>
                    <th>%s</th>
                </tr>
            </thead>
            <tfoot>
                <tr>
                    <th>%s</th>
                    <th>%s</th>
                    <th>%s</th>
                    <th>%s</th>
                    <th>%s</th>
                    <th>%s</th>
                    <th>%s</th>
                    <th>%s</th>
                    <th>%s</th>
                    <th>%s</th>
                    <th>%s</th>
                </tr>
            </tfoot>
        </table>
    </body>
    """%("No.", "Time", "Type", "Source", "Destination", "Src Port", "Dst Port", "Length", "IP Version", "TCP Window Size", "Stream Number", "No.", "Time", "Type", "Source", "Destination", "Src Port", "Dst Port", "Length", "IP Version", "TCP Window Size", "Stream Number")
    create_page(header, body, "wireshark")

def create_mitm_page(lst_flows):
    create_mitm_pages(lst_flows, "Full")
    create_mitm_pages(lst_flows, "GET")
    create_mitm_pages(lst_flows, "POST")
    create_mitm_pages(lst_flows, "OTHER")


def create_mitm_pages(lst_flows, page_name):
    export_data_json_for_mitm_table(lst_flows, "mitm_table", page_name)
    header = create_header_table("MITM Log", ("mitm_table%s.json")%(page_name), "")
    body = """
    <body>
    <b> Keep the mouse over the Link to see the full path. </b> <br>
        <table id="example" class="display">
            <thead>
                <tr>
                    <th>%s</th>
                    <th>%s</th>
                    <th>%s</th>
                    <th>%s</th>
                    <th>%s</th>
                    <th>%s</th>
                    <th>%s</th>
                    <th>%s</th>
                    <th>%s</th>
                    <th>%s</th>
                    <th>%s</th>
                    <th>%s</th>
                    <th>%s</th>
                    <th>%s</th>
                    <th>%s</th>
                    <th>%s</th>
                    <th>%s</th>
                    <th>%s</th>
                    <th>%s</th>
                    <th>%s</th>
                </tr>
            </thead>
            <tfoot>
                <tr>
                    <th>%s</th>
                    <th>%s</th>
                    <th>%s</th>
                    <th>%s</th>
                    <th>%s</th>
                    <th>%s</th>
                    <th>%s</th>
                    <th>%s</th>
                    <th>%s</th>
                    <th>%s</th>
                    <th>%s</th>
                    <th>%s</th>
                    <th>%s</th>
                    <th>%s</th>
                    <th>%s</th>
                    <th>%s</th>
                    <th>%s</th>
                    <th>%s</th>
                    <th>%s</th>
                    <th>%s</th>
                </tr>
            </tfoot>
        </table>
    </body>
    """ % (
    "Flow", "Method", "Status Code", "Content Type", "Content Length (byte)", "URL", "HTTP Version", "Client IP", "MITM IP",
    "Server IP", "Client Port", "MITM Port", "Server Port", "Host", "Time", "Client Initiation Time",
    "Server Initiation Time", "Request Start Time", "Response Start Time", "Packet List", "Flow", "Method", "Status Code", "Content Type", "Content Length (byte)", "URL", "HTTP Version", "Client IP", "MITM IP",
    "Server IP", "Client Port", "MITM Port", "Server Port", "Host", "Time", "Client Initiation Time",
    "Server Initiation Time", "Request Start Time", "Response Start Time", "Packet List")
    create_page(header, body, ("mitm%s")%(page_name))


# This text is header of HTML files that uses JQuery to create big tables
table_javascript_header = """
<link rel="stylesheet" type="text/css" href="https://cdn.datatables.net/v/dt/jq-3.2.1/moment-2.18.1/jszip-2.5.0/pdfmake-0.1.32/dt-1.10.16/af-2.2.2/b-1.5.1/b-colvis-1.5.1/b-flash-1.5.1/b-html5-1.5.1/b-print-1.5.1/fh-3.1.3/r-2.2.1/sc-1.4.4/datatables.min.css">
<script type="text/javascript" charset="utf-8" src="https://cdn.datatables.net/v/dt/jq-3.2.1/moment-2.18.1/jszip-2.5.0/pdfmake-0.1.32/dt-1.10.16/af-2.2.2/b-1.5.1/b-colvis-1.5.1/b-flash-1.5.1/b-html5-1.5.1/b-print-1.5.1/fh-3.1.3/r-2.2.1/sc-1.4.4/datatables.min.js"></script>
<script type="text/javascript" charset="utf-8" src="js/dataTables.editor.min.js"></script>
<script type="text/javascript" charset="utf-8" src="js/editor.bootstrap4.min.js"></script>
<script type="text/javascript" charset="utf-8" src="js/table.stonefinderstones.js"></script>
<script type="text/javascript" charset="utf-8" src="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/js/bootstrap.bundle.min.js"></script>
<script>
    $(document).ready(function() {
        $('#example').DataTable( {
            "ajax": "my_data.json", "pageLength": 50
        } );
    } );
</script>
"""



table_id = -1
def get_table_id():
    global table_id
    table_id+= 1
    return table_id



def make_html_output(text, file_name):
    try:
        if not os.path.exists("output/"):
            os.makedirs("output/")
        path = "output/" + file_name + ".html"
        if os.path.exists(path):
            os.remove(path)
        a = open(path, "a")
        a.write(text)
    except FileNotFoundError:
        print("Error in write output in output folder\n", sys.exc_info()[1])
    # os.system("open http://localhost:8080")
    # webbrowser.open(path)

def create_page(header, body, name):
    text = """
    <html lang="en">
        %s
        %s
    </html>
    """%(header, body)
    make_html_output(text, name)


def create_header_table(title, file_name, other_header_parts):
    text="""
    <head>
        <title>%s</title>
        <link rel="stylesheet" type="text/css" href="https://cdn.datatables.net/v/dt/jq-3.2.1/moment-2.18.1/jszip-2.5.0/pdfmake-0.1.32/dt-1.10.16/af-2.2.2/b-1.5.1/b-colvis-1.5.1/b-flash-1.5.1/b-html5-1.5.1/b-print-1.5.1/fh-3.1.3/r-2.2.1/sc-1.4.4/datatables.min.css">
		<script type="text/javascript" charset="utf-8" src="https://cdn.datatables.net/v/dt/jq-3.2.1/moment-2.18.1/jszip-2.5.0/pdfmake-0.1.32/dt-1.10.16/af-2.2.2/b-1.5.1/b-colvis-1.5.1/b-flash-1.5.1/b-html5-1.5.1/b-print-1.5.1/fh-3.1.3/r-2.2.1/sc-1.4.4/datatables.min.js"></script>
		<script type="text/javascript" charset="utf-8" src="js/dataTables.editor.min.js"></script>
		<script type="text/javascript" charset="utf-8" src="js/editor.bootstrap4.min.js"></script>
		<script type="text/javascript" charset="utf-8" src="js/table.stonefinderstones.js"></script>
		<script type="text/javascript" charset="utf-8" src="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/js/bootstrap.bundle.min.js"></script>

    <script>
        $(document).ready(function() {
    $('#example').dataTable( {
        "ajax": "%s", "lengthMenu": [ [10, 25, 50, 100, 1000, -1], [10, 25, 50, 100, 1000, "All"] ], "pageLength": 10, "autoWidth":true, fixedHeader: {header: true, footer: true}, "displayStart": 0, "pagingType": "full_numbers"
    } );
} );
    </script>
        %s
    </head>
    """%(title, file_name, other_header_parts)
    return text


def create_table_page(title_page, headers:list, data:dict ):
    n = 0
    text = "<body> \n"
    text+='<script src="wiman.js"></script>'
    text += '<table id="myTable" > \n'
    text += "<tr> "
    for i in headers:
        if str(i) == "Number":
            text+='<th onclick="sortNumTable(0)"> %s </th>'%(str(i))
        else:
            text+='<th onclick="sortTable(%s)"> %s </th>'%(n, str(i))
        n+=1
    text+="</tr> \n"

    for i in data:
        text += "<tr> "
        for j in data[i]:
            text+="<td> %s </td>"%(str(j))
        text+="</tr> \n"
    text += "</body>\n"

    create_page(create_header(title_page, ""), text, title_page)
    return text

'''
<button class="tablink" onclick="openPage('Home', this, 'red')">Home</button>
<button class="tablink" onclick="openPage('News', this, 'green')" id="defaultOpen">News</button>
<button class="tablink" onclick="openPage('Contact', this, 'blue')">Contact</button>
<button class="tablink" onclick="openPage('About', this, 'orange')">About</button>

'''



def make_general_tabs(number_of_tabs, tab_names:list, tab_titles:list, tab_texts:list):
    text = ""
    for i in range(number_of_tabs):
        text+= '<button class="tablink" onclick="openPage'
        text+= "('%s', this, 'red')"%(tab_names[i])
        if i==0:
            text+= '" id="defaultOpen'
        text+= '">%s</button>\n'%(tab_names[i])

    # make div for tabs
    for i in range(number_of_tabs):
        text += '''
        <div id="%s" class="tabcontent">
        <h3>%s</h3>
        <p>%s</p>
        </div>
        '''%(tab_names[i], tab_titles[i], tab_texts[i])
    text+="""
    <script>
    document.getElementById("defaultOpen").click();
    </script>
    """
    text += "\n </body>"
    return text

def create_index_page(page_name, page_title, number_of_tabs:list, tab_names:list, tab_texts:list):
    tab_titles = ""
    header = create_header(page_title, "")
    text = make_general_tabs(number_of_tabs,tab_names, tab_titles, tab_texts)
    create_page(header, text, "index")


def create_html_page(page_name, title, body_text, suffix):
    text = """
    <html>
    <head>
    <title> %s </title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css">
    <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.3.1/jquery.min.js"></script>
    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js"></script>
    </head>
    <body>
    %s
    </body>
    </html>
    """ % (title, body_text)
    file_name = str(page_name) + suffix
    if os.path.exists(file_name):
        os.remove(file_name)
    a = open(file_name, "a")
    a.write(text)
    a.close()


'''
not main pages
'''


def get_other_requests_info(lst_flows):
    text = ""
    for f in lst_flows:
        if ((lst_flows[f].method != "GET") and (lst_flows[f].method != "POST")):
            text += "<pr> <br> <h4> Method = "
            text += str(lst_flows[f].method) + "</h4> Request URL = <b>" + str(
                lst_flows[f].host + " </b>| Timestamp = <b>" + lst_flows[f].client_initiated_time) + "</b><br>"
            text += "</pr>"
            continue
    return text


def make_protocol_html(lst_protocol):
    text = ""
    text += '<br><img src="protocols.svg" alt="Protocols" width="100%"> <hr>'
    for p in lst_protocol:
        text += "<b>" + str(p) + " : </b>" + str(len(lst_protocol[p])) + " packets" + "<br>"

    create_html_page("protocols_types", "Protocols Types", text, ".html")


# make_protocol_html()


def make_graph_page_html(page_name, image_name, alt):
    text = ""
    text += '<br><img src="' + image_name + '" alt="test" width="1200"> <hr>'
    create_html_page(page_name, alt, text, ".svg")


'''
Main Pages
'''




# def mainHTML():
#     numberOfFlows = getNumberOfFlows()
#     numberOfGETRequest = getNumberOfGETRequests()
#     numberOfPOSTRequest = getNumberOfPOSTRequests()
#     totalBit = getTotalBit(lstPackets)
#     numberOfConnection = getNumberOfInitConnection()
#     bitrate = getBitRate(lstPackets)
#     text = """
#     <html>
#     <head>
#     <title> Main Page </title>
#     <meta name="viewport" content="width=device-width, initial-scale=1">
#     <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css">
#     <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.3.1/jquery.min.js"></script>
#     <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js"></script>
#     </head>
#     <body>
#     <div class="container">
#     <h2>Request lists</h2>
#     <p><strong>Note:</strong> This list provides the get/put requests. <br> Click on them for more info.</p>
#     <div class="panel-group" id="flows">
#     <div class="panel panel-default">
#     <div class="panel-heading">
#     <h4 class="panel-title">
#     <a data-toggle="collapse" data-parent="#flows" href="#collapse0">General Info</a>
#     </h4>
#     </div>
#     <div id="collapse0" class="panel-collapse collapse in">
#     <div class="panel-body">
#     <b>Number Of Requests = %s
#     <br><b>Number Of Get Requests = %s
#     <br><b>Number Of POST Requests = %s
#     <br><b>Total bits = %s bits
#     <br><b>Number of Connections = %s
#     <br><b>Bitrate = %s
#     </div>
#     </div>
#     </div>
#     """%(str(numberOfFlows), str(numberOfGETRequest), str(numberOfPOSTRequest), str(totalBit), str(numberOfConnection), str(bitrate))
#     for f in lstFlows:
#         text += '<div class="panel panel-default">'
#         text += '<div class="panel-heading">'
#         text += '<h4 class="panel-title">'
#         text += '<a data-toggle="collapse" data-parent="#flows" href="#collapse%s">Flow %s - %s </a>' % (str(lstFlows[f].flowNumber), str(lstFlows[f].flowNumber), str(lstFlows[f].getFlowInfoShortHTML()))
#         text += '</h4> \n </div>'
#         text += '''
#         <div id="collapse%s" class="panel-collapse collapse">
#         <div class="panel-body">%s</div>
#         </div>
#         </div>
#         ''' % (str(lstFlows[f].flowNumber), lstFlows[f].getFlowInfoHTML())
#         # text += '<a href="' + f.flowNumber + '.html"> - More Details </a> <br> ' + "\n"
#         for p in lstPackets:
#             if lstPackets[p].frame_number in lstFlows[f].packetList:
#                 text += lstPackets[p].type
#     text += "</div> </div> </body> </html>"
#     fileName = str("index.html")
#     a = open(fileName, "a")
#     a.write(text)
#

'''
Functions for making output
'''


def get_wireshark_trace_path():
    path = os.getcwd() + "/wireshark.pcapng"
    return path


'''
This part shows the results in HTML output
'''


# def mainHTML():
#     text = """
#     <html>
#     <head>
#     <title> Main Page </title>
#     <meta name="viewport" content="width=device-width, initial-scale=1">
#     <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css">
#     <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.3.1/jquery.min.js"></script>
#     <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js"></script>
#     </head>
#     <body>
#     <div class="container">
#     <h2>Request lists</h2>
#     <p><strong>Note:</strong> This list provides the get/put requests. <br> Click on them for more info.</p> <br>
#     <p>
#     <h4 style="margin-top: 1px; margin-bottom: 1px"> Wireshark trace file | <a href="wireshark.pcapng" target="_blank"> Pcap </a>| <a href="wireshark.json" target="_blank"> JSON </a> | <a href="/main/wireshark.xml" target="_blank"> XML </a> </h4><br>
#     <h4 style="margin-top: 1px; margin-bottom: 1px"> MITM proxy log | <a href="flows.json" target="_blank"> JSON </a> </h4> <br>
#     <h4 style="margin-top: 1px; margin-bottom: 1px"> XYZ proxy log | <a href="/main/player.json" target="_blank"> JSON </a> </h4> <br>
#     </p>
#
#     <div class="panel-group" id="flows">
#     <div class="panel panel-default">
#     <div class="panel-heading">
#     <h4 class="panel-title">
#     <a data-toggle="collapse" data-parent="#flows" href="#collapse0">General Info</a>
#     </h4>
#     </div>
#     <div id="collapse0" class="panel-collapse collapse in">
#     <div class="panel-body">
#
#     <!-- General Statics -->
#     <b>Date </b>= %s
#     <br><b>Start Time </b>= %s
#     <br><b>Stop Time </b>= %s
#     <br><b>Duration </b>= %s (sec)
#
#     <!-- MITM General Statics -->
#     <br><b>Number Of URL Requests </b>= %s
#     <br><b> * Number of Get Requests </b>= %s
#     <br><b> * Number of POST Requests </b>= %s
#     <br><b> * Number of the other Requests types</b>= %s | <a href="other_requests.html"> See </a>
#     <br><b>Number of initiated connections </b>= %s
#
#     <!-- Wireshark General Statics -->
#     <br>
#     <br><b>Number of captured packets </b>= %s packets
#     <br><b> * Number of TCP packets </b>= %s packets
#     <br><b> * Number of UDP packets </b>= %s packets
#     <br><b> * Number of DNS packets </b>= %s packets
#     <br><b> * Number of the other types </b>= %s packets
#     <br><b> ** Packet Lists by protocol type </b> | <a href="protocols_types.html"> See </a>
#     <br>
#     <br><b>Total Captured Bytes</b>= %s bytes
#     <br><b>Total Captured Packets</b>= %s packets
#     <br><b>Average Packet Size</b>= %s bytes
#     <br><b>Bitrate </b>= %s (bps)
#     <br><b>Packet Rate</b>= %s (packet per sec)
#
#     <br><br><b>Charts
#     </br> See the <b><a href="packets.svg"> Packets per sec chart</a></b>
#     </br> See the <b><a href="bytes.svg"> Bytes per sec chart</a></b>
#     </br> See the <b><a href="cdf_packets.svg"> CDF - Packets per sec chart</a></b>
#     </br> See the <b><a href="pdf_packets.svg"> PDF - Packets per sec chart</a></b>
#     </br> See the <b><a href="cdf_bytes.svg"> CDF - Bytes per sec chart</a></b>
#     </br> See the <b><a href="pdf_bytes.svg"> PDF - Bytes per sec chart</a></b>
#     <br><br>
#     <a href = "https://plot.ly/~keshvadi/14/"> View Server Distribution Chart </a>
#     </div>
#     </div>
#     </div>
#     """ % (
#         str(lst_packets["1"].frame_time),  # Date
#         str(start_time),  # Start Time
#         str(stop_time),  # Stop Time
#         str(duration),  # Duration Time
#         str(number_of_flows),
#         str(number_of_get_requests),
#         str(number_of_post_requests),
#         str(number_of_other_requests),
#         str(number_of_initiated_connection),
#         str(number_of_packets),
#         str(number_of_tcp_packets),
#         str(number_of_udp_packets),
#         str(number_of_dns_packets),
#         str(number_of_other_packets),
#         str(total_bytes),
#         str(number_of_packets),
#         str("%.2f" % (float(average_packet_size))),
#         str("%.2f" % (float(bit_rate))),
#         str("%.2f" % (float(packet_rate))),
#     )
#     create_html_page("other_requests", "Other Request Types", get_other_requests_info(), ".html")
#     make_graph_page_html("packet_per_sec", "packets.svg", "Packet per seconds")
#     make_graph_page_html("bytes_per_sec", "bytes.svg", "Packet per seconds")
#     make_graph_page_html("cdf_packet_per_sec", "cdf_packets.svg", "Packet per seconds")
#     make_graph_page_html("pdf_packet_per_sec", "pdf_packets.svg", "Packet per seconds")
#     make_graph_page_html("cdf_byte_per_sec", "cdf_bytes.svg", "Packet per seconds")
#     make_graph_page_html("pdf_byte_per_sec", "pdf_bytes.svg", "Packet per seconds")
#     # create_html_page("protocols_types", "Protocols Types", get_protocol_types_html(), ".html")
#     for f in lst_flows:
#         text += '<div class="panel panel-default">'
#         text += '<div class="panel-heading">'
#         text += '<h4 class="panel-title">'
#         text += '<a data-toggle="collapse" data-parent="#flows" href="#collapse%s">Flow %s - %s </a>' % (
#             str(lst_flows[f].flow_number), str(lst_flows[f].flow_number), str(lst_flows[f].get_short_flow_info_html()))
#         text += '</h4> \n </div>'
#         text += '''
#         <div id="collapse%s" class="panel-collapse collapse">
#         <div class="panel-body">%s</div>
#         </div>
#         </div>
#         ''' % (str(lst_flows[f].flow_number), lst_flows[f].get_full_flow_info_html())
#         # text += '<a href="' + f.flowNumber + '.html"> - More Details </a> <br> ' + "\n"
#
#     text += "</div> </div> </body> </html>"
#     file_name = str("index.html")
#     if os.path.exists(file_name):
#         os.remove(file_name)
#     a = open(file_name, "a")
#     a.write(text)





def create_table_html(headers:list, data:dict, table_id, table_width):
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
        n = 0
        for j in data[i]:
            text+='<td width="%s%%"> %s </td>'%(int(table_width[n]), str(j))
            n+=1
        text+="</tr> \n"
    text += "</table> "
    return text

def create_all_flow_pages_html(lst_packets, lst_flows):
    for f in lst_flows:
        text = """
        <html>
        <head>
        <title> Flow #%s Info </title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css">
        <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.3.1/jquery.min.js"></script>
        <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js"></script>
        </head>
        <body>
        <div class="container">
        <h2>Packet list of Flow #%s</h2>
        <p><strong>Info:</strong> This list provides the wireshark captured packets related to the flow. Click on each packet to find more info.</p>
        <div class="panel-group" id="flows">
        <div class="panel panel-default">
        <div class="panel-heading">
        <h4 class="panel-title">
        <a data-toggle="collapse" data-parent="#packets" href="#collapse0">General Info</a>
        </h4>
        </div>
        <div id="collapse0" class="panel-collapse collapse in">
        <div class="panel-body">
        <br><b>Number Of Packets <b>= %s
        <br><b>Data Type <b>= %s
        <br><b>Duration <b>= %s
        <br><b>Total bits <b>= %s bits
        <br><b>Bitrate <b>= %s bits
        <br><b>Number of TCP Connections <b>= %s
        <br><b>Number of UDP Connections <b>= %s
        </div>
        </div>
        </div>
        """ % (str(lst_flows[f].flow_number),
               str(lst_flows[f].flow_number),
               str(len(lst_flows[f].packet_list)),
               str(lst_flows[f].content_type),
               str(0),
               # str(getDuration(lstFlows[f].packetList)),
               # str(getTotalBit(lstFlows[f].packetList)),
               # str(getBitRate(lstFlows[f].packetList)),
               str(0),
               "0",
               "0",
               "0"
               )
        for p in lst_flows[f].packet_list:
            text += """
            <div class="panel panel-default">
            <div class="panel-heading">
            <h4 class="panel-title">
            <a data-toggle="collapse" data-parent="#packets" href="#collapse%s">Packet %s </a>
            </h4> \n </div>
            <div id="collapse%s" class="panel-collapse collapse">
            <div class="panel-body">%s</div>
            </div>
            </div>
            """ % (str(lst_packets[str(p)].frame_number),
                   str(lst_packets[str(p)].frame_number),
                   str(lst_packets[str(p)].frame_number),
                   str(lst_packets[str(p)].html_info))

        # text += '<br><h3><a href="index.html">Main Page </a></h3>'
        file_name = str("output/flow" + str(lst_flows[f].flow_number) + ".html")
        if os.path.exists(file_name):
            os.remove(file_name)
        a = open(file_name, "a")
        a.write(text)


def create_player_page(lst_players):
    header = create_header("Player Log", "")
    body = "<body> \n"
    temp_headers, temp_data = show_player_logs(lst_players)
    player_log = create_table_html(temp_headers, temp_data, get_table_id(), [20]*len(temp_headers))
    body += player_log
    create_page(header, body, "player")


def get_player_timeline(lst_players: Dict[int, Player]):
    txt = '''
    <h2>Player Activities Timeline</h2>
    <div class="timeline" style="background-color:#474e5d;">
    '''

    n = 0
    for i in lst_players:
        for j in lst_players[i].events:
            if (n%2)==0:
                txt+='<div class="container right">'
            else:
                txt+='<div class="container right">'
            txt +='<div class="content">'
            txt += '<h3>Player Time: %s (sec)</h3>'%(str(format(Decimal(j.time)/1000, '.6f')))
            txt += '<p><b>Event: </b>%s</p>'%(j.key)
            txt += '<p><b>Value: </b>%s</p>'%(j.value)
            txt += '</div></div>'
            n+=1
    txt+='</div></div>'
    return txt

def is_file_exist(file_name):
    if os.path.exists(file_name):
        return True
    else:
        return False

def make_output_folder():
    if os.path.isdir("output")==False:
        os.mkdir("output")

    if os.path.isdir("output/js")==False:
        os.mkdir("output/js")

    if is_file_exist("easylist.txt"):
        pass
    else:
        url = "http://pages.cpsc.ucalgary.ca/~sina.keshvadi1/view/code/easylist.txt"
        urllib.request.urlretrieve(url, "easylist.txt")

    if is_file_exist("output/bootstrap.bundle.min.js"):
        pass
    else:
        url = "http://pages.cpsc.ucalgary.ca/~sina.keshvadi1/view/output/bootstrap.bundle.min.js"
        urllib.request.urlretrieve(url, "output/bootstrap.bundle.min.js")

    if is_file_exist("output/datatables.css"):
        pass
    else:
        url = "http://pages.cpsc.ucalgary.ca/~sina.keshvadi1/view/output/datatables.css"
        urllib.request.urlretrieve(url, "output/datatables.css")

    if is_file_exist("output/datatables.js"):
        pass
    else:
        url = "http://pages.cpsc.ucalgary.ca/~sina.keshvadi1/view/output/datatables.js"
        urllib.request.urlretrieve(url, "output/datatables.js")

    if is_file_exist("output/datatables.min.css"):
        pass
    else:
        url = "http://pages.cpsc.ucalgary.ca/~sina.keshvadi1/view/output/datatables.min.css"
        urllib.request.urlretrieve(url, "output/datatables.min.css")

    if is_file_exist("output/datatables.min.js"):
        pass
    else:
        url = "http://pages.cpsc.ucalgary.ca/~sina.keshvadi1/view/output/datatables.min.js"
        urllib.request.urlretrieve(url, "output/datatables.min.js")

    if is_file_exist("output/json_demo_db_post.php"):
        pass
    else:
        url = "http://pages.cpsc.ucalgary.ca/~sina.keshvadi1/view/output/json_demo_db_post.php"
        urllib.request.urlretrieve(url, "output/json_demo_db_post.php")

    if is_file_exist("output/wiman.css"):
        pass
    else:
        url = "http://pages.cpsc.ucalgary.ca/~sina.keshvadi1/view/output/wiman.css"
        urllib.request.urlretrieve(url, "output/wiman.css")

    if is_file_exist("output/wiman.js"):
        pass
    else:
        url = "http://pages.cpsc.ucalgary.ca/~sina.keshvadi1/view/output/wiman.js"
        urllib.request.urlretrieve(url, "output/wiman.js")

    if is_file_exist("output/js/dataTables.editor.min.js"):
        pass
    else:
        url = "http://pages.cpsc.ucalgary.ca/~sina.keshvadi1/view/output/js/dataTables.editor.min.js"
        urllib.request.urlretrieve(url, "output/js/dataTables.editor.min.js")

    if is_file_exist("output/js/editor.bootstrap4.min.js"):
        pass
    else:
        url = "http://pages.cpsc.ucalgary.ca/~sina.keshvadi1/view/output/js/editor.bootstrap4.min.js"
        urllib.request.urlretrieve(url, "output/js/editor.bootstrap4.min.js")

    if is_file_exist("output/js/table.stonefinderstones.js"):
        pass
    else:
        url = "http://pages.cpsc.ucalgary.ca/~sina.keshvadi1/view/output/js/table.stonefinderstones.js"
        urllib.request.urlretrieve(url, "output/js/table.stonefinderstones.js")

    # if is_file_exist("output/dataTables.editor.min.js"):
    #     pass
    # else:
    #     url = "http://pages.cpsc.ucalgary.ca/~sina.keshvadi1/view/output/bootstrap.bundle.min.js"
    #     urllib.request.urlretrieve(url, "output/bootstrap.bundle.min.js")


