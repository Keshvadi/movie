from typing import List

from packet import *
import matplotlib.pyplot as plt

# from wiman import *
# from wiman import lst_packets


def html_pie_chart(pie_id, title, width, height, pie_data:List[List]):
    html_text = ""
    html_text += """
    <div id="%s">
    </div>
        <script type="text/javascript" src="https://www.gstatic.com/charts/loader.js"></script>
        <script type="text/javascript">
        
        // Load google charts
        google.charts.load('current', {'packages':['corechart']});
        google.charts.setOnLoadCallback(drawChart);
        // Draw the chart and set the chart values
        function drawChart() {
            var data = google.visualization.arrayToDataTable([
    """%(pie_id)
    # import data to the piechart
    html_text += ""
    first_row = True
    for row in pie_data:
        if first_row==True:
            html_text += "\n['%s', '%s']," % (row[0], row[1])
            first_row = False
        else:
            html_text+="\n['%s', %s],"%(row[0], row[1])
    # Remove Last camma
    html_text = html_text[:-1]

    html_text+= """
    ]);
    var options = {'title':'%s', 'width':%s, 'height':%s};
    // Display the chart inside the <div> element with id="piechart"
    var chart = new google.visualization.PieChart(document.getElementById(%s));
    chart.draw(data, options);
    }
    </script>
    """%(title, width, height, pie_id)

    return html_text

"""
    <div id="number_format_chart" align="center">
<!--Bar Chart-->
<script type="text/javascript" src="https://www.gstatic.com/charts/loader.js"></script>
<script type="text/javascript">
// Load google charts
      google.charts.load('current', {packages:['corechart', 'bar']});
      google.charts.setOnLoadCallback(drawStuff);

        function drawStuff() {
        var data = google.visualization.arrayToDataTable([
        ['City', '2010 Population', '2000 Population'],
        ['Total', 8175000, 8008000],
        ['Los Angeles, CA', 3792000, 3694000],
        ['Chicago, IL', 2695000, 2896000],
        ['Houston, TX', 2099000, 1953000],
        ['Philadelphia, PA', 1526000, 1517000]
            ]);
         var options = {
             title: 'GDP of selected countries, in US $millions',
             width: 1000,
             height: 600,
             chartArea: {width: '70%'},
             legend: 'none',
             colors:['#003f5c', '#c10b0b'],
             bar: {groupWidth: '95%'},
             vAxis: { gridlines: { count: 10 }, title: 'Number of Packets' },
             hAxis: { title: 'Protocol' }
         };

         var chart = new google.visualization.ColumnChart(document.getElementById('number_format_chart'));
         chart.draw(data, options);

         document.getElementById('format-select').onchange = function() {
           options['vAxis']['format'] = this.value;
           chart.draw(data, options);
         };
      }
</script>
"""
def html_two_bar_chart(chart_id, title, v_title, h_title, width, height, chart_data:List[List]):
    text_html = '<h2 style="background-color: #3098c1; padding: 10px;  text-align: center; font-size: 25px; color: white">Number of Packets</h2>'
    text_html += '<div id="%s" align="center">'%(chart_id)

    # Add scripts
    text_html+="""
    <!--Bar Chart-->
    <script type="text/javascript" src="https://www.gstatic.com/charts/loader.js"></script>
    <script type="text/javascript">
    // Load google charts
    google.charts.load('current', {packages:['corechart', 'bar']});
    google.charts.setOnLoadCallback(drawStuff);
    
    function drawStuff() {
    var data = google.visualization.arrayToDataTable([
    """
    first_row = True
    for row in chart_data:
        if first_row==True:
            text_html += "\n['%s', '%s', '%s']," % (row[0], row[1], row[2])
            first_row = False
        else:
            text_html +="\n['%s', %s, %s],"%(row[0], row[1], row[2])
    # Remove Last camma
    text_html = text_html[:-1]

    temp = ("""
                ]);
         var options = {
             title: '%s',
             width: %s,
             height: %s,
             chartArea: {width: '%%70'},
             legend: 'none',
             colors:['#003f5c', '#c10b0b'],
             bar: {groupWidth: '%%95'},
             vAxis: { gridlines: { count: 10 }, title: '%s' },
             hAxis: { title: '%s' }
         };

         var chart = new google.visualization.ColumnChart(document.getElementById('%s'));
         chart.draw(data, options);
      }
    </script>

    </div>
    
    """)%(title, width, height, v_title, h_title, chart_id)
    text_html+=temp

    return text_html



#
# def draw_protocols_pie_chart(lst_packets:Dict[str, Packet]):
#     tcp_packets, udp_packets, dns_packets, other_packets = classify_packets_by_protocols(lst_packets)
#     labels = []
#     sizes = []
#     labels.append("TCP")
#     labels.append("UDP")
#     labels.append("DNS")
#     labels.append("Other")
#     sizes.append(len(tcp_packets))
#     sizes.append(len(udp_packets))
#     sizes.append(len(dns_packets))
#     sizes.append(len(other_packets))
#
#     fig, ax = plt.subplots(figsize=(12, 6), subplot_kw=dict(aspect="equal"))
#     slices, texts, autotexts = ax.pie(labels, autopct='%1.1f%%', textprops=dict(color="w"))
#
#     ax.legend(slices, sizes, title="Protocols", loc="center left", bbox_to_anchor=(1, 0, 0.5, 1))
#
#     # size is font size on the pie chart.
#     plt.setp(autotexts, size=10, weight="bold")
#
#     ax.set_title("Protocols")
#     fig.savefig('protocols_full.svg')
#     plt.close()
#
#
# # labels = []
# # sizes = []
# # Test Classify the protocols
# # lst_protocol = classify_packets_by_protocols()
# # for i in lst_protocol:
# #     # print("Protocol: ", i, " - ", len(lst_result[i]), " packets")
# #     labels.append(str(i) + " - " + str(len(lst_protocol[i])) + " packets.")
# #     sizes.append(len(lst_protocol[i]))
# # draw_pie_chart_full(labels, sizes)
#
#
# '''
# Plot + Hyperlink
# '''
# # Packets per Sec
# lst_sec = {}  # {<sec, number of packets in the sec>}
# for p in lst_packets:
#     sec = int(float(lst_packets[p].frame_time_relative))
#     if sec in lst_sec:
#         lst_sec[sec] += 1
#     else:
#         lst_sec[sec] = 1
#
# lst_cdf = []
# for i in lst_sec:
#     lst_cdf.append(lst_sec[i])
#
# # CDF Plot (Packets per Second)
# sum = np.sum(lst_cdf)
# cum_lst_cdf = np.cumsum(lst_cdf)
# cum_lst_cdf = cum_lst_cdf / sum
# plt.title("CDF (Packets per Second)")
# plt.ylabel("CDF")
# plt.xlabel("Time (Sec)")
# plt.plot(range(len(cum_lst_cdf)), cum_lst_cdf)
# s = plt.scatter(range(len(cum_lst_cdf)), cum_lst_cdf)
# s.set_urls(['http://www.bbc.co.uk/news', 'http://www.google.com', 'http://www.uofc.ca'])
#
# plt.savefig(str(os.getcwd()) + "/cdf_packets.svg")
# # plt.show()
# plt.close()
#
# # PDf Plot (Packets per Second)
# lst_pdf = lst_cdf / sum
# plt.title("PDF (Packets per Second)")
# plt.ylabel("PDF")
# plt.xlabel("Time (Sec)")
# plt.plot(range(len(lst_pdf)), lst_pdf)
# plt.savefig(str(os.getcwd()) + "/pdf_packets.svg")
# # plt.show()
# plt.close()
#
# # Bytes per Sec
# lst_bytes_per_sec = {}  # {<sec, bytes in the sec>}
# for p in lst_packets:
#     sec = int(float(lst_packets[p].frame_time_relative))
#     if sec in lst_bytes_per_sec:
#         lst_bytes_per_sec[sec] += int(float(lst_packets[p].frame_len))
#     else:
#         lst_bytes_per_sec[sec] = int(float(lst_packets[p].frame_len))
#
# cdf_byte_per_sec = []
# for i in lst_bytes_per_sec:
#     cdf_byte_per_sec.append(lst_bytes_per_sec[i])
#
# # CDF Plot (Packets per Second)
# sum = np.sum(cdf_byte_per_sec)
# cum_lst_cdf = np.cumsum(cdf_byte_per_sec)
# cum_lst_cdf = cum_lst_cdf / sum
# plt.title("CDF (Bytes per Second)")
# plt.ylabel("CDF")
# plt.xlabel("Time (Sec)")
# plt.plot(range(len(cum_lst_cdf)), cum_lst_cdf)
# s = plt.scatter(range(len(cum_lst_cdf)), cum_lst_cdf)
# s.set_urls(['http://www.bbc.co.uk/news', 'http://www.google.com', 'http://www.uofc.ca'])
#
# plt.savefig(str(os.getcwd()) + "/cdf_bytes.svg")
# # plt.show()
# plt.close()
#
# # PDf Plot (Packets per Second)
# lst_pdf = cdf_byte_per_sec / sum
# plt.title("PDF (Bytes per Second)")
# plt.ylabel("PDF")
# plt.xlabel("Time (Sec)")
# plt.plot(range(len(lst_pdf)), lst_pdf)
# plt.savefig(str(os.getcwd()) + "/pdf_bytes.svg")
# # plt.show()
# plt.close()
#
# # Regular Plots
# # Packets per Sec
# lst_sec = {}  # {<sec, number of packets in the sec>}
# for p in lst_packets:
#     sec = int(float(lst_packets[p].frame_time_relative))
#     if sec in lst_sec:
#         lst_sec[sec] += 1
#     else:
#         lst_sec[sec] = 1
#
# lst_cdf = []
# for i in lst_sec:
#     lst_cdf.append(lst_sec[i])
#
# # CDF Plot (Packets per Second)
# sum = np.sum(lst_cdf)
# cum_lst_cdf = np.cumsum(lst_cdf)
# # cum_lst_cdf = cum_lst_cdf / sum
# plt.title("Cumulative Packets per Second")
# plt.ylabel("Packets")
# plt.xlabel("Time (Sec)")
# plt.plot(range(len(cum_lst_cdf)), cum_lst_cdf)
# s = plt.scatter(range(len(cum_lst_cdf)), cum_lst_cdf)
# s.set_urls(['http://www.bbc.co.uk/news', 'http://www.google.com', 'http://www.uofc.ca'])
#
# plt.savefig(str(os.getcwd()) + "/c_packets.svg")
# # plt.show()
# plt.close()
#
# # PDf Plot (Packets per Second)
# lst_pdf = lst_cdf
# plt.title("Packets per Second")
# plt.ylabel("Packets")
# plt.xlabel("Time (Sec)")
# plt.plot(range(len(lst_pdf)), lst_pdf)
# plt.savefig(str(os.getcwd()) + "/packets.svg")
# # plt.show()
# plt.close()
#
# # Bytes per Sec
# lst_bytes_per_sec = {}  # {<sec, bytes in the sec>}
# for p in lst_packets:
#     sec = int(float(lst_packets[p].frame_time_relative))
#     if sec in lst_bytes_per_sec:
#         lst_bytes_per_sec[sec] += int(float(lst_packets[p].frame_len))
#     else:
#         lst_bytes_per_sec[sec] = int(float(lst_packets[p].frame_len))
#
# cdf_byte_per_sec = []
# for i in lst_bytes_per_sec:
#     cdf_byte_per_sec.append(lst_bytes_per_sec[i])
#
# # CDF Plot (Packets per Second)
# sum = np.sum(cdf_byte_per_sec)
# cum_lst_cdf = np.cumsum(cdf_byte_per_sec)
# # cum_lst_cdf = cum_lst_cdf / sum
# plt.title("Cumulative Bytes per Second")
# plt.ylabel("Bytes")
# plt.xlabel("Time (Sec)")
# plt.plot(range(len(cum_lst_cdf)), cum_lst_cdf)
# s = plt.scatter(range(len(cum_lst_cdf)), cum_lst_cdf)
# s.set_urls(['http://www.bbc.co.uk/news', 'http://www.google.com', 'http://www.uofc.ca'])
#
# plt.savefig(str(os.getcwd()) + "/c_bytes.svg")
# # plt.show()
# plt.close()
#
# # PDf Plot (Packets per Second)
# lst_pdf = cdf_byte_per_sec
# plt.title("Bytes per Second")
# plt.ylabel("Bytes")
# plt.xlabel("Time (Sec)")
# plt.plot(range(len(lst_pdf)), lst_pdf)
# plt.savefig(str(os.getcwd()) + "/bytes.svg")
# # plt.show()
# plt.close()
#
#
# # def plotServerTypes():
# #     serverName = {}
# #     for f in lstFlows:
# #         if lstFlows[f].server == None:
# #             continue
# #         if str(lstFlows[f].server) in serverName:
# #             serverName[str(lstFlows[f].server)] +=1
# #         else:
# #             serverName[str(lstFlows[f].server)] =1
# #     labels = []
# #     values = []
# #     for i in serverName:
# #         labels.append(str(i))
# #         values.append(int(serverName[i]))
# #     trace = go.Pie(labels=labels, values=values)
# #     r = py.iplot([trace], filename='WebConnextions')
# #     print(r.resource)
# #
# #
# # plotServerTypes()
