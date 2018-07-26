#!/usr/bin/env python

import os
import re
import numpy as np
import matplotlib as mpl
import matplotlib.pyplot as plt
import brewer2mpl
from scipy.interpolate import spline
from matplotlib.ticker import MultipleLocator, FormatStrFormatter

bmap = brewer2mpl.get_map('Set1', 'qualitative', 5)
colors = bmap.mpl_colors
# mpl.rcParams['axes.color_cycle'] = colors


counts = 60

timeline = np.array(range(0, counts, 1))
timeline = timeline / float(8)

def extract_server_pps(filename):
    f = open('data/' + filename, 'r')
    timeline = []
    tcp_pkts = []
    attack_pkts = []
    pattern = re.compile(r'(\d+\.\d+),(\d+),(\d+)')
    for line in f.readlines():
        match = pattern.match(line)
        if match:
            timeline.append(float(match.group(1)))
            tcp_pkts.append(int(match.group(2)) * 1000)
            attack_pkts.append(int(match.group(3)) * 1000)
    f.close()
    return timeline, tcp_pkts, attack_pkts

def extract_proxy_entry_number(filename):
    f = open('data/' + filename, 'r')
    status = []
    counter = []
    counter.append(0)
    counter.append(0)
    counter.append(0)
    for line in f.readlines():
        lines = line.split(' ')
        #print lines
        if lines[0] == 'proxy_status:':
            if(int(lines[1]) == -1):
                status.append(0)
            else:
                status.append(int(lines[1]))
        elif lines[0] == 'proxy_table_entry_counter:':
            counter.append(int(lines[1]))
    f.close()
    return status, counter

proxy_status, entry_counter = extract_proxy_entry_number('output.txt')

resize_metric = 100

client_timeline, client_tcp, client_attack = extract_server_pps('client_1ms.csv')
counter = 0
tcp_pkts_sum = 0
attack_pkts_sum = 0
timeline = []
tcp = []
attack = []
for i in range(0, len(client_timeline)):
    tcp_pkts_sum = tcp_pkts_sum + client_tcp[i]
    attack_pkts_sum = attack_pkts_sum + client_attack[i]
    counter = counter + 1
    if counter == resize_metric:
        timeline.append(client_timeline[i - resize_metric + 1])
        tcp.append(tcp_pkts_sum / float(resize_metric))
        attack.append(attack_pkts_sum / float(resize_metric))
        tcp_pkts_sum = 0
        attack_pkts_sum = 0
        counter = 0
client_timeline = timeline
client_tcp = tcp
client_attack = attack

server_timeline, server_tcp, server_attack = extract_server_pps('server_1ms.csv')
counter = 0
tcp_pkts_sum = 0
attack_pkts_sum = 0
timeline = []
tcp = []
attack = []
for i in range(0, len(server_timeline)):
    tcp_pkts_sum = tcp_pkts_sum + server_tcp[i]
    attack_pkts_sum = attack_pkts_sum + server_attack[i]
    counter = counter + 1
    if counter == resize_metric:
        timeline.append(server_timeline[i - resize_metric + 1])
        tcp.append(tcp_pkts_sum / float(resize_metric))
        attack.append(attack_pkts_sum / float(resize_metric))
        tcp_pkts_sum = 0
        attack_pkts_sum = 0
        counter = 0
server_timeline = timeline
server_tcp = tcp
server_attack = attack


start_point = 80
end_point = -50
start_time = start_point / 10
end_time = 35 + end_point / 10

xmajorLocator   = MultipleLocator(5)
xmajorFormatter = FormatStrFormatter('%1d')
xminorLocator   = MultipleLocator(2.5)

ymajorLocator   = MultipleLocator(1000)
ymajorFormatter = FormatStrFormatter('%4d')
yminorLocator   = MultipleLocator(500)

plt.figure(figsize=(8, 12))
ax = plt.subplot(311)

ax.xaxis.set_major_locator(xmajorLocator)
ax.xaxis.set_major_formatter(xmajorFormatter)

ax.yaxis.set_major_locator(ymajorLocator)
ax.yaxis.set_major_formatter(ymajorFormatter)

ax.xaxis.set_minor_locator(xminorLocator)
ax.yaxis.set_minor_locator(yminorLocator)

ax.xaxis.grid(True, which='major', ls='dotted')
ax.yaxis.grid(True, which='major', ls='dotted')

plt.ylim(0, 5000)
plt.xlim(start_time, end_time)
plt.plot(client_timeline[start_point:end_point], client_tcp[start_point:end_point], '-', label="TCP Packets", color=colors[0])
plt.plot(client_timeline[start_point:end_point], client_attack[start_point:end_point], '-', label="Attack SYN Packets", color=colors[1])

legend = plt.legend(loc='upper left', shadow=False)

# for label in ax.xaxis.get_ticklabels():
#     label.set_fontsize(20)
# for label in ax.yaxis.get_ticklabels():
#     label.set_fontsize(20)

plt.xlabel('Time(s)')
plt.ylabel('Speed(pps)')

bx = plt.subplot(312)

bx.xaxis.set_major_locator(xmajorLocator)
bx.xaxis.set_major_formatter(xmajorFormatter)

bx.yaxis.set_major_locator(ymajorLocator)
bx.yaxis.set_major_formatter(ymajorFormatter)

bx.xaxis.set_minor_locator(xminorLocator)
bx.yaxis.set_minor_locator(yminorLocator)

bx.xaxis.grid(True, which='major', ls='dotted')
bx.yaxis.grid(True, which='major', ls='dotted')

plt.ylim(0, 5000)
plt.xlim(start_time, end_time)
plt.plot(server_timeline[start_point:end_point], server_tcp[start_point:end_point], '-', label="TCP Packets", color=colors[0])
plt.plot(server_timeline[start_point:end_point], server_attack[start_point:end_point], '-', label="Attack SYN Packets", color=colors[1])

legend = plt.legend(loc='upper left', shadow=False)

# for label in bx.xaxis.get_ticklabels():
#     label.set_fontsize(20)
# for label in bx.yaxis.get_ticklabels():
#     label.set_fontsize(20)

plt.xlabel('Time(s)')
plt.ylabel('Speed(pps)')


ymajorLocatorEntry   = MultipleLocator(10)
ymajorFormatterEntry = FormatStrFormatter('%2d')
yminorLocatorEntry   = MultipleLocator(5)

cx = plt.subplot(313)

cx.xaxis.set_major_locator(xmajorLocator)
cx.xaxis.set_major_formatter(xmajorFormatter)

cx.yaxis.set_major_locator(ymajorLocatorEntry)
cx.yaxis.set_major_formatter(ymajorFormatterEntry)

cx.xaxis.set_minor_locator(xminorLocator)
cx.yaxis.set_minor_locator(yminorLocatorEntry)

cx.xaxis.grid(True, which='major', ls='dotted')
cx.yaxis.grid(True, which='major', ls='dotted')

plt.ylim(0, 60)
plt.xlim(start_time, end_time)
plt.plot(np.linspace(0, max(client_timeline), num=len(entry_counter)), entry_counter, '-', label="Valid Entry Number of Proxy Table", color=colors[0])

# legend = plt.legend(loc='upper left', shadow=False, fontsize=20)

# for label in cx.xaxis.get_ticklabels():
#     label.set_fontsize(20)
# for label in cx.yaxis.get_ticklabels():
#     label.set_fontsize(20)

plt.xlabel('Time(s)')
plt.ylabel('Num. of Valid Entries in Proxy Table')

plt.savefig('figure.pdf')
plt.show()
