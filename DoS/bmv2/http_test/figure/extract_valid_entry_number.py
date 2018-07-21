#!/usr/bin/env python

import os
import numpy as np
import matplotlib as mpl
import matplotlib.pyplot as plt
import brewer2mpl
from scipy.interpolate import spline
from matplotlib.ticker import MultipleLocator, FormatStrFormatter

bmap = brewer2mpl.get_map('Set1', 'qualitative', 5)
colors = bmap.mpl_colors
mpl.rcParams['axes.color_cycle'] = colors


counts = 60

timeline = np.array(range(0, counts, 1))
timeline = timeline / float(8)

def extract_proxy_entry_number(filename):
    f = open('data/' + filename, 'r')
    status = []
    counter = []
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
proxy_entry_length = len(entry_counter)


xmajorLocator   = MultipleLocator(1)
xmajorFormatter = FormatStrFormatter('%1.0f')
xminorLocator   = MultipleLocator(0.5)

ymajorLocator   = MultipleLocator(10)
ymajorFormatter = FormatStrFormatter('%1.0f')
yminorLocator   = MultipleLocator(5)

plt.figure(figsize=(10,6.5))
ax = plt.subplot(111)

ax.xaxis.set_major_locator(xmajorLocator)
ax.xaxis.set_major_formatter(xmajorFormatter)

ax.yaxis.set_major_locator(ymajorLocator)
ax.yaxis.set_major_formatter(ymajorFormatter)

ax.xaxis.set_minor_locator(xminorLocator)
ax.yaxis.set_minor_locator(yminorLocator)

ax.xaxis.grid(True, which='major', ls='dotted')
ax.yaxis.grid(True, which='major', ls='dotted')

# plt.ylim(-5, 55)
# plt.xlim(1, 7)
plt.plot(range(0, proxy_entry_length), entry_counter, '-', label="Valid Entry Number of Proxy Table")

# legend = plt.legend(loc='upper left', shadow=False, fontsize=20)

for label in ax.xaxis.get_ticklabels():
    label.set_fontsize(20)
for label in ax.yaxis.get_ticklabels():
    label.set_fontsize(20)

# plt.xlabel('Time(s)', fontsize=20)
# plt.ylabel('Packet Loss Rate (%)', fontsize=20)

plt.savefig('valid_proxy_table_entry.pdf')
plt.show()
