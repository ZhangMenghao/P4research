import numpy as np
import matplotlib as mpl
import matplotlib.pyplot as plt
import brewer2mpl
import os
from scipy.interpolate import spline
from matplotlib.ticker import MultipleLocator, FormatStrFormatter

bmap = brewer2mpl.get_map('Set1', 'qualitative', 8)
colors = bmap.mpl_colors
mpl.rcParams['axes.color_cycle'] = colors


def extract(filename):
    switches = [[], [], []]
    f = open(filename, 'r')
    for lines in f.readlines():
        # split into 3 parts
        line = lines.split(',')
        switches[0].append(int(line[0]))
        switches[1].append(int(line[1]))
        switches[2].append(int(line[2]))
    return switches

def lighten(color):
    r = color[0] + (1 - color[0]) * 0.5
    g = color[1] + (1 - color[1]) * 0.5
    b = color[2] + (1 - color[2]) * 0.5
    return (r, g, b)


def draw(filename=['./output.txt', './output_original.txt']):

    switches = extract(filename[0])
    original_switches = extract(filename[1])


    plt.figure(figsize=(10,6))
    ax = plt.subplot(111)

    xmajorLocator   = MultipleLocator(20)
    xmajorFormatter = FormatStrFormatter('%2d')
    xminorLocator   = MultipleLocator(10)

    ymajorLocator   = MultipleLocator(4000)
    ymajorFormatter = FormatStrFormatter('%4d')
    yminorLocator   = MultipleLocator(2000)

    ax.xaxis.set_major_locator(xmajorLocator)
    ax.xaxis.set_major_formatter(xmajorFormatter)

    ax.yaxis.set_major_locator(ymajorLocator)
    ax.yaxis.set_major_formatter(ymajorFormatter)

    ax.xaxis.set_minor_locator(xminorLocator)
    ax.yaxis.set_minor_locator(yminorLocator)

    ax.xaxis.grid(True, which='minor', ls='dotted')
    ax.yaxis.grid(True, which='minor', ls='dotted')

    plt.xlim(0, 160)
    plt.ylim(0, 20000)

    timeline = range(len(switches[0]))

    plt.plot(timeline, original_switches[0], '--', label="s1-without redistribution",
        color=lighten(colors[0]))
    plt.plot(timeline, original_switches[1], '--', label="s2-without redistribution",
        color=lighten(colors[1]))
    plt.plot(timeline, original_switches[2], '--', label="s3-without redistribution",
        color=lighten(colors[2]))
    plt.plot(timeline, switches[0], '-', label="s1-with redistribution")
    plt.plot(timeline, switches[1], '-', label="s2-with redistribution")
    plt.plot(timeline, switches[2], '-', label="s3-with redistribution")

    plt.legend(loc='lower right', shadow=False, fontsize='xx-large')

    for label in ax.xaxis.get_ticklabels():
        label.set_fontsize('xx-large')
    for label in ax.yaxis   .get_ticklabels():
        label.set_fontsize('xx-large')

    plt.xlabel('Time (s)', fontsize='xx-large')
    plt.ylabel('Active Flow Count', fontsize='xx-large')

    plt.savefig('active_flows.pdf')
    plt.show()

draw()