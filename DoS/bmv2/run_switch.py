# This python file aims to keep update of some of the flow table in the switch
# including syn cookie hash key (timely update)
# and check for the value of syn meter, syn counter, valid ack counter from time to time

from scapy.all import *
import subprocess
import os
import re

def send_to_CLI(cmd):
    this_dir = os.path.dirname(os.path.realpath(__file__))
    p = subprocess.Popen(os.path.join(this_dir, 'sswitch_CLI.sh'), stdout=subprocess.PIPE, stdin=subprocess.PIPE)
    output = p.communicate(input=cmd)[0]
    print output
    return output