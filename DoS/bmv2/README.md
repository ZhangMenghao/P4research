# BMv2 demo 
This is a demo with all features mentioned implemented using p4-14 standard. Source code in this folder is designed for running in BMv2 enviornment.
## Overview
We implement a switch that can mitigate most type of DDoS attacks, including a filter, an anti-spoofing module and an unspoofing attack defense module. Most of the mechanisms are implemented in the data plane of programmable switches.

## Design
### Modeling
We set up a relatively simple model with h1-s1-h2 topology using mininet. We assume that h1 first initializes a session request(send the SYN packet) to h2 and after the three-way handshake, the tcp session is set up and successive packets such as http request will travel between h1 and h2 through the switch.
### Workflow
1. H1 initializes a session and sends the syn packet. The switch will capture the packet and send back the SYN/ACK packet to h1 with certain SEQ# without transmiting any message to h2. 
2. When h1 sends the ack packet back, the switch validates its ACK# and sends SYN packet to h2 to establish a session with h2. After the session between h2 is set up, the switch will relay the session A (between h1 and s1) and session B (between s1 and h2).
3. Additionally, the program will watch for every SYN packet passing through and every connection established. The SYN proxy module will start up or shut down automatically according to the speed of SYN packets sent to the switch and the difference of the number between SYN packets and valid ACK packets during TCP handshake. Meanwhile, two sketches are responsible for watching for hosts who is holding up too much connections or sending too much data in a certain period.
## Test
To test this demo, you are supposed to set up a topology on **mininet** where we run the switch.


1. Run `run_demo.sh` to start the switch on the topology defined in `topo.py`. 
2. Run a simple web server and client according to [mininet walkthrough](http://mininet.org/walkthrough/#run-a-simple-web-server-and-client).
3. `run_switch.py` contains most of the measurement mechanisms. SYN proxy is on by default.



## Source Code
`p4src/syntry.p4`  This is the p4 source code.

`topo.py` This script will set up the topology of this model and starts the CLI of p4 switch.

`server.py` This script will run a simple server on the host.

`run_demo.sh` Start the switch on the topology defined in `topo.py` without log.

`commands.txt` There are table entries here, which will be loaded into the swtich by `topo.py`. You can also add the entries manually through CLI.

`cleanup` Clean up the environment such as the virtual network interfaces.

