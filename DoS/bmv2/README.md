# DoS SYN proxy demo 
This is a introduction to our SYN proxy project.
## Overview
We implement a switch which could act as a syn proxy and count the number of packets sent to a specific IP address.
Based on this the switch is able to deal with DDoS attack and other future function extension in security.

## Design
### Modeling
We set up a relatively simple model with h1-s1-h2 topology. We assume that h1 first initializes a session request(send the SYN packet) to h2 and after the three-way handshake, the tcp session is set up and successive packets such as http request will travel between h1 and h2 through the switch.
### Workflow
1. H1 initializes a session and sends the syn packet. The switch will capture the packet and send back the SYN/ACK packet to h1 without transmiting any message to h2. 
2. When h1 sends the ack packet back, the switch captures it and sends SYN packet to h2 to establish a session with h2. After the session between h2 is set up, the switch will relay the session A (between h1 and s1) and session B (between s1 and h2).
3. 
## Test
There are two ways to start the p4 switch. One is to take the PC as the switch sniffing and sending packets through the virtual network interfaces, while the other is to set up a topology on **mininet** where we run the switch.

For the first way, you should follow these steps:

1. Run `veth_setup.sh` to set up the virtual network interfaces.
2. Run `run_demolog.sh` to start the server with log in `ss-log.txt`. 
3. Run `vethsendip.py` and `recvip.py` to send and check the packets.

For the second way, you should follow these steps:

1. Run `run_demo.sh` to start the switch on the topology defined in `topo.py`
2. Run a simple web server and client according to [mininet walkthrough](http://mininet.org/walkthrough/#run-a-simple-web-server-and-client). You can also try `sendip.py` or `recvip.py`.


We recommend you test in the second way.


## Source Code
`p4src/syntry.p4`  This is the p4 source code.

`veth_setup.sh`  This script will set up the virtual network interfaces such as "veth2", "veth4", "veth6" and so on.

`vethsendip.py`  This python script will send specific TCP packets through specific network interface. You can modify it for your own needs.  

`topo.py` This script will set up the topology of this model and starts the CLI of p4 switch.

`server.py` This script will run a simple server on the host.

`sendip.py` Send specific packets through eth0. You modify it for your needs.

`recvip.py` Receive and handle specifics packets.

`run_demolog.sh` Start the switch with log in `ss-log.txt`. Remember to run `veth_setup.sh` firstly.

`run_demo.sh` Start the switch on the topology defined in `topo.py` without log.

`commands.txt` There are table entries here, which will be loaded into the swtich by `topo.py`. You can also add the entries manually through CLI.

`cleanup` Clean up the environment such as the virtual network interfaces.

