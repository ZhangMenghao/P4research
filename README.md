# DDoS Migitation using switching ASICs
Here in this repository, we implemented multiple network security methods in switching ASICs to protect servers from DDoS attacks.

Modern programmable switches now have enough power that most of the security methods can be implemented, but limited memory makes it difficult to implement all of the methods at the same time. Here we are looking for a way to make switches a perfect shield for various DDoS attacks, to combine all the methods together as a system and implement them all on switching ASICs, to achieve minimum memory overhead and minumnm latency in the network.

The key challenge here is how to fit all those complex mitigating methods into the data plane of a switch. Almost every method we implement here requires a considerablly large memory overhead to track the status of connections or packets. So we gave up some accuracy here, applying different kinds of sketches to reduce memory overhead. 

The whole mechanism here is completely transparent to all devices in the network. The whole system can be automatically turned on or off according to all the traffic passing through in order to reduce the impact to network performance, while keep every connection intact that no one will notice whether the system is working. 

The types of DDoS attacks the system can mitigate are *UDP FLOOD*, *ICMP FLOOD*, *SYN FLOOD* and all the other unspoofing, TCP-based attacks.

## UDP and ICMP Attacks
### Simple Spoofing Attacks
We use a whitelist to limit the overall throughput while garanteeing a higher priority for those source-IPs in the whitelist. The whitelist can be built from two sources, one is migrated directly from the whiltelist of TCP defence mechanism, the other is obtained from DNS or ICMP tracking table.
### Reflector Attacks 
Tracking table, as mentioned above, is a great way to protect a network from reflection attacks. Take DNS reflecion attack as an example. We can track every DNS request message sent out of the network, and DNS reply can re-enter the network only if its corresponding request packet was recorded.

## SYN FLOOD
Our policy for migitating spoofing SYN floods is SYN proxy, based on the idea of SYN-cookie. We use two private keys to calculate syn cookie value, among with original 5-tuple of the connection. The two keys are distributed by control plane, and the older one will be updated after a certain time period to prevent security breach. When receiving a ACK from a unknown connection, the switch will calculate two cookie values using two keys respectively and compare them with ACK number carried in the packet. Drop the packet if there are no matches. 


## Other Unspoofing Attacks
Heavy hitter detector is adapted for every legitimate packets. The number and the total packet size of connections established by the same IP address are recorded using count-min sketch. If either of these two data is abnormal (way higher than threshold, for example), the corresponding source IP address will be inserted into blacklist table, which is basically a filter at the very beginning of the whole system. Packets that hit the filter are recognized as malicious ones and will be dropped immediately. Both blacklist and the whitelist that we mentioned above have timeout mechanism to prevent the table to be too memory-consuming.

 