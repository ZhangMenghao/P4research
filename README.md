# DDoS Mitigation Using Switching ASICs
Here in this repository, we implemented multiple Denial-of-Service (DoS) defense modules in switching ASICs to protect servers from DoS attacks.

Modern programmable switches now have enough power to implement most of the DoS defense methods directly. However, traditional DoS defense approaches are all memory-intensive, while switch only has limited resources, which makes it non-trivial to migrate these approach directly. We carefully design various techniques such as memory reuse, compromising accuracy, hash-based compressing to fully exploit the potential of a switch.

The whole mechanism here is completely transparent to all devices in the network. The whole system can be automatically turned on or off according to the traffic passing through it, which make our system incur negative impacts on legitimate traffic as low as possible.

We mainly aim at provides protection for flooding-based DoS attacks, including spoofing attacks (e.g., *UDP FLOOD*, *ICMP FLOOD*, * TCP SYN FLOOD*, *DNS Reflection*) and unspoofing attacks (e.g. *data flood*, *Sloworis attack*, *NAPTHA attack*).

## Spoofing Attacks
We use a whitelist to limit the overall throughput while guaranteeing a higher priority for those source-IPs in the whitelist. The whitelist can be built from two sources, one is migrated directly from the whiltelist of TCP defence mechanism, the other is obtained from DNS or ICMP tracking table.
### Reflector Attacks 
Tracking table, as mentioned above, is a great way to protect a network from reflection attacks. Take DNS reflecion attack as an example. We can track every DNS request message sent out of the network, and DNS reply can re-enter the network only if its corresponding request packet was recorded.

### SYN FLOOD
Our policy for migrating spoofing SYN floods is SYN proxy, originating from the idea of SYN-cookie. We use two private keys to calculate syn cookie value, among with original 5-tuple of the connection. The two keys are distributed by control plane, and the older one will be updated after a certain time period for security considerations. When receiving a ACK from a unknown connection, the switch will calculate two cookie values using two keys respectively and compare them with ACK number carried in the packet. Drop the packet if there are no matches. 


## Other Unspoofing Attacks
Heavy hitter detector is adapted for unspoofing packets. The number and the total packet size of connections established by the same IP address are recorded using count-min sketch. If either of these two data is abnormal (way higher than threshold, for example), the corresponding source IP address will be inserted into blacklist table, which is basically a filter at the very beginning of the whole system. Packets that hit the filter are recognized as malicious ones and will be dropped immediately. Out-date entries in both blacklist and whitelist are removed to reduce the memory costs.

 