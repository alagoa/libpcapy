# Libpcapy
**Libpcapy** is a Python wrapper for _libpcap_, an interface written in C for user-level packet captures.
The motivation for the development of this library was the need of a high-performance packet sniffer (with a high packet processing rate) while programming with Python. This project uses the _ctypes_ library.

## Dependencies

### Libpcap:

 *Ubuntu/Debian*: 
 > apt-get install libpcap-dev
 
*CentOS/Fedora*:
 > dnf install libpcap-devel

*Arch*:
 > pacman -S libpcap

Or you can download it [here](http://www.tcpdump.org/release/libpcap-1.7.4.tar.gz) and install it yourself.

## Install
Install **Libpcapy** with pip:
>pip3 install libpcapy


## Example

```python
from libpcapy import capture  
  
# Callback function to be called every time the sniffer catches a packet  
def my_callback(pkthdr, data, user_data):  
    print("Packet arrived!")  
    print("\tTimestamp: ", pkthdr.ts.tv_sec)  
    print("\tLength: ", pkthdr.caplen)  
  
  
# Find all capture devices  
devices = capture.pcap_findalldevs()  
device = devices[0]  
  
# Set snapshot lenght, promiscuous mode and timeout  
snaplen = 65535 # maximum number of bytes to be captured by pcap  
promisc = 1 # promiscuous mode  
to_ms = 10000 # timeout  
  
print("Capturing on %s" % device)  
handle = capture.pcap_open_live(device, snaplen, promisc, to_ms)  
  
if handle:  
    bpf = capture.bpf_program()  
    # Setting a filter  
  result = capture.pcap_setfilter(handle, bpf)  
    capture.call_loop(handle, -1, my_callback, None)  
  
print("Closing live capture")  
capture.pcap_close(handle)
```

**Note**: You need to execute this script with a user that has capture priviledges, such as _root_.
