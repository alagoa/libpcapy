from libpcapy import capture

# Callback function to be called every time the sniffer catches a packet
def my_callback(pkthdr, data, user_data):
    print("Packet arrived!")
    print("\tTimestamp: ", pkthdr.ts.tv_sec)
    print("\tLenght: ", pkthdr.caplen)


# Find all capture devices
devices = capture.pcap_findalldevs()
device = devices[0]

# Set snapshot lenght, promiscuous mode and timeout
snaplen = 65535  # maximum number of bytes to be captured by pcap
promisc = 1  # promiscuous mode
to_ms = 10000  # timeout

print("Capturing on %s" % device)
handle = capture.pcap_open_live(device, snaplen, promisc, to_ms)

if handle:
    bpf = capture.bpf_program()
    # Setting a filter
    result = capture.pcap_setfilter(handle, bpf)
    capture.call_loop(handle, -1, my_callback, None)

print("Closing live capture")
capture.pcap_close(handle)