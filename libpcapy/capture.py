#!/usr/bin/env python
from libpcapy.pcap_structures import *
import threading

libpcap_filename = "libpcap.so"
_libpcap = ctypes.cdll.LoadLibrary(libpcap_filename)

'''
Find the default device/interface on which to capture
'''


def pcap_lookupdev():
    errbuf = ctypes.create_string_buffer(PCAP_ERRBUF_SIZE)
    pcap_lookupdev = _libpcap.pcap_lookupdev
    pcap_lookupdev.restype = ctypes.c_char_p
    return pcap_lookupdev(errbuf)


'''
Get a list of capture devices/interfaces
'''


def pcap_findalldevs():
    pcap_findalldevs = _libpcap.pcap_findalldevs
    pcap_findalldevs.restype = ctypes.c_int
    pcap_findalldevs.argtypes = [ctypes.POINTER(ctypes.POINTER(pcap_if)), ctypes.c_char_p]
    errbuf = ctypes.create_string_buffer(PCAP_ERRBUF_SIZE)
    alldevs = ctypes.POINTER(pcap_if)()
    result = pcap_findalldevs(ctypes.byref(alldevs), errbuf)
    if result == 0:
        devices = []
        device = alldevs.contents
        while device:
            devices.append(device.name)
            if device.next:
                device = device.next.contents
            else:
                device = False
        pcap_freealldevs(alldevs)
    else:
        raise Exception(errbuf)
    return devices


'''
Free the device list
'''


def pcap_freealldevs(alldevs):
    pcap_freealldevs = _libpcap.pcap_freealldevs
    pcap_freealldevs.restype = None
    pcap_freealldevs.argtypes = [ctypes.POINTER(pcap_if)]
    pcap_freealldevs(alldevs)


'''
Open a device for live capturing
'''


def pcap_open_live(device, snaplen, promisc, to_ms):
    pcap_open_live = _libpcap.pcap_open_live
    pcap_open_live.restype = ctypes.POINTER(ctypes.c_void_p)
    pcap_open_live.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_char_p]
    errbuf = ctypes.create_string_buffer(PCAP_ERRBUF_SIZE)
    handle = pcap_open_live(device, snaplen, promisc, to_ms, errbuf)
    if not handle:
        print("Error occurred while trying to capture on %s." % device)
        return None
    return handle


'''
Read the next packet from a handle
'''


def pcap_next(handle):
    pcap_next = _libpcap.pcap_next
    pcap_next.restype = ctypes.POINTER(ctypes.c_char)
    pcap_next.argtypes = [ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(pcap_pkthdr)]
    pkthdr = pcap_pkthdr()
    pktdata = pcap_next(handle, ctypes.byref(pkthdr))
    return pkthdr, pktdata[:pkthdr.len]


'''
Collect packets until cnt is reached
'''


def __pcap_loop(hpcap, cnt, callback, user_data):
    pcap_pkthdr_p = ctypes.POINTER(pcap_pkthdr)
    pcap_handler = ctypes.CFUNCTYPE(None, ctypes.POINTER(ctypes.py_object), pcap_pkthdr_p,
                                    ctypes.POINTER(ctypes.c_ubyte))
    retcode = _libpcap.pcap_loop(hpcap, cnt, pcap_handler(__callback_wrapper),
                                 ctypes.pointer(ctypes.py_object((callback, user_data))))
    if retcode == -1:
        exit(1)
    return retcode


'''
Set a filter for the capture
'''


def pcap_setfilter(handle, bpf):
    pcap_setfilter = _libpcap.pcap_setfilter
    pcap_setfilter.restype = ctypes.c_int
    pcap_setfilter.argtypes = [ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(bpf_program)]
    return pcap_setfilter(handle, bpf)


'''
Close the connection
'''


def pcap_close(handle):
    pcap_close = _libpcap.pcap_close
    pcap_close.restype = None
    pcap_close.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
    pcap_close(handle)


'''
Wrapper for the callback function to be written
'''


def __callback_wrapper(user_data, pkthdr_p, data):
    (callback, obj) = user_data.contents.value
    if callback:
        callback(pkthdr_p.contents, ctypes.string_at(data, pkthdr_p.contents.caplen), obj)


'''
Call loop on different thread so we can interrupt the main thread with a KeyboardInterrupt
'''


def call_loop(hpcap, cnt, callback, user_data):
    t = threading.Thread(target=__pcap_loop, args=[hpcap, cnt, callback, user_data])
    t.daemon = True
    t.start()
    while t.is_alive():
        t.join(.1)
