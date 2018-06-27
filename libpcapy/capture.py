#!/usr/bin/env python
import ctypes
import types

libpcap_filename = "libpcap.so"
_libpcap_lib = ctypes.cdll.LoadLibrary(libpcap_filename)

'''
Find the default device/interface on which to capture
'''


def pcap_lookupdev():
    errbuf = ctypes.create_string_buffer(types.ERR_BUFF_SIZE)
    pcap_lookupdev = _libpcap_lib.pcap_lookupdev
    pcap_lookupdev.restype = ctypes.c_char_p
    return pcap_lookupdev(errbuf)


'''
Get a list of capture devices/interfaces
'''


def pcap_findalldevs():
    pcap_findalldevs = _libpcap_lib.pcap_findalldevs
    pcap_findalldevs.restype = ctypes.c_int
    pcap_findalldevs.argtypes = [ctypes.POINTER(ctypes.POINTER(types.pcap_if)),
                                 ctypes.c_char_p]
    errbuf = ctypes.create_string_buffer(types.ERR_BUFF_SIZE)
    alldevs = ctypes.POINTER(types.pcap_if)()
    result = pcap_findalldevs(ctypes.byref(alldevs), errbuf)
    if result == 0:
        devices = []
        device = alldevs.contents
        while (device):
            devices.append(device.name)
            if device.next:
                device = device.next.contents
            else:
                device = False
        # free to avoid leaking every time we call findalldevs
        pcap_freealldevs(alldevs)
    else:
        raise Exception(errbuf)
    return devices


'''
Free the device list
'''


def pcap_freealldevs(alldevs):
    pcap_freealldevs = _libpcap_lib.pcap_freealldevs
    pcap_freealldevs.restype = None
    pcap_freealldevs.argtypes = [ctypes.POINTER(types.pcap_if)]
    pcap_freealldevs(alldevs)


'''
Open a device for live capturing
'''


def pcap_open_live(device, snaplen, promisc, to_ms):
    pcap_open_live = _libpcap_lib.pcap_open_live
    pcap_open_live.restype = ctypes.POINTER(ctypes.c_void_p)
    pcap_open_live.argtypes = [ctypes.c_char_p,
                               ctypes.c_int,
                               ctypes.c_int,
                               ctypes.c_int,
                               ctypes.c_char_p]
    errbuf = ctypes.create_string_buffer(types.ERR_BUFF_SIZE)
    handle = pcap_open_live(device, snaplen, promisc, to_ms, errbuf)
    if not handle:
        print("Error opening device %s." % device)
        return None
    return handle


'''
Read the next packet from a handle
'''


def pcap_next(handle):
    pcap_next = _libpcap_lib.pcap_next
    pcap_next.restype = ctypes.POINTER(ctypes.c_char)
    pcap_next.argtypes = [ctypes.POINTER(ctypes.c_void_p),
                          ctypes.POINTER(types.pcap_pkthdr)]
    pkthdr = types.pcap_pkthdr()
    pktdata = pcap_next(handle, ctypes.byref(pkthdr))
    return pkthdr, pktdata[:pkthdr.len]


'''
Collect packets until cnt is reached
'''


def pcap_loop(hpcap, cnt, callback, user_data):
    pcap_pkthdr_p = ctypes.POINTER(types.pcap_pkthdr)
    pcap_handler = ctypes.CFUNCTYPE(None, ctypes.POINTER(ctypes.py_object), pcap_pkthdr_p,
                                    ctypes.POINTER(ctypes.c_ubyte))

    retcode = _libpcap_lib.pcap_loop(hpcap, cnt, pcap_handler(__callback_wrapper),
                                     ctypes.pointer(ctypes.py_object((callback, user_data))))
    if retcode == -1:
        exit(1)
    return retcode


'''
Set a filter for the capture
'''


def pcap_setfilter(handle, bpf):
    pcap_setfilter = _libpcap_lib.pcap_setfilter
    pcap_setfilter.restype = ctypes.c_int
    pcap_setfilter.argtypes = [ctypes.POINTER(ctypes.c_void_p),
                               ctypes.POINTER(types.bpf_program)]
    result = pcap_setfilter(handle, bpf)
    return result


'''
Close the connection
'''


def pcap_close(handle):
    pcap_close = _libpcap_lib.pcap_close
    pcap_close.restype = None
    pcap_close.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
    pcap_close(handle)


def __callback_wrapper(user_data, pkthdr_p, data):
    (callback, obj) = user_data.contents.value
    if callback:
        callback(pkthdr_p.contents, ctypes.string_at(data, pkthdr_p.contents.caplen), obj)
