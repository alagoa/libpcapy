#!/usr/bin/env python
'''
    Structures and constants of libpcap mapped to python
'''

import ctypes

PCAP_NETMASK_UNKNOWN = 0xffffffff
PCAP_ERRBUF_SIZE = 256
ETHERNET_HDR_SIZE = 14
IP_HDR_binary_string_format = '!BBHHHBBH4s4s'


class sockaddr(ctypes.Structure):
    _fields_ = [("sa_family", ctypes.c_ushort),
                ("sa_data", ctypes.c_char * 14)]


# We need to declare the structure before the fields because of the 'next' field
class pcap_addr(ctypes.Structure):
    pass


pcap_addr._fields_ = [('next', ctypes.POINTER(pcap_addr)),
                      ('addr', ctypes.POINTER(sockaddr)),
                      ('netmask', ctypes.POINTER(sockaddr)),
                      ('broadaddr', ctypes.POINTER(sockaddr)),
                      ('dstaddr', ctypes.POINTER(sockaddr))]


# We need to declare the structure before the fields because of the 'next' field
class pcap_if(ctypes.Structure):
    pass


pcap_if._fields_ = [('next', ctypes.POINTER(pcap_if)),
                    ('name', ctypes.c_char_p),
                    ('description', ctypes.c_char_p),
                    ('addresses', ctypes.POINTER(pcap_addr)),
                    ('flags', ctypes.c_uint)]


class timeval(ctypes.Structure):
    _fields_ = [('tv_sec', ctypes.c_long),
                ('tv_usec', ctypes.c_long)]


class pcap_pkthdr(ctypes.Structure):
    _fields_ = [('ts', timeval),
                ('caplen', ctypes.c_uint),
                ('len', ctypes.c_uint)]


class bpf_insn(ctypes.Structure):
    _fields_ = [('code', ctypes.c_ushort),
                ('jt', ctypes.c_ubyte),
                ('jf', ctypes.c_ubyte),
                ('k', ctypes.c_ulong)]


class bpf_program(ctypes.Structure):
    _fields_ = [('bf_len', ctypes.c_int),
                ('bpf_insn', ctypes.POINTER(bpf_insn))]


class ipv4_header(ctypes.Structure):
    _fields_ = [('ip_vhl', ctypes.c_uint8),
                ('ip_tos', ctypes.c_uint8),
                ('ip_len', ctypes.c_uint16),
                ('ip_id', ctypes.c_uint16),
                ('ip_off', ctypes.c_uint16),
                ('ip_ttl', ctypes.c_uint8),
                ('ip_p', ctypes.c_uint8),
                ('ip_sum', ctypes.c_uint16),
                ('ip_src', ctypes.c_uint32),
                ('ip_dst', ctypes.c_uint32)]
