import socket
import struct
import textwrap

"""A network sniffer captures and analyzes network traffic in real-time. They are various common tools for it but that's not our focus today. Let's run the code and see if it works🔥🔥"""
"""Hurray🎺🎺It worked. Thanks for watching"""
# Formatting constants
TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '

def main():
    try:
        # Create a raw socket
        from scapy.all import sniff

        def packet_callback(packet):
            print(packet.summary())  # This prints a short summary of each packet

        sniff(prn=packet_callback, store=False)

        print("[INFO] Sniffing started... Press Ctrl+C to stop.")
    except PermissionError:
        print("[ERROR] Permission denied! Run this script as an administrator.")
        return
    except Exception as e:
        print(f"[ERROR] Failed to start sniffer: {e}")
        return

    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('\nEthernet Frame:')
        print(TAB_1 + f'Destination: {dest_mac}, Source: {src_mac}, Protocol: {eth_proto}')

        # IPv4 Packets
        if eth_proto == 8:
            version, header_length, ttl, proto, src, target, data = ipv4_packet(data)
            print(TAB_1 + 'IPv4 Packet:')
            print(TAB_2 + f'Version: {version}, Header Length: {header_length}, TTL: {ttl}')
            print(TAB_2 + f'Protocol: {proto}, Source: {src}, Target: {target}')

            # ICMP Packets
            if proto == 1:
                icmp_type, code, checksum, data = icmp_packet(data)
                print(TAB_1 + 'ICMP Packet:')
                print(TAB_2 + f'Type: {icmp_type}, Code: {code}, Checksum: {checksum}')
                print(TAB_2 + 'Data:')
                print(format_multi_line(DATA_TAB_3, data))

            # TCP Packets
            elif proto == 6:
                src_port, dest_port, sequence, acknowledgement, flags = tcp_segment(data)
                print(TAB_1 + 'TCP Segment:')
                print(TAB_2 + f'Source Port: {src_port}, Destination Port: {dest_port}')
                print(TAB_2 + f'Sequence: {sequence}, Acknowledgement: {acknowledgement}')
                print(TAB_2 + 'Flags:')
                print(TAB_3 + f'URG: {flags[0]}, ACK: {flags[1]}, PSH: {flags[2]}, RST: {flags[3]}, SYN: {flags[4]}, FIN: {flags[5]}')
                print(TAB_2 + 'Data:')
                print(format_multi_line(DATA_TAB_3, data))

            # UDP Packets
            elif proto == 17:
                src_port, dest_port, length, data = udp_segment(data)
                print(TAB_1 + 'UDP Segment:')
                print(TAB_2 + f'Source Port: {src_port}, Destination Port: {dest_port}, Length: {length}')

            # Other Protocols
            else:
                print(TAB_1 + 'Other Protocol Data:')
                print(format_multi_line(DATA_TAB_2, data))

        else:
            print(TAB_1 + 'Data:')
            print(format_multi_line(DATA_TAB_1, data))

# Unpack Ethernet frame
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

# Return properly formatted MAC address
def get_mac_addr(bytes_addr):
    return ':'.join(map('{:02x}'.format, bytes_addr)).upper()

# Unpack IPv4 packet
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

# Return properly formatted IPv4 address
def ipv4(addr):
    return '.'.join(map(str, addr))

# Unpack ICMP packet
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

# Unpack TCP segment
def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flags = [
        (offset_reserved_flags & 32) >> 5,  # URG
        (offset_reserved_flags & 16) >> 4,  # ACK
        (offset_reserved_flags & 8) >> 3,   # PSH
        (offset_reserved_flags & 4) >> 2,   # RST
        (offset_reserved_flags & 2) >> 1,   # SYN
        offset_reserved_flags & 1           # FIN
    ]
    return src_port, dest_port, sequence, acknowledgement, flags, data[offset:]

# Unpack UDP segment
def udp_segment(data):
    src_port, dest_port, length = struct.unpack('! H H H', data[:6])
    return src_port, dest_port, length, data[8:]

# Format multi-line data output
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

if __name__ == "__main__":
    main()
