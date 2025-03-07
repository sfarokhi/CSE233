import sys
import struct
import socket
from scapy.all import rdpcap, TCP, IP, IPv6, Raw

def parse_pcap(file_path):
    """
    Parse a PCAP file and extract TCP/IP headers and payloads.
    
    Args:
        file_path (str): Path to the PCAP file
    """
    # Read the PCAP file
    packets = rdpcap(file_path)
    
    # Process each packet
    for i, packet in enumerate(packets):
        print(f"\n{'='*70}")
        print(f"Packet {i+1}/{len(packets)}")
        print(f"{'='*70}")
        
        # Check if packet has IP layer
        if IP in packet:
            ip_layer = packet[IP]
            print("\nIP Header:")
            print(f"  Version: {ip_layer.version}")
            print(f"  Header Length: {ip_layer.ihl * 4} bytes")
            print(f"  ToS: {ip_layer.tos}")
            print(f"  Total Length: {ip_layer.len}")
            print(f"  ID: {ip_layer.id}")
            print(f"  Flags: {ip_layer.flags}")
            print(f"  Fragment Offset: {ip_layer.frag}")
            print(f"  TTL: {ip_layer.ttl}")
            print(f"  Protocol: {ip_layer.proto}")
            print(f"  Checksum: 0x{ip_layer.chksum:04x}")
            print(f"  Source IP: {ip_layer.src}")
            print(f"  Destination IP: {ip_layer.dst}")
        
        # Check if packet has IPv6 layer
        elif IPv6 in packet:
            ipv6_layer = packet[IPv6]
            print("\nIPv6 Header:")
            print(f"  Version: {ipv6_layer.version}")
            print(f"  Traffic Class: {ipv6_layer.tc}")
            print(f"  Flow Label: {ipv6_layer.fl}")
            print(f"  Payload Length: {ipv6_layer.plen}")
            print(f"  Next Header: {ipv6_layer.nh}")
            print(f"  Hop Limit: {ipv6_layer.hlim}")
            print(f"  Source IP: {ipv6_layer.src}")
            print(f"  Destination IP: {ipv6_layer.dst}")
        
        # Check if packet has TCP layer
        if TCP in packet:
            tcp_layer = packet[TCP]
            print("\nTCP Header:")
            print(f"  Source Port: {tcp_layer.sport}")
            print(f"  Destination Port: {tcp_layer.dport}")
            print(f"  Sequence Number: {tcp_layer.seq}")
            print(f"  Acknowledgment Number: {tcp_layer.ack}")
            print(f"  Data Offset: {tcp_layer.dataofs * 4} bytes")
            print(f"  Reserved: {tcp_layer.reserved}")
            
            # Extract flags
            flags = []
            if tcp_layer.flags & 0x01: flags.append("FIN")
            if tcp_layer.flags & 0x02: flags.append("SYN")
            if tcp_layer.flags & 0x04: flags.append("RST")
            if tcp_layer.flags & 0x08: flags.append("PSH")
            if tcp_layer.flags & 0x10: flags.append("ACK")
            if tcp_layer.flags & 0x20: flags.append("URG")
            if tcp_layer.flags & 0x40: flags.append("ECE")
            if tcp_layer.flags & 0x80: flags.append("CWR")
            
            print(f"  Flags: {', '.join(flags) if flags else 'None'}")
            print(f"  Window Size: {tcp_layer.window}")
            print(f"  Checksum: 0x{tcp_layer.chksum:04x}")
            print(f"  Urgent Pointer: {tcp_layer.urgptr}")
            
            # Extract options if present
            if tcp_layer.options:
                print("  Options:")
                for option in tcp_layer.options:
                    print(f"    {option}")
        
        # Check for payload data
        if Raw in packet:
            payload = packet[Raw].load
            print("\nPayload Data:")
            print_payload(payload)

def print_payload(data, bytes_per_line=16):
    """
    Print payload data in hexadecimal and ASCII format.
    
    Args:
        data (bytes): Raw payload data
        bytes_per_line (int): Number of bytes to print per line
    """
    for i in range(0, len(data), bytes_per_line):
        chunk = data[i:i+bytes_per_line]
        hex_values = ' '.join(f'{b:02x}' for b in chunk)
        
        # Pad hex values for alignment
        hex_padding = ' ' * (3 * (bytes_per_line - len(chunk)))
        
        # Convert to ASCII (replace non-printable chars with dots)
        ascii_values = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        
        print(f"  {i:04x}: {hex_values}{hex_padding}  |{ascii_values}|")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <pcap_file>")
        sys.exit(1)
    
    parse_pcap(sys.argv[1])
