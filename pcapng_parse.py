import pyshark
import sys
from datetime import datetime
import os
import struct
import binascii

class PacketData:
    def __init__(self):
        # IP layer
        self.src_ip = None
        self.dst_ip = None
        self.ip_proto = None
        self.ip_ttl = None
        self.ip_id = None
        
        # Transport layer
        self.src_port = None
        self.dst_port = None
        self.seq_num = None
        self.ack_num = None
        
        # TCP flags
        self.tcp_flags = None
        self.tcp_window = None
        
        # Raw data
        self.raw_payload = None
        self.payload_hex = None
        self.payload_length = 0
        
        # Timestamp
        self.timestamp = None
        self.packet_number = None

def analyze_mms_packets(pcap_path):
    """
    Parse a PCAPNG file and extract TCP/IP data and raw payload for MMS packets.
    """
    if not os.path.exists(pcap_path):
        print(f"Error: File not found: {pcap_path}")
        return
    
    print(f"\n{'='*80}")
    print(f"Analyzing MMS packets in: {os.path.basename(pcap_path)}")
    print(f"Analysis started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*80}\n")
    
    try:
        # Create capture with filter for MMS (port 102)
        cap = pyshark.FileCapture(pcap_path, display_filter="mms", include_raw=True, use_json=True)
        
        packet_count = 0
        
        for packet in cap:
            # Limit the number of packets to analyze (for testing)
            if packet_count >= 10:
                break
                
            packet_count += 1
            packet_data = PacketData()
            
            # Store packet metadata
            packet_data.packet_number = packet.number
            packet_data.timestamp = packet.sniff_time
            
            print(f"\n{'*'*70}")
            print(f"Packet #{packet_data.packet_number} - {packet.sniff_time}")
            print(f"{'*'*70}")
            
            # Extract IP layer information
            if hasattr(packet, 'ip'):
                packet_data.src_ip = packet.ip.src
                packet_data.dst_ip = packet.ip.dst
                packet_data.ip_proto = packet.ip.proto
                packet_data.ip_ttl = packet.ip.ttl
                packet_data.ip_id = packet.ip.id
                
                print(f"Source IP: {packet_data.src_ip}")
                print(f"Destination IP: {packet_data.dst_ip}")
                print(f"IP Protocol: {packet_data.ip_proto}")
                print(f"IP TTL: {packet_data.ip_ttl}")
                print(f"IP ID: {packet_data.ip_id}")
            
            # Extract Ethernet information
            if hasattr(packet, 'eth'):
                print(f"Source MAC: {packet.eth.src}")
                print(f"Destination MAC: {packet.eth.dst}")
            
            # Extract TCP layer information
            if hasattr(packet, 'tcp'):
                packet_data.src_port = packet.tcp.srcport
                packet_data.dst_port = packet.tcp.dstport
                packet_data.seq_num = packet.tcp.seq
                packet_data.ack_num = packet.tcp.ack if hasattr(packet.tcp, 'ack') else None
                packet_data.tcp_flags = packet.tcp.flags
                packet_data.tcp_window = packet.tcp.window_size_value if hasattr(packet.tcp, 'window_size_value') else packet.tcp.window
                
                print(f"Source Port: {packet_data.src_port}")
                print(f"Destination Port: {packet_data.dst_port}")
                print(f"Sequence Number: {packet_data.seq_num}")
                print(f"Acknowledgment Number: {packet_data.ack_num}")
                print(f"TCP Flags: {packet_data.tcp_flags}")
                print(f"Window Size: {packet_data.tcp_window}")
                
                # Extract raw TCP payload
                if hasattr(packet.tcp, 'payload'):
                    raw_payload = None
                    
                    # Try to get raw payload using different methods
                    try:
                        # Method 1: Get from tcp.payload field
                        raw_payload = binascii.unhexlify(packet.tcp.payload.replace(':', ''))
                    except (AttributeError, binascii.Error):
                        try:
                            # Method 2: Get from tcp layer raw
                            raw = packet.tcp.get_field_value('tcp.payload')
                            if raw:
                                raw_payload = binascii.unhexlify(raw.replace(':', ''))
                        except:
                            pass
                    
                    # Method 3: Get from raw captured data if possible
                    if not raw_payload and hasattr(packet, 'raw'):
                        try:
                            raw_bytes = packet.get_raw_packet()
                            
                            # Skip Ethernet header (14 bytes), IP header, and TCP header
                            ip_header_len = int(packet.ip.hdr_len) if hasattr(packet.ip, 'hdr_len') else 20
                            tcp_header_len = int(int(packet.tcp.hdr_len) / 4) if hasattr(packet.tcp, 'hdr_len') else 20
                            
                            payload_offset = 14 + ip_header_len + tcp_header_len
                            raw_payload = raw_bytes[payload_offset:]
                        except:
                            pass
                    
                    if raw_payload:
                        packet_data.raw_payload = raw_payload
                        packet_data.payload_hex = binascii.hexlify(raw_payload).decode('utf-8')
                        packet_data.payload_length = len(raw_payload)
                        
                        print("\nTCP Payload Data:")
                        print(f"Payload Length: {packet_data.payload_length} bytes")
                        print("Payload Hex:")
                        
                        # Print payload in hexdump format
                        for i in range(0, len(raw_payload), 16):
                            chunk = raw_payload[i:i+16]
                            hex_values = ' '.join(f'{b:02x}' for b in chunk)
                            ascii_values = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
                            print(f"  {i:04x}: {hex_values:<48}  |{ascii_values}|")
                        
                        # Attempt to identify protocol layers in the payload
                        print("\nPayload Protocol Analysis:")
                        
                        # Check for TPKT (RFC1006) - typically starts with 03 00
                        if len(raw_payload) >= 2 and raw_payload[0] == 0x03 and raw_payload[1] == 0x00:
                            print("  TPKT Header Detected (RFC1006)")
                            if len(raw_payload) >= 4:
                                tpkt_length = (raw_payload[2] << 8) + raw_payload[3]
                                print(f"  TPKT Length: {tpkt_length} bytes")
                                
                                # Check for COTP (ISO 8073)
                                if len(raw_payload) >= 5:
                                    cotp_length = raw_payload[4]
                                    print(f"  COTP Header Length: {cotp_length} bytes")
                                    
                                    if len(raw_payload) >= 6:
                                        cotp_pdu_type = raw_payload[5] & 0x0F
                                        cotp_types = {
                                            0x00: "Connection Request", 
                                            0x02: "Ack. Connection", 
                                            0x04: "Data",
                                            0x05: "Expedited Data",
                                            0x06: "Data Acknowledgement"
                                        }
                                        cotp_type_name = cotp_types.get(cotp_pdu_type, f"Unknown (0x{cotp_pdu_type:02x})")
                                        print(f"  COTP PDU Type: {cotp_type_name}")
                                        
                                        # Check for MMS/ISO 8650 data after COTP+TPKT headers
                                        iso_offset = 5 + cotp_length
                                        if cotp_pdu_type == 0x04 and len(raw_payload) > iso_offset:
                                            print("  ISO 8650/MMS Data Present")
                        
                        # Check for typical MMS patterns in the data
                        mms_patterns = [
                            (b'\xa0', "MMS Confirmed Request"),
                            (b'\xa1', "MMS Confirmed Response"),
                            (b'\xa2', "MMS Confirmed Error"),
                            (b'\xa3', "MMS Unconfirmed Request"),
                            (b'\xa4', "MMS Reject"),
                            (b'\xa8', "MMS Initiate Request"),
                            (b'\xa9', "MMS Initiate Response"),
                            (b'\xaa', "MMS Initiate Error"),
                            (b'\xab', "MMS Conclude Request"),
                            (b'\xac', "MMS Conclude Response"),
                            (b'\xad', "MMS Conclude Error")
                        ]
                        
                        for pattern, desc in mms_patterns:
                            if pattern in raw_payload:
                                position = raw_payload.find(pattern)
                                print(f"  Possible {desc} at offset {position}")
            
            # If no packet data was parsed for this packet, notify
            if not packet_data.raw_payload:
                print("\nNo payload data found in this packet.")
        
        cap.close()
        
        if packet_count == 0:
            print("\nNo MMS packets (TCP port 102) found in the capture file.")
        else:
            print(f"\n{'='*80}")
            print(f"Analysis complete: {packet_count} packets analyzed")
            print(f"{'='*80}")
    
    except Exception as e:
        print(f"Error analyzing file: {str(e)}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <pcapng_file>")
        print("Example: python mms_raw_parser.py capture.pcapng")
        sys.exit(1)
    
    analyze_mms_packets(sys.argv[1])