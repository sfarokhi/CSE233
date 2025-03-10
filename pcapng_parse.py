import pyshark # type: ignore
import sys
from datetime import datetime
import os
import binascii

# General data for the packet
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
        
        # MMS specific data
        self.tpkt_length = None
        self.cotp_length = None
        self.cotp_pdu_type = None
        self.mms_pdu_type = None


def analyze_packet(packet) -> tuple[frozenset, PacketData]:
    
    try:
        packet_data = PacketData()
        
        # Store packet metadata
        packet_data.packet_number = packet.number
        packet_data.timestamp = packet.sniff_time
        
        # Extract IP layer information
        if hasattr(packet, 'ip'):
            packet_data.src_ip = packet.ip.src
            packet_data.dst_ip = packet.ip.dst
            packet_data.ip_proto = packet.ip.proto
            packet_data.ip_ttl = packet.ip.ttl
            packet_data.ip_id = packet.ip.id
        else:
            return  # Skip if no IP layer
        
        # Extract TCP layer information
        if hasattr(packet, 'tcp'):
            packet_data.src_port = packet.tcp.srcport
            packet_data.dst_port = packet.tcp.dstport
            packet_data.seq_num = packet.tcp.seq
            packet_data.ack_num = packet.tcp.ack if hasattr(packet.tcp, 'ack') else None
            packet_data.tcp_flags = packet.tcp.flags
            packet_data.tcp_window = packet.tcp.window_size_value if hasattr(packet.tcp, 'window_size_value') else packet.tcp.window
            
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
                    
                    # Parse protocol layers in the payload
                    # Check for TPKT (RFC1006) - typically starts with 03 00
                    if len(raw_payload) >= 2 and raw_payload[0] == 0x03 and raw_payload[1] == 0x00:
                        if len(raw_payload) >= 4:
                            packet_data.tpkt_length = (raw_payload[2] << 8) + raw_payload[3]
                            
                            # Check for COTP (ISO 8073)
                            if len(raw_payload) >= 5:
                                packet_data.cotp_length = raw_payload[4]
                                
                                if len(raw_payload) >= 6:
                                    packet_data.cotp_pdu_type = raw_payload[5] & 0x0F


                    print(f"Packet Number: {packet_data.packet_number}")
                    print(f"Timestamp: {packet_data.timestamp}")    
                    print(f"Source IP: {packet_data.src_ip}")
                    print(f"Destination IP: {packet_data.dst_ip}")
                    print(f"IP Protocol: {packet_data.ip_proto}")
                    print(f"IP TTL: {packet_data.ip_ttl}")
                    print(f"IP ID: {packet_data.ip_id}")    
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
        print("="*80)
        # Create connection identifiers - both directions
        forward_key = frozenset([
            f"src={packet_data.src_ip}:{packet_data.src_port}",
            f"dst={packet_data.dst_ip}:{packet_data.dst_port}"
        ])

        return forward_key, packet_data

    except Exception as e:
        print(f"Error analyzing file: {str(e)}")
        return None, None    

def analyze_mms_packets(pcap_path):

    if not os.path.exists(pcap_path):
        print(f"Error: File not found: {pcap_path}")
        return
    
    print(f"\n{'='*80}")
    print(f"Analyzing MMS packets in: {os.path.basename(pcap_path)}")
    print(f"Analysis started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*80}\n")
    
    # Dictionary to store packet data keyed by IP/port combinations
    # We have to use a frozen set as the key because lists are not hashable
    # The key is a set of strings with the format "src=ip:port" and "dst=ip:port"
    # The value is a list of PacketData objects
    # We must parse through this dict to check for any anomalies
    connection_data = {}
    
    try:
        # Create capture with filter for MMS (port 102)
        cap = pyshark.FileCapture(pcap_path, display_filter="mms", include_raw=True, use_json=True)
        
        # Total number of packets analyzed
        packet_count = 0
        
        # We go through each packet in the capture
        for packet in cap:
            # Limit the number of packets to analyze (for testing)
            if packet_count >= 10:
                return connection_data
                
            packet_data = PacketData()
            
            # Analyze the packet
            forward_key, packet_data = analyze_packet(packet)
            
            # add error handling for None values
            if forward_key is None:
                continue
            
            # Store packet in connection data dictionary
            if forward_key not in connection_data:
                
                connection_data[forward_key] = {
                    "connection_state": {},
                    "packets": []
                }


            # Check if this is the first packet in the connection
            if len(connection_data[forward_key]["packets"]) == 0:
                connection_data[forward_key]["connection_state"] = {
                    "last_seq_num": packet_data.seq_num,
                    "last_ack_num": packet_data.ack_num,
                    "last_flags": packet_data.tcp_flags,
                    "last_window": packet_data.tcp_window,
                    "last_timestamp": packet_data.timestamp
                }

                # Add the connection state to the dictionary 
                continue

            connection_state = {}

            ## Add checks for erronious/malicous packets, mmms pdu types, ip flags, etc.

            connection_data[forward_key]["connection_state"] = connection_state


            connection_data[forward_key]["packets"].append(packet_data)
            packet_count += 1
        
        cap.close()
            
        # Return the connection data dictionary for further processing
        return connection_data

    except Exception as e:
        print(f"Error analyzing file: {str(e)}")
        return {}

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <pcapng_file>")
        print("Example: python mms_connections.py capture.pcapng")
        sys.exit(1)
    
    foo = analyze_mms_packets(sys.argv[1])
    # for i in foo:
        # packet_obj = foo[i]
        # print(i)
        # for item in packet_obj:
        #     print(f"MMS PDU Type     : {item.mms_pdu_type}")
        #     print(f"Timestamp       : {item.timestamp}")
        #     print(f"Payload Length  : {item.payload_length}")
        #     print(f"Payload (Hex)   : {item.payload_hex}")
        #     print(f"Source IP       : {item.src_ip}")
        #     print(f"Source Port     : {item.src_port}")
        #     print(f"Destination IP  : {item.dst_ip}")
        #     print(f"Destination Port: {item.dst_port}")
        #     print(f"IP Protocol     : {item.ip_proto}")
        #     print(f"IP TTL          : {item.ip_ttl}")
        #     print(f"IP ID           : {item.ip_id}")
        #     print(f"Sequence Number : {item.seq_num}")
        #     print(f"Acknowledgment # : {item.ack_num}")
        #     print(f"TCP Flags       : {item.tcp_flags}")
        #     print(f"TCP Window      : {item.tcp_window}")
        #     print(f"TPKT Length     : {item.tpkt_length}")
        #     print(f"COTP Length     : {item.cotp_length}")
        #     print(f"COTP PDU Type   : {item.cotp_pdu_type}")
        #     print(f"MMS PDU Type    : {item.mms_pdu_type}")
        #     print(f"Packet Number   : {item.packet_number}")
        #     print("="*80)