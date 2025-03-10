import pyshark
import binascii
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, FrozenSet

@dataclass
class PacketData:
    # Basic packet info
    packet_number: int = None
    timestamp: str = None
    
    # IP layer
    src_ip: str = None
    dst_ip: str = None
    ip_proto: str = None
    ip_ttl: int = None
    ip_id: str = None
    
    # TCP layer
    src_port: int = None
    dst_port: int = None
    seq_num: int = None
    ack_num: int = None
    tcp_flags: str = None
    tcp_window: int = None
    
    # Payload data
    raw_payload: bytes = None
    payload_hex: str = None
    payload_length: int = None
    
    # TPKT/COTP data
    tpkt_length: int = None
    cotp_length: int = None
    cotp_pdu_type: int = None
    
    # MMS specific data
    mms_data: Dict = field(default_factory=dict)
    
    # Variable tracking
    lln0_variables: Dict[str, Dict] = field(default_factory=dict)

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
            return None, None  # Skip if no IP layer
        
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
        
        # Extract MMS data if available
        extract_mms_data(packet, packet_data)
        
        # Extract LLN0$ variables
        extract_lln0_variables(packet, packet_data)

        print(f"Packet Number: {packet_data.packet_number}")
        print(f"Timestamp: {packet_data.timestamp}")    
        print(f"Source IP: {packet_data.src_ip}")
        print(f"Destination IP: {packet_data.dst_ip}")
        print(f"IP Protocol: {packet_data.ip_proto}")
        print(f"IP TTL: {packet_data.ip_ttl}")
        print(f"IP ID: {packet_data.ip_id}")    
        
        if packet_data.raw_payload:
            print("\nTCP Payload Data:")
            print(f"Payload Length: {packet_data.payload_length} bytes")
            print("Payload Hex:")
            
            # Print payload in hexdump format
            raw_payload = packet_data.raw_payload
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
        
        # Print MMS data if available
        if packet_data.mms_data:
            print("\nMMS Data Fields:")
            for key, value in packet_data.mms_data.items():
                if "pdu_element" in key:
                    print(f"  {key}: {value}")
        
        # Print LLN0$ variables if found
        if packet_data.lln0_variables:
            print("\nLLN0$ Variables:")
            for var_name, details in packet_data.lln0_variables.items():
                print(f"  Variable: {var_name}")
                for key, value in details.items():
                    print(f"    {key}: {value}")
            
        print("="*80)
        
        # Create connection identifiers - both directions
        forward_key = frozenset([
            f"src={packet_data.src_ip}:{packet_data.src_port}",
            f"dst={packet_data.dst_ip}:{packet_data.dst_port}"
        ])

        return forward_key, packet_data

    except Exception as e:
        print(f"Error analyzing packet: {str(e)}")
        return None, None

def extract_mms_data(packet, packet_data):
    """Extract all available MMS data fields from the packet"""
    if hasattr(packet, 'mms'):
        mms_layer = packet.mms
        
        # Extract all fields from the MMS layer
        mms_fields = {}
        
        # Get all available MMS fields
        for field_name in dir(mms_layer):
            # Skip internal/private attributes
            if field_name.startswith('_') or field_name in ['get_field', 'get_field_value', 'layer_name', 'pretty_print']:
                continue
            
            try:
                value = getattr(mms_layer, field_name)
                if value and not callable(value):
                    mms_fields[field_name] = value
            except Exception:
                pass
        
        packet_data.mms_data = mms_fields

def extract_lln0_variables(packet, packet_data):
    """Extract all variables following LLN0$ pattern"""
    
    # Regular expression to find LLN0$ followed by any characters
    lln0_pattern = re.compile(r'LLN0\$([a-zA-Z0-9_]+)')
    
    # Check in all layers for LLN0$ variables
    for layer_name in dir(packet):
        print(f"Layer Name: {layer_name}")
        if layer_name.startswith('_'):
            continue
        
        try:
            layer = getattr(packet, layer_name)
            
            for field_name in dir(layer):
                if field_name.startswith('_') or callable(getattr(layer, field_name)):
                    continue
                
                try:
                    value = getattr(layer, field_name)
                    if isinstance(value, str):
                        # Find all LLN0$ variables in the string
                        matches = lln0_pattern.findall(value)
                        for variable in matches:
                            if variable not in packet_data.lln0_variables:
                                packet_data.lln0_variables[variable] = {}
                            
                            packet_data.lln0_variables[variable].update({
                                "layer": layer_name,
                                "field": field_name,
                                "context": value
                            })
                except Exception:
                    print(f"1: Error extracting LLN0$ variables from {layer_name}.{field_name}")
                    pass
        except Exception:
            print(f"2: Error extracting LLN0$ variables from {layer_name}")
            pass
    
    # Also check in raw payload if available
    if packet_data.raw_payload:
        try:
            # Convert bytes to string for regex matching
            payload_str = packet_data.raw_payload.decode('utf-8', errors='ignore')
            matches = lln0_pattern.findall(payload_str)
            
            for variable in matches:
                if variable not in packet_data.lln0_variables:
                    packet_data.lln0_variables[variable] = {}
                
                # Find the context (20 chars before and after the match)
                start_pos = payload_str.find(f"LLN0${variable}")
                context_start = max(0, start_pos - 20)
                context_end = min(len(payload_str), start_pos + len(variable) + 25)
                context = payload_str[context_start:context_end]
                
                packet_data.lln0_variables[variable].update({
                    "layer": "raw_payload",
                    "offset": start_pos,
                    "context": context
                })
        except Exception:
            pass

def analyze_pcap_file(pcap_file):
    """Process a pcap file and track MMS packets"""
    # Open the pcap file with pyshark
    capture = pyshark.FileCapture(pcap_file, display_filter='mms')
    
    connections = {}  # To store connection data
    all_lln0_variables = {}  # To store all LLN0$ variables found
    counter = 0
    for packet in capture:
        if counter > 100:
            break
        counter += 1
        result = analyze_packet(packet)
        if result:
            conn_key, packet_data = result
            if conn_key:
                if conn_key not in connections:
                    connections[conn_key] = []
                connections[conn_key].append(packet_data)
                
                # Collect all LLN0$ variables
                for var_name, details in packet_data.lln0_variables.items():
                    if var_name not in all_lln0_variables:
                        all_lln0_variables[var_name] = []
                    
                    # Add packet reference
                    var_details = details.copy()
                    var_details["packet_number"] = packet_data.packet_number
                    var_details["timestamp"] = packet_data.timestamp
                    all_lln0_variables[var_name].append(var_details)
    
    # Print summary of connections
    print("\nConnection Summary:")
    for conn_key, packets in connections.items():
        print(f"Connection: {' <-> '.join(conn_key)}")
        print(f"Total packets: {len(packets)}")
        
        # Count LLN0$ variables
        lln0_vars = set()
        for p in packets:
            lln0_vars.update(p.lln0_variables.keys())
        
        if lln0_vars:
            print(f"LLN0$ variables: {', '.join(lln0_vars)}")
        
        print("-" * 40)
    
    # Print summary of all LLN0$ variables
    print("\nLLN0$ Variable Summary:")
    for var_name, occurrences in all_lln0_variables.items():
        print(f"Variable: LLN0${var_name}")
        print(f"Occurrences: {len(occurrences)}")
        print(f"First seen: Packet #{occurrences[0]['packet_number']} at {occurrences[0]['timestamp']}")
        print("-" * 40)

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python script.py <pcap_file>")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    analyze_pcap_file(pcap_file)