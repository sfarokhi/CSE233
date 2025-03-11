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
    mms_message_type: str = None
    mms_data_values: dict = field(default_factory=dict)
    
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
        print("="*80)
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
        
        # Extract MMS data if available
        extract_mms_data(packet, packet_data)
        
        # Print MMS data if available
        if packet_data.mms_data:
            print("\nMMS Data Fields:")
            for key, value in packet_data.mms_data.items():
                if "pdu_element" in key:
                    
                    if "response" in key:
                        packet_data.mms_message_type = "Response"
                        print(f"MMS Packet Type: Response")
                    elif "request" in key:
                        packet_data.mms_message_type = "Request"
                        print(f"MMS Packet Type: Request")
        
        # Extract LLN0$ variables
        extract_mms_data(packet, packet_data)
        
        """
            NEED TO START HERE:
            Extract LLN0$ variables FROM mms.identifier for directory (All Values)
            Extract LLN0$ variables FROM mms.itemid for data values (All Values)
        """

                    
        # Create connection identifiers - both directions
        forward_key = frozenset([
            f"src={packet_data.src_ip}:{packet_data.src_port}",
            f"dst={packet_data.dst_ip}:{packet_data.dst_port}"
        ])

        return forward_key, packet_data

    except Exception as e:
        print(f"Error analyzing packet: {str(e)}")
        return None, None

def parse_layer_fields_container(field_container):
    """
    Recursively parses a LayerFieldsContainer and returns a structured dictionary.
    """
    if not isinstance(field_container, pyshark.packet.fields.LayerFieldsContainer):
        return None  # Ensure we only parse valid LayerFieldsContainer objects

    parsed_data = {}

    # Extract key attributes
    parsed_data["default_value"] = field_container.get_default_value()
    parsed_data["all_values"] = field_container.all_fields  # List of all values
    parsed_data["show_name"] = getattr(field_container, 'showname', None)

    # Handle nested fields recursively if applicable
    if hasattr(field_container, 'field_names'):
        nested_fields = {}
        for field_name in field_container.field_names:
            nested_field = getattr(field_container, field_name, None)
            if isinstance(nested_field, pyshark.packet.fields.LayerFieldsContainer):
                nested_fields[field_name] = parse_layer_fields_container(nested_field)  # Recursive parsing
            else:
                nested_fields[field_name] = nested_field  # Directly store simple values

        parsed_data["nested_fields"] = nested_fields if nested_fields else None

    return parsed_data

def extract_mms_data(packet, packet_data):
    """
    There are four different packet types:
        GetServerDirectoryRequest
        GetServerDirectoryResponse
        GetDataValuesRequest
        GetDataValuesResponse
    Requests will always have a single itemid and domainid
    Responses will either have:
        DirectoryResponse: A list of listOfAccessResult items
        DataValuesResponse: 
    """
    if hasattr(packet, 'mms'):
        mms_layer = packet.mms
        
        # Extract all fields from the MMS layer
        mms_fields = {}
        print("+++++++++++++++++++++++++")
        
        for field_name in getattr(mms_layer, 'field_names', []):
            try:
                field_value = getattr(mms_layer, field_name, None)

                if isinstance(field_value, pyshark.packet.fields.LayerFieldsContainer):
                    # print(f"Parsing LayerFieldsContainer: {field_name}")
                    mms_fields[field_name] = parse_layer_fields_container(field_value)
                else:
                    mms_fields[field_name] = field_value  # Store non-container values directly

            except Exception as e:
                print(f"Error processing {field_name}: {e}")
        
        packet_data.mms_data = mms_fields
        print_mms_fields(mms_fields, indent=4)
        

def print_mms_fields(mms_fields, indent=0):
    """
    Recursively prints the structured MMS fields in a readable format.
    """
    indent_space = "    " * indent  # Indentation for readability

    for key, value in mms_fields.items():
        print(f"{indent_space}📌 {key}:")
        
        # Print main attributes
        print(f"{indent_space}    🔹 Default Value: {value.get('default_value', 'N/A')}")
        print(f"{indent_space}    🔹 Show Name: {value.get('show_name', 'N/A')}")
        
        # Print all values if available
        all_values = value.get("all_values", [])
        if all_values:
            print(f"{indent_space}    🔹 All Values:")
            for field in all_values:
                print(f"{indent_space}        - {field}")

        # Print nested fields (if any)
        nested_fields = value.get("nested_fields")
        if nested_fields:
            print(f"{indent_space}    🔹 Nested Fields:")
            print_mms_fields(nested_fields, indent + 1)



def analyze_pcap_file(pcap_file):
    """Process a pcap file and track MMS packets"""
    # Open the pcap file with pyshark
    display_filter = 'mms or frame.number == 10017 or frame.number == 10018 or frame.number == 12548 or frame.number == 12549'
    capture = pyshark.FileCapture(pcap_file, display_filter=display_filter)
    
    connections = {}  # To store connection data
    all_lln0_variables = {}  # To store all LLN0$ variables found
    counter = 0
    for packet in capture:
        if counter > 10:
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
        
    #     # Count LLN0$ variables
    #     lln0_vars = set()
    #     for p in packets:
    #         lln0_vars.update(p.lln0_variables.keys())
        
    #     if lln0_vars:
    #         print(f"LLN0$ variables: {', '.join(lln0_vars)}")
        
    #     print("-" * 40)
    
    # # Print summary of all LLN0$ variables
    # print("\nLLN0$ Variable Summary:")
    # for var_name, occurrences in all_lln0_variables.items():
    #     print(f"Variable: LLN0${var_name}")
    #     print(f"Occurrences: {len(occurrences)}")
    #     print(f"First seen: Packet #{occurrences[0]['packet_number']} at {occurrences[0]['timestamp']}")
    #     print("-" * 40)

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python script.py <pcap_file>")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    analyze_pcap_file(pcap_file)