import pyshark
import binascii
import re
from dataclasses import dataclass, field
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from datetime import datetime
import pandas as pd
from typing import Dict, List, Optional, Set, Tuple, Any, Callable

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

    # Message type: Request or Response
    mms_message_type: str = None

    # Domain, commonly WAGO61850ServerLogicalDevice or None
    mms_domain: str = None

    # Stores any data values extracted from the MMS packet
    # For requests, this is a single itemid
    # For directory responses, this is a list of itemids
    mms_data_values: List[str]  = field(default_factory=list)
    
def plot_packet_data(packet_data_list: List[Any], 
                     x_attr: str = 'timestamp',
                     y_attr: str = 'payload_length',
                     color_attr: str = 'mms_message_type',
                     x_label: str = 'Time',
                     y_label: str = 'Payload Length (bytes)',
                     title: str = 'MMS Packet Data Over Time',
                     x_formatter: Optional[Callable] = None,
                     figsize: Tuple[int, int] = (12, 6)) -> Tuple[plt.Figure, plt.Axes]:
    """
    Plot packet data on an XY graph with flexible attribute selection.
    
    Args:
        packet_data_list: List of PacketData objects
        x_attr: Attribute name to use for the X-axis
        y_attr: Attribute name to use for the Y-axis
        color_attr: Attribute name to use for color grouping
        x_label: Label for X-axis
        y_label: Label for Y-axis
        title: Plot title
        x_formatter: Optional formatter for X-axis (for timestamps)
        figsize: Figure size as (width, height) tuple
    
    Returns:
        Tuple of (figure, axis) objects
    """
    # Extract data from packet list
    data = []
    for packet in packet_data_list:
        try:
            # Get attributes
            x_value = getattr(packet, x_attr)
            y_value = getattr(packet, y_attr)
            color_value = getattr(packet, color_attr)
            
            # Handle datetime conversion if needed
            if isinstance(x_value, str) and x_attr == 'timestamp':
                try:
                    x_value = datetime.strptime(x_value, "%Y-%m-%d %H:%M:%S.%f")
                except ValueError:
                    # Try alternative formats if needed
                    try:
                        x_value = datetime.strptime(x_value, "%Y-%m-%d %H:%M:%S")
                    except ValueError:
                        print(f"Could not parse timestamp: {x_value}")
                        continue
            
            data.append({
                'x_value': x_value,
                'y_value': y_value,
                'color_value': color_value
            })
        except (AttributeError, ValueError, TypeError) as e:
            print(f"Error processing packet {getattr(packet, 'packet_number', '?')}: {e}")
    
    # Create DataFrame
    df = pd.DataFrame(data)
    
    # Sort by x value if it's time-based
    if x_attr == 'timestamp':
        df = df.sort_values('x_value')
    
    # Create figure and axis
    fig, ax = plt.subplots(figsize=figsize)
    
    # Get unique color groups
    color_groups = df['color_value'].unique()
    
    # Default colors
    colors = ['blue', 'red', 'green', 'orange', 'purple', 'brown', 'pink', 'gray', 'olive', 'cyan']
    
    # Plot each group with a different color
    for i, group in enumerate(color_groups):
        group_data = df[df['color_value'] == group]
        color = colors[i % len(colors)]
        ax.scatter(group_data['x_value'], group_data['y_value'], 
                   color=color, label=str(group), alpha=0.7)
    
    # Format the x-axis for timestamps if needed
    if x_attr == 'timestamp':
        if x_formatter:
            ax.xaxis.set_major_formatter(x_formatter)
        else:
            ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
        fig.autofmt_xdate()  # Rotate date labels
    
    # Add labels and title
    ax.set_xlabel(x_label)
    ax.set_ylabel(y_label)
    ax.set_title(title)
    
    # Add legend if we have color groups
    if len(color_groups) > 1:
        ax.legend()
    
    # Add grid for better readability
    ax.grid(True, linestyle='--', alpha=0.7)
    
    # Tight layout
    plt.tight_layout()
    
    return fig, ax

def plot_time_vs_size(packet_data_list):
    """
    Plot packet data on an XY graph where X is timestamp and Y is payload length.
    Different colors are assigned based on MMS message type (Request vs Response).
    
    Args:
        packet_data_list: List of PacketData objects
    """
    # Convert timestamps to datetime objects
    timestamps = []
    payload_lengths = []
    message_types = []
    
    for packet in packet_data_list:
        try:
            # Store timestamp directly if it's already a datetime object
            timestamp = packet.timestamp if isinstance(packet.timestamp, datetime) else datetime.strptime(packet.timestamp, "%Y-%m-%d %H:%M:%S.%f")
            timestamps.append(timestamp)
            payload_lengths.append(packet.payload_length)
            message_types.append(packet.mms_message_type)
        except (ValueError, TypeError) as e:
            print(f"Error processing packet {packet.packet_number}: {e}")

    # Create a DataFrame for easier plotting
    df = pd.DataFrame({
        'timestamp': timestamps,
        'payload_length': payload_lengths,
        'message_type': message_types
    })
    
    # Sort by timestamp
    df = df.sort_values('timestamp')
    
    # Create figure and axis
    fig, ax = plt.subplots(figsize=(12, 6))
    
    # Plot requests and responses with different colors
    request_data = df[df['message_type'] == 'Request']
    response_data = df[df['message_type'] == 'Response']
    
    ax.scatter(request_data['timestamp'], request_data['payload_length'], 
               color='blue', label='Request', alpha=0.7)
    ax.scatter(response_data['timestamp'], response_data['payload_length'], 
               color='red', label='Response', alpha=0.7)
    
    # Format the x-axis to show readable timestamps
    ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
    fig.autofmt_xdate()  # Rotate date labels
    
    # Add labels and title
    ax.set_xlabel('Time')
    ax.set_ylabel('Payload Length (bytes)')
    ax.set_title('MMS Packet Payload Length Over Time')
    
    # Add legend
    ax.legend()
    
    # Add grid for better readability
    ax.grid(True, linestyle='--', alpha=0.7)
    
    # Tight layout
    plt.tight_layout()
    
    return fig, ax

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
        
        # Extract MMS data if available
        extract_mms_data(packet, packet_data)

        # Print MMS data if available
        if packet_data.mms_data:
            
            print("\nMMS Data Fields:")
            
            if 'confirmed_responsepdu_element' in packet_data.mms_data:
                packet_data.mms_message_type = "Response"
                print(f"MMS Packet Type: Response")

            elif 'confirmed_requestpdu_element' in packet_data.mms_data:
                packet_data.mms_message_type = "Request"
                print(f"MMS Packet Type: Request")
            else:
                print(f"MMS Packet Type: Unknown")

            # Request
            if packet_data.mms_message_type == "Request":

                if 'domainid' in packet_data.mms_data and 'itemid' in packet_data.mms_data:
                    
                    raw_domain = str(packet_data.mms_data['domainid']['all_values'])
                    packet_data.mms_domain = raw_domain.split(': ')[1][:-2] if ': ' in raw_domain else raw_domain

                    raw_itemid = str(packet_data.mms_data['itemid']['all_values'])
                    packet_data.mms_data_values.append(raw_itemid.split(': ')[1][:-2] if ': ' in raw_itemid else raw_itemid)

            # Response        
            else:

                # GetDirectory Response                       
                if 'itemid' in packet_data.mms_data:

                    raw_items = str(packet_data.mms_data['itemid']['all_values'])
                    items = [str(field).split(': ')[1].rstrip('>') for field in raw_items.split(',')]
                    items[-1] = items[-1][:-3]

                    packet_data.mms_data_values = items

        print(f"MMS Domain: {packet_data.mms_domain}")
        print(f"MMS Data Values: {packet_data.mms_data_values}")

        return packet_data

    except Exception as e:
        print(f"Error analyzing packet: {str(e)}")
        return None, None

def parse_layer_fields_container(field_container):
    """
    Recursively parses a LayerFieldsContainer and returns a structured dictionary.
    """
    if not isinstance(field_container, pyshark.packet.fields.LayerFieldsContainer):
        return None  # Ensure we only parse valid LayerFieldsContainer objects

    """Parse a pyshark LayerFieldsContainer into a dictionary structure."""
    # For LayerField objects, extract the actual value
    if hasattr(field_container, '_get_default_value'):
        default_value = field_container._get_default_value()
        if hasattr(default_value, '__str__') and ': ' in str(default_value):
            default_value = str(default_value).split(': ')[1]
    else:
        default_value = str(field_container)


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
        # print_mms_fields(mms_fields, indent=4)
        
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
    display_filter = 'mms'
    capture = pyshark.FileCapture(pcap_file, display_filter=display_filter)
    
    data = []  # To store connection data
    for packet in capture:
        packet_data = analyze_packet(packet)
        if packet_data:
            data.append(packet_data)

    fig, ax = plot_time_vs_size(data)
    plt.savefig('packet_data.png')

    # Custom attributes and labels
    fig, ax = plot_packet_data(
        data,
        x_attr='timestamp',
        y_attr='payload_length',  # Plot TPKT length instead
        color_attr='src_ip',   # Group by source IP instead of message type
        x_label='Time',
        y_label='Payload Length',
        title='MMS Packet Payload Length Over Time (Grouped by Source IP)',
    )
    plt.savefig('custom_plot.png')

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python script.py <pcap_file>")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    analyze_pcap_file(pcap_file)