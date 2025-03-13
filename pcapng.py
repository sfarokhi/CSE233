import pyshark
import numpy as np
import binascii
import re
from dataclasses import dataclass, field
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import matplotlib.patches as mpatches
from datetime import datetime
from collections import Counter, defaultdict
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

def data_values_vs_payload_length(packet_data_list: List[Any], max_items: int = 15, 
                                      title: str = 'Average Payload Length by MMS Data Values', 
                                      figsize: Tuple[int, int] = (15, 10), 
                                      color: str = 'skyblue', edgecolor: str = 'navy', 
                                      sort_by: str = 'frequency') -> Tuple[plt.Figure, plt.Axes]:
    """
    Create a bar chart showing the average payload length for each MMS data value,
    with auto-sizing to prevent text collisions.
    
    Args:
        packet_data_list: List of PacketData objects
        max_items: Maximum number of items to show (for readability)
        title: Chart title
        figsize: Figure size as (width, height) tuple
        color: Default bar color
        edgecolor: Bar edge color
        sort_by: How to sort the bars ('frequency', 'length', or 'alphabetical')
        
    Returns:
        Tuple of (figure, axis) objects
    """
    import numpy as np
    import matplotlib.patches as mpatches
    from collections import defaultdict, Counter
    
    # Track values, their payload lengths, and source IPs
    value_payload_lengths = defaultdict(list)
    value_to_ips = defaultdict(list)
    
    for packet in packet_data_list:
        values = getattr(packet, 'mms_data_values', [])
        payload_length = getattr(packet, 'payload_length', 0)
        src_ip = getattr(packet, 'src_ip', 'unknown')
        
        if not values or payload_length is None:
            continue
            
        if isinstance(values, list):
            for value in values:
                value_payload_lengths[value].append(payload_length)
                value_to_ips[value].append(src_ip)
        else:
            value_payload_lengths[values].append(payload_length)
            value_to_ips[values].append(src_ip)
    
    # Calculate average payload length and frequency for each value
    avg_payload_lengths = {}
    frequencies = {}
    
    for value, lengths in value_payload_lengths.items():
        avg_payload_lengths[value] = sum(lengths) / len(lengths)
        frequencies[value] = len(lengths)
    
    # Convert to DataFrame for easier manipulation
    df = pd.DataFrame({
        'mms_value': list(avg_payload_lengths.keys()),
        'avg_payload_length': list(avg_payload_lengths.values()),
        'frequency': list(frequencies.values())
    })
    
    # Sort based on user preference - default to frequency
    if sort_by == 'length':
        df = df.sort_values('avg_payload_length', ascending=False)
    elif sort_by == 'alphabetical':
        df = df.sort_values('mms_value')
    else:  # 'frequency' (default)
        df = df.sort_values('frequency', ascending=False)
    
    # Limit to max_items for readability
    if max_items and len(df) > max_items:
        df = df.head(max_items)
        truncated = True
    else:
        truncated = False
    
    # Adjust figure width based on number of bars
    # Ensure at least 0.8 inch per bar plus margins
    min_width = len(df) * 0.8 + 4
    actual_width = max(figsize[0], min_width)
    
    # Create figure and axis
    fig, ax = plt.subplots(figsize=(actual_width, figsize[1]))
    
    # Set up second axis for frequency annotations
    ax2 = ax.twinx()
    
    # Get unique source IPs across all data values for color mapping
    all_unique_ips = set()
    for ips in value_to_ips.values():
        all_unique_ips.update(ips)
    all_unique_ips = sorted(list(all_unique_ips))
    
    # Create a color map for unique IPs
    ip_colors = plt.cm.tab20(np.linspace(0, 1, len(all_unique_ips)))
    ip_color_map = {ip: ip_colors[i] for i, ip in enumerate(all_unique_ips)}
    
    # Create a legend mapping
    legend_patches = [mpatches.Patch(color=ip_color_map[ip], label=ip) for ip in all_unique_ips]
    
    # Create the stacked bar chart showing IP contribution to each value
    for i, row in enumerate(df.itertuples()):
        value = row.mms_value
        full_height = row.avg_payload_length
        
        # Get IP breakdown for this value
        if value in value_to_ips:
            # Count occurrences of each IP for this value
            ip_counter = Counter(value_to_ips[value])
            total = sum(ip_counter.values())
            
            bottom = 0
            # Draw a segment for each source IP proportional to their contribution
            for ip, count in ip_counter.items():
                # Height proportional to this IP's contribution
                height = (count / total) * full_height
                ax.bar(i, height, bottom=bottom, color=ip_color_map[ip], edgecolor=edgecolor, width=0.8)
                
                # Add percentage label if segment is large enough
                if count / total > 0.05 and height > full_height * 0.05:
                    percentage = count / total * 100
                    ax.text(i, bottom + height/2, f"{percentage:.1f}%", 
                            ha='center', va='center', color='white', fontweight='bold')
                
                bottom += height
    
    # Plot frequency as red dots on second axis
    ax2.plot(range(len(df)), df['frequency'], 'ro', label='Frequency')
    
    # Add frequency labels with smaller font and offset to avoid collisions
    for i, freq in enumerate(df['frequency']):
        ax2.text(i, freq * 1.05, f"n={freq}", ha='center', color='red', fontsize=9)
    
    # Set the x-tick positions and labels - vertical for better readability
    ax.set_xticks(range(len(df['mms_value'])))
    ax.set_xticklabels(df['mms_value'], rotation=90, ha='center')
    
    # Add value labels on top of bars showing average payload length
    max_payload = df['avg_payload_length'].max() if not df.empty else 0
    for i, avg_len in enumerate(df['avg_payload_length']):
        ax.text(i, avg_len * 1.01, f'{avg_len:.1f}', ha='center', va='bottom', fontsize=9)
    
    # Ensure y-axis starts at zero
    ax.set_ylim(bottom=0)
    
    # Set labels and title
    ax.set_xlabel('MMS Data Values', labelpad=15)
    ax.set_ylabel('Average Payload Length (bytes)')
    ax2.set_ylabel('Frequency (packets)', color='red')
    ax2.tick_params(axis='y', labelcolor='red')
    
    # Add note if data was truncated
    if truncated:
        plot_title = f"{title}\n(Showing top {max_items} values by {sort_by})"
    else:
        plot_title = title
    ax.set_title(plot_title)
    
    # Add grid for better readability
    ax.grid(True, axis='y', linestyle='--', alpha=0.7)
    
    # Adjust legend position based on number of IPs
    if len(all_unique_ips) > 10:
        # For many IPs, place legend outside
        ax.legend(handles=legend_patches, title="Source IP", bbox_to_anchor=(1.02, 1), loc='upper left')
    else:
        # For fewer IPs, place in upper right corner inside
        ax.legend(handles=legend_patches, title="Source IP", loc='upper right')
    
    # Set tight layout with appropriate padding
    plt.tight_layout(pad=2.0)
    
    # Add extra bottom padding for x-labels
    plt.subplots_adjust(bottom=0.25)
    
    return fig, ax

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
                        # print(f"Could not parse timestamp: {x_value}")
                        continue
            
            data.append({
                'x_value': x_value,
                'y_value': y_value,
                'color_value': color_value
            })
        except (AttributeError, ValueError, TypeError) as e:
            # print(f"Error processing packet {getattr(packet, 'packet_number', '?')}: {e}")
            pass
    
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
        # print("="*80)
        # print(f"Packet Number: {packet_data.packet_number}")
        # print(f"Timestamp: {packet_data.timestamp}")    
        # print(f"Source IP: {packet_data.src_ip}")
        # print(f"Destination IP: {packet_data.dst_ip}")
        # print(f"IP Protocol: {packet_data.ip_proto}")
        # print(f"IP TTL: {packet_data.ip_ttl}")
        # print(f"IP ID: {packet_data.ip_id}")    
        
        if packet_data.raw_payload:
            # print("\nTCP Payload Data:")
            # print(f"Payload Length: {packet_data.payload_length} bytes")
            # print("Payload Hex:")
            
            # Print payload in hexdump format
            raw_payload = packet_data.raw_payload
            for i in range(0, len(raw_payload), 16):
                chunk = raw_payload[i:i+16]
                hex_values = ' '.join(f'{b:02x}' for b in chunk)
                ascii_values = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
                # print(f"  {i:04x}: {hex_values:<48}  |{ascii_values}|")
        
        # Extract MMS data if available
        extract_mms_data(packet, packet_data)

        # Print MMS data if available
        if packet_data.mms_data:
            
            # print("\nMMS Data Fields:")
            
            if 'confirmed_responsepdu_element' in packet_data.mms_data:
                packet_data.mms_message_type = "Response"
                # print(f"MMS Packet Type: Response")

            elif 'confirmed_requestpdu_element' in packet_data.mms_data:
                packet_data.mms_message_type = "Request"
                # print(f"MMS Packet Type: Request")
            else:
                # print(f"MMS Packet Type: Unknown")
                pass

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

        # print(f"MMS Domain: {packet_data.mms_domain}")
        # print(f"MMS Data Values: {packet_data.mms_data_values}")

        return packet_data

    except Exception as e:
        # print(f"Error analyzing packet: {str(e)}")
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
                    # # print(f"Parsing LayerFieldsContainer: {field_name}")
                    mms_fields[field_name] = parse_layer_fields_container(field_value)
                else:
                    mms_fields[field_name] = field_value  # Store non-container values directly

            except Exception as e:
                # print(f"Error processing {field_name}: {e}")
                pass
        
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
        
    # fig, ax = plot_packet_data(
    #     data,
    #     x_attr='timestamp',
    #     y_attr='payload_length',  # Plot TPKT length instead
    #     color_attr='src_ip',   # Group by source IP instead of message type
    #     x_label='Time',
    #     y_label='Payload Length',
    #     title='MMS Packet Payload Length Over Time (Grouped by Source IP)',
    # )
    # plt.savefig('payload_length_vs_time.png')

    # fig, ax = data_values_vs_payload_length(data)
    # plt.savefig('data_values_vs_payload_length.png')

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        # print("Usage: python script.py <pcap_file>")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    analyze_pcap_file(pcap_file)