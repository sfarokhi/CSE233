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
from scapy.all import Ether, IP, TCP, Raw, rdpcap, wrpcap, send
from scapy.packet import Packet
from typing import Dict, List, Optional, Set, Tuple, Any, Callable

@dataclass  
class PacketData:
    # Basic packet info
    packet_number: str = None
    timestamp: datetime = None
    
    # IP layer
    src_ip: str = None
    dst_ip: str = None
    ip_proto: str = None
    ip_ttl: str = None
    ip_id: str = None
    
    # TCP layer
    src_port: str = None
    dst_port: str = None
    seq_num: str = None
    ack_num: str = None
    tcp_flags: str = None
    tcp_window: str = None
    
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
    mms_domain: str = None
    mms_data_values: List[str] = field(default_factory=list)

def modify_mms_packet(pcapng_file, target_packet_number, modified_data):
    """
    Creates a modified copy of a specific packet from a pcapng file
    
    Args:
        pcapng_file: Path to the pcapng file
        target_packet_number: The packet number to modify
        modified_data: PacketData object with new values
    
    Returns:
        Modified packet
    """
    # Load the pcapng file
    packets = rdpcap(pcapng_file)
    
    # Find the target packet
    target_packet = None
    for packet in packets:
        if hasattr(packet, 'number') and str(packet.number) == str(target_packet_number):
            target_packet = packet
            break
    
    if not target_packet:
        print(f"Packet {target_packet_number} not found in the pcapng file")
        return None
    
    # Create a shallow copy
    modified_packet = target_packet.copy()
    
    # Modify the packet attributes
    if IP in modified_packet and modified_data.src_ip:
        modified_packet[IP].src = modified_data.src_ip
    if IP in modified_packet and modified_data.dst_ip:
        modified_packet[IP].dst = modified_data.dst_ip
    if IP in modified_packet and modified_data.ip_ttl:
        modified_packet[IP].ttl = int(modified_data.ip_ttl)
    if IP in modified_packet and modified_data.ip_id:
        # Convert hex string to int if needed
        if isinstance(modified_data.ip_id, str) and modified_data.ip_id.startswith('0x'):
            modified_packet[IP].id = int(modified_data.ip_id, 16)
        else:
            modified_packet[IP].id = int(modified_data.ip_id)
            
    if TCP in modified_packet and modified_data.src_port:
        modified_packet[TCP].sport = int(modified_data.src_port)
    if TCP in modified_packet and modified_data.dst_port:
        modified_packet[TCP].dport = int(modified_data.dst_port)
    if TCP in modified_packet and modified_data.seq_num:
        modified_packet[TCP].seq = int(modified_data.seq_num)
    if TCP in modified_packet and modified_data.ack_num:
        modified_packet[TCP].ack = int(modified_data.ack_num)
    if TCP in modified_packet and modified_data.tcp_flags:
        # Convert hex string to int if needed
        if isinstance(modified_data.tcp_flags, str) and modified_data.tcp_flags.startswith('0x'):
            modified_packet[TCP].flags = int(modified_data.tcp_flags, 16)
        else:
            modified_packet[TCP].flags = int(modified_data.tcp_flags)
    if TCP in modified_packet and modified_data.tcp_window:
        modified_packet[TCP].window = int(modified_data.tcp_window)
    
    # Modify MMS-related content in the payload if needed
    if Raw in modified_packet and modified_data.mms_domain:
        payload = bytearray(modified_packet[Raw].load)
        
        # Find the position where the original domain name starts
        domain_pos = modified_packet[Raw].load.find(b"WAGO61850ServerLogicalDevice")
        if domain_pos != -1:
            # Replace with new domain, ensuring same length
            original_domain = b"WAGO61850ServerLogicalDevice"
            new_domain = modified_data.mms_domain.encode()
            
            # Pad or truncate to match original length
            if len(new_domain) < len(original_domain):
                new_domain = new_domain + b'\x00' * (len(original_domain) - len(new_domain))
            elif len(new_domain) > len(original_domain):
                new_domain = new_domain[:len(original_domain)]
                
            # Replace the domain in the payload
            for i in range(len(new_domain)):
                if domain_pos + i < len(payload):
                    payload[domain_pos + i] = new_domain[i]
        
        # If a completely new payload is provided, use it instead
        if modified_data.raw_payload:
            payload = modified_data.raw_payload
        elif modified_data.payload_hex:
            payload = binascii.unhexlify(modified_data.payload_hex)
        
        # Update the packet with the modified payload
        modified_packet[Raw].load = bytes(payload)
    
    # Recalculate checksums
    if IP in modified_packet:
        del modified_packet[IP].chksum
    if TCP in modified_packet:
        del modified_packet[TCP].chksum
    
    return modified_packet

def save_modified_packet(packet, output_file="modified_packet.pcap"):
    """Save a modified packet to a pcap file"""
    if packet:
        wrpcap(output_file, packet)
        print(f"Modified packet saved to {output_file}")
    else:
        print("No packet to save")

# Example usage
if __name__ == "__main__":
    pcapng_file = "pcaps/Scenario_1.pcapng"
    
    # Create a PacketData object with modifications
    modified_data = PacketData()
    modified_data.src_ip = "192.168.1.100"
    modified_data.dst_ip = "192.168.1.200"
    modified_data.src_port = "60000"
    modified_data.dst_port = "102"
    modified_data.seq_num = "1000"
    modified_data.ack_num = "2000"
    modified_data.mms_domain = "MODIFIED61850ServerDevice"
    
    # Modify a specific packet (e.g., packet number 10017)
    modified_packet = modify_mms_packet(pcapng_file, "10017", modified_data)
    
    # Save the modified packet
    if modified_packet:
        save_modified_packet(modified_packet, "modified_mms_packet.pcap")