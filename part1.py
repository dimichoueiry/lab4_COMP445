#!/usr/bin/env python3
from collections import Counter, defaultdict
import os
import struct
from scapy.all import rdpcap, IP, TCP

def read_pcap_file(file_path):
    """Read a pcap file and return the packet data."""
    packets = []
    with open(file_path, 'rb') as f:
        # Skip pcap file header (24 bytes)
        f.seek(24)
        
        while True:
            # Read packet header (16 bytes)
            header = f.read(16)
            if not header or len(header) < 16:
                break
                
            # Parse packet header
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack('=IIII', header)
            
            # Read packet data
            packet_data = f.read(incl_len)
            if not packet_data or len(packet_data) < incl_len:
                break
                
            packets.append(packet_data)
            
    return packets

def analyze_packets(packets):
    """Analyze packets and return statistics."""
    # Count total packets
    total_packets = len(packets)
    
    # Count packets per source IP
    source_ips = Counter()
    
    # Count packets per destination port
    dest_ports = Counter()
    
    # Count packets per source IP and destination port pair
    ip_port_pairs = Counter()
    
    for packet in packets:
        try:
            # Parse IP header (starts at offset 14 for Ethernet header)
            ip_header = packet[14:34]
            iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
            
            # Get source IP
            source_ip = '.'.join(str(b) for b in iph[8])
            source_ips[source_ip] += 1
            
            # If it's a TCP packet (protocol = 6)
            if iph[6] == 6:
                # Parse TCP header
                tcp_header = packet[34:54]
                tcph = struct.unpack('!HHLLBBHHH', tcp_header)
                dest_port = tcph[1]
                
                dest_ports[dest_port] += 1
                ip_port_pairs[(source_ip, dest_port)] += 1
                
        except Exception as e:
            continue
    
    return {
        'total_packets': total_packets,
        'source_ips': source_ips,
        'dest_ports': dest_ports,
        'ip_port_pairs': ip_port_pairs
    }

def process_pcap_file(filename: str) -> dict:
    # Read pcap file
    packets = rdpcap(filename)
    
    # Initialize counters
    packet_count = 0
    src_ip_counts = defaultdict(int)
    dst_port_counts = defaultdict(int)
    ip_port_pairs = defaultdict(int)
    
    for packet in packets:
        if IP in packet:
            packet_count += 1
            src_ip = packet[IP].src
            src_ip_counts[src_ip] += 1
            
            if TCP in packet:
                dst_port = packet[TCP].dport
                dst_port_counts[dst_port] += 1
                ip_port_pairs[f"{src_ip}:{dst_port}"] += 1
    
    return {
        'packet_count': packet_count,
        'src_ip_counts': dict(src_ip_counts),
        'dst_port_counts': dict(dst_port_counts),
        'ip_port_pairs': dict(ip_port_pairs)
    }

def print_sorted_dict(d, title, output_file):
    """Print a sorted dictionary with proper formatting."""
    output_file.write(f"\n{title}\n")
    output_file.write("-" * (len(title) + 2) + "\n")
    for key, value in sorted(d.items(), key=lambda x: (-x[1], x[0])):
        output_file.write(f"{key}: {value}\n")

def analyze_pcap(pcap_file):
    """Analyze a single pcap file and return statistics."""
    packets = rdpcap(pcap_file)
    stats = {
        'total_packets': len(packets),
        'source_ips': defaultdict(int),
        'tcp_ports': defaultdict(int),
        'ip_port_pairs': defaultdict(int)
    }
    
    for packet in packets:
        if IP in packet:
            src_ip = packet[IP].src
            stats['source_ips'][src_ip] += 1
            
            if TCP in packet:
                dst_port = packet[TCP].dport
                stats['tcp_ports'][dst_port] += 1
                stats['ip_port_pairs'][f"{src_ip}:{dst_port}"] += 1
    
    return stats

def main():
    # Create output file
    with open('part1_output.txt', 'w') as f:
        f.write("PCAP Analysis Report\n")
        f.write("=" * 50 + "\n\n")
        
        # Process each directory
        for dir_name in ['Lab3-pcap-1', 'Lab3-pcap-2']:
            if not os.path.exists(dir_name):
                print(f"Directory {dir_name} not found. Skipping...")
                continue
                
            f.write(f"\nAnalyzing {dir_name}:\n")
            f.write("-" * 50 + "\n")
            
            # Process each pcap file in the directory
            for filename in os.listdir(dir_name):
                if filename.endswith('.pcap'):
                    pcap_file = os.path.join(dir_name, filename)
                    stats = analyze_pcap(pcap_file)
                    
                    f.write(f"\nFile: {filename}\n")
                    f.write(f"Total packets: {stats['total_packets']}\n")
                    
                    # Print source IPs
                    print_sorted_dict(stats['source_ips'], "Source IP Addresses:", f)
                    
                    # Print TCP ports
                    print_sorted_dict(stats['tcp_ports'], "Destination TCP Ports:", f)
                    
                    # Print IP-Port pairs
                    print_sorted_dict(stats['ip_port_pairs'], "Source IP and Destination Port Pairs:", f)
                    f.write("\n" + "-" * 50 + "\n")
        
        # Calculate and print overall statistics
        f.write("\nOverall Statistics:\n")
        f.write("-" * 50 + "\n")
        
        total_packets = 0
        all_source_ips = defaultdict(int)
        all_tcp_ports = defaultdict(int)
        all_ip_port_pairs = defaultdict(int)
        
        for dir_name in ['Lab3-pcap-1', 'Lab3-pcap-2']:
            if not os.path.exists(dir_name):
                continue
                
            for filename in os.listdir(dir_name):
                if filename.endswith('.pcap'):
                    pcap_file = os.path.join(dir_name, filename)
                    stats = analyze_pcap(pcap_file)
                    
                    total_packets += stats['total_packets']
                    for ip, count in stats['source_ips'].items():
                        all_source_ips[ip] += count
                    for port, count in stats['tcp_ports'].items():
                        all_tcp_ports[port] += count
                    for pair, count in stats['ip_port_pairs'].items():
                        all_ip_port_pairs[pair] += count
        
        f.write(f"\nTotal packets across all files: {total_packets}\n")
        print_sorted_dict(all_source_ips, "Overall Source IP Addresses:", f)
        print_sorted_dict(all_tcp_ports, "Overall Destination TCP Ports:", f)
        print_sorted_dict(all_ip_port_pairs, "Overall Source IP and Destination Port Pairs:", f)

if __name__ == "__main__":
    main() 