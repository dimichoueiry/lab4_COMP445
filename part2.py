#!/usr/bin/env python3
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
import argparse
from collections import defaultdict
import sys

def find_clusters(packets, width, min_packets, is_probing=True):
    """Find clusters of packets based on time (probing) or port (scanning)."""
    if not packets:
        return []
    
    clusters = []
    current_cluster = [packets[0]]
    
    for packet in packets[1:]:
        if is_probing:
            # For probing, check time difference
            if packet['time'] - current_cluster[-1]['time'] <= width:
                current_cluster.append(packet)
            else:
                if len(current_cluster) >= min_packets:
                    clusters.append(current_cluster)
                current_cluster = [packet]
        else:
            # For scanning, check port difference
            if packet['port'] - current_cluster[-1]['port'] <= width:
                current_cluster.append(packet)
            else:
                if len(current_cluster) >= min_packets:
                    clusters.append(current_cluster)
                current_cluster = [packet]
    
    if len(current_cluster) >= min_packets:
        clusters.append(current_cluster)
    
    return clusters

def process_packets(packets, target_ip, width_probe, min_packets_probe, width_scan, min_packets_scan):
    """Process packets to find probing and scanning activities."""
    # Sort packets by time and port
    time_sorted = sorted(packets, key=lambda x: x['time'])
    port_sorted = sorted(packets, key=lambda x: x['port'])
    
    # Find probes (time-based clusters)
    probes = find_clusters(time_sorted, width_probe, min_packets_probe, True)
    
    # Find scans (port-based clusters)
    scans = find_clusters(port_sorted, width_scan, min_packets_scan, False)
    
    return probes, scans

def analyze_pcap(pcap_file, target_ip, width_probe, min_packets_probe, width_scan, min_packets_scan):
    """Analyze a pcap file for probing and scanning activities."""
    packets = rdpcap(pcap_file)
    
    # Separate TCP and UDP packets
    tcp_packets = []
    udp_packets = []
    
    for packet in packets:
        if IP in packet and packet[IP].dst == target_ip:
            if TCP in packet:
                tcp_packets.append({
                    'time': packet.time,
                    'port': packet[TCP].dport,
                    'src_ip': packet[IP].src
                })
            elif UDP in packet:
                udp_packets.append({
                    'time': packet.time,
                    'port': packet[UDP].dport,
                    'src_ip': packet[IP].src
                })
    
    # Process TCP packets
    tcp_probes, tcp_scans = process_packets(
        tcp_packets, target_ip, width_probe, min_packets_probe, width_scan, min_packets_scan
    )
    
    # Process UDP packets
    udp_probes, udp_scans = process_packets(
        udp_packets, target_ip, width_probe, min_packets_probe, width_scan, min_packets_scan
    )
    
    return {
        'tcp': {'probes': tcp_probes, 'scans': tcp_scans},
        'udp': {'probes': udp_probes, 'scans': udp_scans}
    }

def write_results(results, output_file):
    """Write analysis results to the output file."""
    with open(output_file, 'w') as f:
        f.write("Network Traffic Analysis Results\n")
        f.write("==============================\n\n")
        
        # Write TCP results
        f.write("TCP Analysis\n")
        f.write("------------\n")
        
        # TCP Probes
        f.write("\nProbing Activities:\n")
        if results['tcp']['probes']:
            for i, probe in enumerate(results['tcp']['probes'], 1):
                src_ips = defaultdict(int)
                for packet in probe:
                    src_ips[packet['src_ip']] += 1
                
                f.write(f"\nProbe {i}:\n")
                f.write(f"  Number of packets: {len(probe)}\n")
                f.write(f"  Time range: {probe[0]['time']:.2f} to {probe[-1]['time']:.2f} seconds\n")
                f.write("  Source IPs:\n")
                for ip, count in src_ips.items():
                    f.write(f"    {ip}: {count} packets\n")
        else:
            f.write("  No probing activities detected\n")
        
        # TCP Scans
        f.write("\nScanning Activities:\n")
        if results['tcp']['scans']:
            for i, scan in enumerate(results['tcp']['scans'], 1):
                src_ips = defaultdict(int)
                for packet in scan:
                    src_ips[packet['src_ip']] += 1
                
                f.write(f"\nScan {i}:\n")
                f.write(f"  Number of packets: {len(scan)}\n")
                f.write(f"  Port range: {scan[0]['port']} to {scan[-1]['port']}\n")
                f.write("  Source IPs:\n")
                for ip, count in src_ips.items():
                    f.write(f"    {ip}: {count} packets\n")
        else:
            f.write("  No scanning activities detected\n")
        
        # Write UDP results
        f.write("\nUDP Analysis\n")
        f.write("------------\n")
        
        # UDP Probes
        f.write("\nProbing Activities:\n")
        if results['udp']['probes']:
            for i, probe in enumerate(results['udp']['probes'], 1):
                src_ips = defaultdict(int)
                for packet in probe:
                    src_ips[packet['src_ip']] += 1
                
                f.write(f"\nProbe {i}:\n")
                f.write(f"  Number of packets: {len(probe)}\n")
                f.write(f"  Time range: {probe[0]['time']:.2f} to {probe[-1]['time']:.2f} seconds\n")
                f.write("  Source IPs:\n")
                for ip, count in src_ips.items():
                    f.write(f"    {ip}: {count} packets\n")
        else:
            f.write("  No probing activities detected\n")
        
        # UDP Scans
        f.write("\nScanning Activities:\n")
        if results['udp']['scans']:
            for i, scan in enumerate(results['udp']['scans'], 1):
                src_ips = defaultdict(int)
                for packet in scan:
                    src_ips[packet['src_ip']] += 1
                
                f.write(f"\nScan {i}:\n")
                f.write(f"  Number of packets: {len(scan)}\n")
                f.write(f"  Port range: {scan[0]['port']} to {scan[-1]['port']}\n")
                f.write("  Source IPs:\n")
                for ip, count in src_ips.items():
                    f.write(f"    {ip}: {count} packets\n")
        else:
            f.write("  No scanning activities detected\n")

def main():
    parser = argparse.ArgumentParser(description='Analyze pcap file for probing and scanning activities')
    parser.add_argument('-f', required=True, help='pcap filename')
    parser.add_argument('-t', required=True, help='target IP address')
    parser.add_argument('-l', type=float, required=True, help='width for probing (Wp)')
    parser.add_argument('-m', type=int, required=True, help='minimum packets for probing (Np)')
    parser.add_argument('-n', type=int, required=True, help='width for scanning (Ws)')
    parser.add_argument('-p', type=int, required=True, help='minimum packets for scanning (Ns)')
    
    args = parser.parse_args()
    
    try:
        results = analyze_pcap(
            args.f, args.t, args.l, args.m, args.n, args.p
        )
        write_results(results, 'part2_output.txt')
        print("Analysis complete. Results written to part2_output.txt")
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main() 