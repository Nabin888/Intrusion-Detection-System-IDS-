"""
Real-time packet generator for simulating network traffic.
"""
import random
import time
from datetime import datetime, timedelta
from typing import List, Dict, Any
from enum import Enum
from .packet import Packet, ActivityType
from .ids_manager import IDSManager

class ThreatType(Enum):
    """Types of threats to simulate."""
    NORMAL = "normal"
    PORT_SCAN = "port_scan"
    BRUTE_FORCE = "brute_force"
    DDoS = "ddos"
    MALWARE = "malware"
    DATA_EXFILTRATION = "data_exfiltration"

class PacketGenerator:
    """Generates realistic network packets for IDS testing."""
    
    def __init__(self, ids_manager: IDSManager):
        self.ids_manager = ids_manager
        self.running = False
        
        # Sample data for realistic simulation
        self.sample_ips = [
            "192.168.1.100", "192.168.1.101", "192.168.1.102",
            "10.0.0.50", "10.0.0.51", "10.0.0.52",
            "172.16.0.10", "172.16.0.11", "172.16.0.12",
            "203.0.113.1", "203.0.113.2", "203.0.113.3",  # External IPs
            "198.51.100.1", "198.51.100.2", "198.51.100.3"
        ]
        
        self.suspicious_ips = [
            "185.220.101.182", "185.220.102.183",  # Known malicious IPs
            "192.168.1.200", "10.0.0.100"  # Internal suspicious
        ]
        
        self.usernames = [
            "admin", "user1", "user2", "guest", "operator",
            "analyst", "manager", "developer", "tester", "auditor"
        ]
        
        self.protocols = ["TCP", "UDP", "ICMP", "HTTP", "HTTPS", "FTP", "SSH"]
        self.ports = [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 8080, 8443]
        
        # Threat simulation parameters
        self.threat_probability = 0.15  # 15% chance of threat
        self.current_threat_type = ThreatType.NORMAL
        
    def generate_normal_packet(self) -> Packet:
        """Generate a normal network packet."""
        ip = random.choice(self.sample_ips)
        username = random.choice(self.usernames)
        protocol = random.choice(self.protocols)
        port = random.choice(self.ports)
        
        # Random activity types for normal traffic
        activities = [
            ActivityType.LOGIN_SUCCESS,
            ActivityType.FILE_ACCESS,
            ActivityType.DATA_TRANSFER,
            ActivityType.SYSTEM_COMMAND
        ]
        
        activity = random.choice(activities)
        
        packet = Packet(
            timestamp=datetime.now(),
            ip_address=ip,
            username=username,
            activity_type=activity,
            protocol=protocol,
            port=port,
            payload_size=random.randint(64, 1500),
            threat_score=random.randint(0, 20)  # Low threat for normal traffic
        )
        
        return packet
    
    def generate_port_scan_packet(self) -> Packet:
        """Generate a port scan attack packet."""
        ip = random.choice(self.suspicious_ips)
        
        # Port scan characteristics
        port = random.choice(range(1, 65535))
        username = "unknown"  # Scans often don't have valid usernames
        
        packet = Packet(
            timestamp=datetime.now(),
            ip_address=ip,
            username=username,
            activity_type=ActivityType.SUSPICIOUS_ACTIVITY,
            protocol="TCP",
            port=port,
            payload_size=random.randint(40, 100),  # Small packets for scanning
            threat_score=random.randint(60, 85)
        )
        
        return packet
    
    def generate_brute_force_packet(self) -> Packet:
        """Generate a brute force attack packet."""
        ip = random.choice(self.suspicious_ips)
        username = random.choice(["admin", "root", "administrator"])
        
        # Brute force on common ports
        port = random.choice([22, 23, 3389, 21, 25])
        
        packet = Packet(
            timestamp=datetime.now(),
            ip_address=ip,
            username=username,
            activity_type=ActivityType.LOGIN_FAILED,
            protocol="TCP",
            port=port,
            payload_size=random.randint(100, 300),
            threat_score=random.randint(70, 95)
        )
        
        return packet
    
    def generate_ddos_packet(self) -> Packet:
        """Generate a DDoS attack packet."""
        ip = random.choice(self.suspicious_ips)
        username = "unknown"
        
        # DDoS characteristics - high volume, varied ports
        port = random.choice([80, 443, 53, 22])
        
        packet = Packet(
            timestamp=datetime.now(),
            ip_address=ip,
            username=username,
            activity_type=ActivityType.SUSPICIOUS_ACTIVITY,
            protocol=random.choice(["TCP", "UDP"]),
            port=port,
            payload_size=random.randint(64, 512),
            threat_score=random.randint(80, 100)
        )
        
        return packet
    
    def generate_malware_packet(self) -> Packet:
        """Generate malware communication packet."""
        ip = random.choice(self.suspicious_ips)
        username = random.choice(self.usernames)
        
        # Malware often uses uncommon ports or protocols
        port = random.choice([4444, 5555, 6667, 8080, 12345])
        
        packet = Packet(
            timestamp=datetime.now(),
            ip_address=ip,
            username=username,
            activity_type=ActivityType.DATA_TRANSFER,
            protocol=random.choice(["TCP", "UDP"]),
            port=port,
            payload_size=random.randint(200, 1000),
            threat_score=random.randint(75, 95)
        )
        
        return packet
    
    def generate_data_exfiltration_packet(self) -> Packet:
        """Generate data exfiltration attempt packet."""
        ip = random.choice(self.suspicious_ips)
        username = random.choice(self.usernames)
        
        # Data exfiltration - large outbound transfers
        port = random.choice([21, 22, 443, 993])
        
        packet = Packet(
            timestamp=datetime.now(),
            ip_address=ip,
            username=username,
            activity_type=ActivityType.DATA_TRANSFER,
            protocol=random.choice(["TCP", "FTP", "HTTPS"]),
            port=port,
            payload_size=random.randint(5000, 15000),  # Large packets
            threat_score=random.randint(65, 90)
        )
        
        return packet
    
    def generate_packet(self) -> Packet:
        """Generate a packet based on current threat scenario."""
        # Determine if this should be a threat packet
        if random.random() < self.threat_probability:
            # Select threat type
            threat_types = [
                ThreatType.PORT_SCAN,
                ThreatType.BRUTE_FORCE,
                ThreatType.DDoS,
                ThreatType.MALWARE,
                ThreatType.DATA_EXFILTRATION
            ]
            
            threat_type = random.choice(threat_types)
            
            # Generate specific threat packet
            if threat_type == ThreatType.PORT_SCAN:
                return self.generate_port_scan_packet()
            elif threat_type == ThreatType.BRUTE_FORCE:
                return self.generate_brute_force_packet()
            elif threat_type == ThreatType.DDoS:
                return self.generate_ddos_packet()
            elif threat_type == ThreatType.MALWARE:
                return self.generate_malware_packet()
            elif threat_type == ThreatType.DATA_EXFILTRATION:
                return self.generate_data_exfiltration_packet()
        else:
            # Generate normal packet
            return self.generate_normal_packet()
    
    def simulate_attack_sequence(self, attack_type: ThreatType, duration_seconds: int = 30):
        """Simulate a specific attack sequence."""
        start_time = datetime.now()
        
        while (datetime.now() - start_time).total_seconds() < duration_seconds:
            if attack_type == ThreatType.PORT_SCAN:
                # Generate multiple port scan packets quickly
                for _ in range(random.randint(5, 15)):
                    packet = self.generate_port_scan_packet()
                    self.ids_manager.add_packet(packet)
                    time.sleep(0.1)
                    
            elif attack_type == ThreatType.BRUTE_FORCE:
                # Generate failed login attempts
                for _ in range(random.randint(3, 8)):
                    packet = self.generate_brute_force_packet()
                    self.ids_manager.add_packet(packet)
                    time.sleep(0.5)
                    
            elif attack_type == ThreatType.DDoS:
                # Generate high volume packets
                for _ in range(random.randint(10, 25)):
                    packet = self.generate_ddos_packet()
                    self.ids_manager.add_packet(packet)
                    time.sleep(0.05)
                    
            elif attack_type == ThreatType.MALWARE:
                # Generate periodic malware communication
                packet = self.generate_malware_packet()
                self.ids_manager.add_packet(packet)
                time.sleep(random.uniform(1, 3))
                
            elif attack_type == ThreatType.DATA_EXFILTRATION:
                # Generate large data transfers
                packet = self.generate_data_exfiltration_packet()
                self.ids_manager.add_packet(packet)
                time.sleep(random.uniform(0.5, 2))
            
            time.sleep(1)
    
    def start_continuous_generation(self, packets_per_second: int = 2):
        """Start continuous packet generation."""
        self.running = True
        interval = 1.0 / packets_per_second
        
        while self.running:
            packet = self.generate_packet()
            self.ids_manager.add_packet(packet)
            time.sleep(interval)
    
    def stop_generation(self):
        """Stop packet generation."""
        self.running = False
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get packet generation statistics."""
        stats = self.ids_manager.get_stats()
        stats.update({
            'threat_probability': self.threat_probability,
            'sample_ips_count': len(self.sample_ips),
            'suspicious_ips_count': len(self.suspicious_ips),
            'supported_threats': [t.value for t in ThreatType]
        })
        return stats
