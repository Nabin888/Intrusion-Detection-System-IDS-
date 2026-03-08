"""
IDS Manager - Central controller for the Intrusion Detection System.

This module provides the IDSManager class which serves as the main controller
for managing packets, users, logs, and blacklisted IPs in the IDS.
"""
from queue import Queue
from typing import Dict, Set, List, Optional, Any
from datetime import datetime

from .packet import Packet
from .user import User, UserRole

class IDSManager:
    """
    Central controller for the Intrusion Detection System.
    
    Manages users, packets, blacklisted IPs, and provides methods for
    packet processing and threat detection.
    
    Attributes:
        users: Dictionary mapping usernames to User objects
        blacklisted_ips: Set of blacklisted IP addresses
        logs: List of all processed Packet objects
        packet_queue: Queue for real-time packet processing
    """
    
    def __init__(self) -> None:
        """Initialize the IDS Manager with empty data structures."""
        self.users: Dict[str, User] = {}
        self.blacklisted_ips: Set[str] = set()
        self.logs: List[Packet] = []
        self.packet_queue: Queue[Packet] = Queue()
    
    def add_packet(self, packet: Packet) -> None:
        """
        Add a packet to the system for processing.
        
        Args:
            packet: The Packet object to add
            
        Steps:
            1. Add packet to the processing queue
            2. Add packet to logs
            3. Create or update user information
        """
        # Add to processing queue
        self.packet_queue.put(packet)
        
        # Add to logs
        self.logs.append(packet)
        
        # Create user if not exists
        if packet.username not in self.users:
            self.users[packet.username] = User(
                username=packet.username,
                role=UserRole.VIEWER,  # Default role
                email=f"{packet.username}@example.com"  # Default email
            )
    
    def process_packet(self) -> Dict[str, Any]:
        """
        Process the next packet in the queue.
        
        Returns:
            Dictionary containing:
            - status: 'processed', 'queue_empty', or 'blacklisted'
            - packet: The processed packet (if any)
            - threat_detected: Boolean indicating if threat was detected
            - details: Additional information about the processing
            
        Raises:
            Exception: If there's an error processing the packet
        """
        if self.packet_queue.empty():
            return {
                'status': 'queue_empty',
                'packet': None,
                'threat_detected': False,
                'details': 'No packets in queue'
            }
        
        try:
            # Get next packet
            packet = self.packet_queue.get()
            
            # Check if IP is blacklisted
            if packet.ip_address in self.blacklisted_ips:
                return {
                    'status': 'blacklisted',
                    'packet': packet,
                    'threat_detected': True,
                    'details': f'Blacklisted IP: {packet.ip_address}'
                }
            
            # Get or create user
            user = self.get_user(packet.username)
            if user is None:
                user = User(
                    username=packet.username,
                    role=UserRole.VIEWER,
                    email=f"{packet.username}@example.com"
                )
                self.users[packet.username] = user
            
            # Update user activity
            user.add_activity(packet)
            
            # Check for failed login attempts
            if packet.activity_type == packet.activity_type.LOGIN_FAILED:
                user.increment_failed_attempts()
            
            # Determine threat status
            threat_detected = (
                packet.threat_score > 50 or  # High threat score
                user.threat_level.value in ['HIGH', 'CRITICAL']  # User threat level
            )
            
            return {
                'status': 'processed',
                'packet': packet,
                'threat_detected': threat_detected,
                'user': user,
                'details': {
                    'threat_score': packet.threat_score,
                    'user_threat_level': user.threat_level.value,
                    'failed_attempts': user.failed_login_attempts
                }
            }
            
        except Exception as e:
            return {
                'status': 'error',
                'packet': packet,
                'threat_detected': False,
                'details': f'Error processing packet: {str(e)}'
            }
        finally:
            # Mark task as done
            if not self.packet_queue.empty():
                self.packet_queue.task_done()
    
    def blacklist_ip(self, ip_address: str) -> bool:
        """
        Add an IP address to the blacklist.
        
        Args:
            ip_address: The IP address to blacklist
            
        Returns:
            True if IP was added, False if it was already blacklisted
        """
        if ip_address not in self.blacklisted_ips:
            self.blacklisted_ips.add(ip_address)
            return True
        return False
    
    def remove_from_blacklist(self, ip_address: str) -> bool:
        """
        Remove an IP address from the blacklist.
        
        Args:
            ip_address: The IP address to remove from blacklist
            
        Returns:
            True if IP was removed, False if it wasn't in the blacklist
        """
        if ip_address in self.blacklisted_ips:
            self.blacklisted_ips.remove(ip_address)
            return True
        return False
    
    def is_ip_blacklisted(self, ip_address: str) -> bool:
        """
        Check if an IP address is blacklisted.
        
        Args:
            ip_address: The IP address to check
            
        Returns:
            True if the IP is blacklisted, False otherwise
        """
        return ip_address in self.blacklisted_ips
    
    def get_user(self, username: str) -> Optional[User]:
        """
        Get a user by username.
        
        Args:
            username: The username to look up
            
        Returns:
            User object if found, None otherwise
        """
        return self.users.get(username)
    
    def get_all_logs(self) -> List[Packet]:
        """
        Get all logged packets.
        
        Returns:
            List of all Packet objects in the log
        """
        return self.logs.copy()
    
    def get_recent_logs(self, count: int = 100) -> List[Packet]:
        """
        Get the most recent log entries.
        
        Args:
            count: Number of recent logs to return (default: 100)
            
        Returns:
            List of recent Packet objects, most recent first
        """
        return self.logs[-count:][::-1]  # Return in reverse chronological order
    
    def get_blacklisted_ips(self) -> Set[str]:
        """
        Get all blacklisted IP addresses.
        
        Returns:
            Set of blacklisted IP addresses
        """
        return self.blacklisted_ips.copy()
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get statistics about the IDS state.
        
        Returns:
            Dictionary containing various statistics
        """
        return {
            'total_users': len(self.users),
            'total_logs': len(self.logs),
            'blacklisted_ips': len(self.blacklisted_ips),
            'queue_size': self.packet_queue.qsize(),
            'threat_levels': {
                'high_risk_users': sum(1 for u in self.users.values() 
                                     if u.threat_level.value in ['HIGH', 'CRITICAL']),
                'suspicious_activities': sum(1 for p in self.logs 
                                          if p.threat_score > 50)
            }
        }
