"""
Brute Force Detector module for detecting brute force login attempts.

This module provides the BruteForceDetector class which tracks failed login attempts
per IP address and detects potential brute force attacks.
"""
from typing import Dict, Optional
from datetime import datetime, timedelta
from .packet import Packet, ActivityType

class BruteForceDetector:
    """
    Detects brute force login attempts by tracking failed login attempts per IP address.
    
    This class maintains a dictionary of IP addresses and their corresponding
    failed login attempt counts. It provides methods to detect potential brute
    force attacks based on configurable thresholds.
    
    Attributes:
        failed_attempts: Dictionary mapping IP addresses to their failed attempt counts
        threshold: Number of failed attempts before considering it a potential attack
    """
    
    def __init__(self, threshold: int = 5) -> None:
        """
        Initialize the BruteForceDetector with the given threshold.
        
        Args:
            threshold: Number of failed attempts before considering it a potential attack
        """
        self.failed_attempts: Dict[str, Dict[str, int]] = {}  # {ip: {'count': int, 'last_attempt': timestamp}}
        self.threshold = threshold
    
    def detect(self, packet: Packet) -> str:
        """
        Analyze a packet for potential brute force login attempts.
        
        Args:
            packet: The Packet object to analyze
            
        Returns:
            str: Threat level as "LOW", "MEDIUM", "HIGH", or "CRITICAL"
        """
        # Only process failed login attempts
        if packet.activity_type != ActivityType.LOGIN_FAILED:
            return "LOW"
        
        ip_address = packet.ip_address
        current_time = datetime.now()
        
        # Initialize or update the attempt count for this IP
        if ip_address not in self.failed_attempts:
            self.failed_attempts[ip_address] = {
                'count': 1,
                'last_attempt': current_time
            }
        else:
            self.failed_attempts[ip_address]['count'] += 1
            self.failed_attempts[ip_address]['last_attempt'] = current_time
        
        # Clean up old entries to prevent memory leaks
        self._cleanup_old_entries()
        
        # Get the current attempt count
        attempts = self.failed_attempts[ip_address]['count']
        
        # Determine threat level based on attempt count
        if attempts > 10:
            return "CRITICAL"
        elif attempts > 5:
            return "HIGH"
        elif attempts > 2:
            return "MEDIUM"
        return "LOW"
    
    def reset(self, ip_address: str) -> None:
        """
        Reset the failed attempt counter for a specific IP address.
        
        Args:
            ip_address: The IP address to reset
        """
        if ip_address in self.failed_attempts:
            del self.failed_attempts[ip_address]
    
    def get_attempts(self, ip_address: str) -> int:
        """
        Get the number of failed login attempts for a specific IP address.
        
        Args:
            ip_address: The IP address to check
            
        Returns:
            int: Number of failed attempts, or 0 if IP not found
        """
        return self.failed_attempts.get(ip_address, {}).get('count', 0)
    
    def _cleanup_old_entries(self, max_age_minutes: int = 30) -> None:
        """
        Remove entries older than the specified age to prevent memory leaks.
        
        Args:
            max_age_minutes: Maximum age in minutes before an entry is considered old
        """
        current_time = datetime.now()
        max_age = timedelta(minutes=max_age_minutes)
        
        # Create a list of IPs to remove
        to_remove = [
            ip for ip, data in self.failed_attempts.items()
            if current_time - data['last_attempt'] > max_age
        ]
        
        # Remove old entries
        for ip in to_remove:
            del self.failed_attempts[ip]
    
    def get_all_attempts(self) -> Dict[str, int]:
        """
        Get a dictionary of all IPs and their failed attempt counts.
        
        Returns:
            Dict[str, int]: Dictionary mapping IP addresses to their attempt counts
        """
        return {
            ip: data['count']
            for ip, data in self.failed_attempts.items()
        }
