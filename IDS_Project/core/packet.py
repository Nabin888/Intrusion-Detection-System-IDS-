"""
Packet class for handling network activity data in an Intrusion Detection System.
"""
from enum import Enum, auto
from datetime import datetime
from typing import Dict, Any, Optional, ClassVar

class ActivityType(Enum):
    """Enumeration of possible activity types for network packets."""
    LOGIN_SUCCESS = auto()
    LOGIN_FAILED = auto()
    SUSPICIOUS_ACTIVITY = auto()
    FILE_ACCESS = auto()
    DATA_TRANSFER = auto()
    SYSTEM_COMMAND = auto()
    BLACKLISTED_IP_ACCESS = auto()
    NORMAL = auto()

class Packet:
    # Class-level constants for threat scoring
    _THREAT_SCORES: ClassVar[Dict[ActivityType, int]] = {
        ActivityType.LOGIN_SUCCESS: 0,    # No threat for successful logins
        ActivityType.LOGIN_FAILED: 40,    # Failed logins are suspicious
        ActivityType.SUSPICIOUS_ACTIVITY: 70,      # Explicitly suspicious activities
        ActivityType.FILE_ACCESS: 20,      # File access monitoring
        ActivityType.DATA_TRANSFER: 15,     # Data transfer monitoring
        ActivityType.SYSTEM_COMMAND: 25,    # System command monitoring
        ActivityType.BLACKLISTED_IP_ACCESS: 100,  # Blacklisted IP access
        ActivityType.NORMAL: 5,           # Normal background traffic
    }
    
    def __init__(
        self, 
        ip_address: str, 
        username: str, 
        activity_type: ActivityType, 
        timestamp: Optional[datetime] = None,
        protocol: str = "TCP",
        port: int = 0,
        payload_size: int = 0,
        threat_score: Optional[int] = None
    ) -> None:
        """
        Initialize a new Packet instance.
        
        Args:
            ip_address: Source IP address of activity
            username: Username associated with activity
            activity_type: Type of activity (from ActivityType enum)
            timestamp: When the activity occurred (defaults to current time)
            protocol: Network protocol (TCP, UDP, etc.)
            port: Port number
            payload_size: Size of packet payload in bytes
            threat_score: Override calculated threat score
        """
        self._ip_address = ip_address
        self._username = username
        self._activity_type = activity_type
        self._timestamp = timestamp if timestamp is not None else datetime.now()
        self._protocol = protocol
        self._port = port
        self._payload_size = payload_size
        
        if threat_score is not None:
            self._threat_score = threat_score
        else:
            self._threat_score = 0
            self.calculate_threat_score()
    
    @property
    def ip_address(self) -> str:
        """Get the source IP address of the packet."""
        return self._ip_address
    
    @property
    def username(self) -> str:
        """Get the username associated with the activity."""
        return self._username
    
    @property
    def timestamp(self) -> datetime:
        """Get the timestamp of when the activity occurred."""
        return self._timestamp
    
    @property
    def activity_type(self) -> ActivityType:
        """Get the type of activity."""
        return self._activity_type
    
    @property
    def threat_score(self) -> int:
        """Get calculated threat score."""
        return self._threat_score
    
    @property
    def protocol(self) -> str:
        """Get network protocol."""
        return self._protocol
    
    @property
    def port(self) -> int:
        """Get port number."""
        return self._port
    
    @property
    def payload_size(self) -> int:
        """Get payload size in bytes."""
        return self._payload_size
    
    def calculate_threat_score(self) -> None:
        """
        Calculate and update the threat score based on activity type.
        
        Scoring:
        - login_success: 0 (no threat)
        - login_failed: 40 (potential brute force)
        - suspicious: 70 (highly suspicious)
        - normal: 5 (background noise)
        """
        self._threat_score = self._THREAT_SCORES.get(self._activity_type, 0)
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the packet to a dictionary for storage or serialization.
        
        Returns:
            Dictionary containing all packet data
        """
        return {
            'ip_address': self._ip_address,
            'username': self._username,
            'timestamp': self._timestamp.isoformat(),
            'activity_type': self._activity_type.name,
            'threat_score': self._threat_score
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Packet':
        """
        Create a Packet from a dictionary.
        
        Args:
            data: Dictionary containing packet data
            
        Returns:
            A new Packet instance
        """
        return cls(
            ip_address=data['ip_address'],
            username=data['username'],
            activity_type=ActivityType[data['activity_type']],
            timestamp=datetime.fromisoformat(data['timestamp'])
        )
    
    def __str__(self) -> str:
        """
        Return a human-readable string representation of the packet.
        
        Returns:
            Formatted string with packet details
        """
        return (
            f"Packet(ip='{self._ip_address}', "
            f"user='{self._username}', "
            f"type={self._activity_type.name.lower()}, "
            f"score={self._threat_score}, "
            f"time={self._timestamp.strftime('%Y-%m-%d %H:%M:%S')})"
        )
