"""
User class for managing user accounts, authentication, and threat monitoring.
"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import List, Dict, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .packet import Packet

class UserRole(Enum):
    """Enumeration of user roles and permissions."""
    ADMIN = auto()
    ANALYST = auto()
    VIEWER = auto()

class ThreatLevel(Enum):
    """Enumeration of threat levels for user accounts."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class User:
    """
    Represents a system user with authentication, authorization, and threat monitoring.
    
    Attributes:
        username: Unique identifier for the user
        failed_login_attempts: Number of consecutive failed login attempts
        activity_history: List of Packet objects representing user activity
        last_login_time: Timestamp of the last successful login
        threat_level: Current threat level (LOW, MEDIUM, HIGH, CRITICAL)
        role: User role (ADMIN, ANALYST, VIEWER)
        email: User's email address
        is_active: Whether the account is active
    """
    
    def __init__(self, username: str, role: UserRole = UserRole.VIEWER, 
                 email: str = "", is_active: bool = True):
        """
        Initialize a new User instance.
        
        Args:
            username: Unique identifier for the user
            role: User role (default: VIEWER)
            email: User's email address (default: empty string)
            is_active: Whether the account is active (default: True)
        """
        self._username = username
        self._failed_login_attempts = 0
        self._activity_history: List['Packet'] = []
        self._last_login_time: Optional[datetime] = None
        self._threat_level = ThreatLevel.LOW
        self.role = role
        self.email = email
        self.is_active = is_active
    
    @property
    def username(self) -> str:
        """Get the username."""
        return self._username
    
    @property
    def failed_login_attempts(self) -> int:
        """Get the number of failed login attempts."""
        return self._failed_login_attempts
    
    @property
    def activity_history(self) -> List['Packet']:
        """Get a copy of the user's activity history."""
        return self._activity_history.copy()
    
    @property
    def last_login_time(self) -> Optional[datetime]:
        """Get the timestamp of the last login."""
        return self._last_login_time
    
    @property
    def threat_level(self) -> ThreatLevel:
        """Get the current threat level."""
        return self._threat_level
    
    def add_activity(self, packet: 'Packet') -> None:
        """
        Add a packet to the user's activity history and update last login time.
        
        Args:
            packet: The Packet object representing the user activity
        """
        self._activity_history.append(packet)
        self._last_login_time = datetime.now()
    
    def increment_failed_attempts(self) -> None:
        """Increment the failed login attempts counter and update threat level."""
        self._failed_login_attempts += 1
        self._update_threat_level()
    
    def reset_attempts(self) -> None:
        """Reset the failed login attempts counter to zero and update threat level."""
        self._failed_login_attempts = 0
        self._update_threat_level()
    
    def _update_threat_level(self) -> None:
        """Update the threat level based on failed login attempts."""
        if self._failed_login_attempts <= 2:
            self._threat_level = ThreatLevel.LOW
        elif 3 <= self._failed_login_attempts <= 5:
            self._threat_level = ThreatLevel.MEDIUM
        elif 6 <= self._failed_login_attempts <= 10:
            self._threat_level = ThreatLevel.HIGH
        else:
            self._threat_level = ThreatLevel.CRITICAL
    
    def calculate_risk_level(self) -> ThreatLevel:
        """
        Calculate and return the current threat level.
        
        Returns:
            The current ThreatLevel based on failed login attempts
        """
        self._update_threat_level()
        return self._threat_level
    
    def to_dict(self) -> Dict:
        """
        Convert the User object to a dictionary for serialization.
        
        Returns:
            Dictionary containing user data
        """
        return {
            'username': self._username,
            'failed_login_attempts': self._failed_login_attempts,
            'last_login_time': self._last_login_time.isoformat() if self._last_login_time else None,
            'threat_level': self._threat_level.value,
            'role': self.role.name,
            'email': self.email,
            'is_active': self.is_active
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'User':
        """
        Create a User object from a dictionary.
        
        Args:
            data: Dictionary containing user data
            
        Returns:
            A new User instance
        """
        user = cls(
            username=data['username'],
            role=UserRole[data['role']],
            email=data.get('email', ''),
            is_active=data.get('is_active', True)
        )
        
        user._failed_login_attempts = data.get('failed_login_attempts', 0)
        
        if 'last_login_time' in data and data['last_login_time']:
            user._last_login_time = datetime.fromisoformat(data['last_login_time'])
        
        user._threat_level = ThreatLevel(data.get('threat_level', 'LOW'))
        
        return user
    
    def __str__(self) -> str:
        """
        Return a string representation of the User object.
        
        Returns:
            Formatted string with user information
        """
        last_login = (self._last_login_time.strftime('%Y-%m-%d %H:%M:%S') 
                     if self._last_login_time else 'Never')
        
        return (
            f"User(username='{self._username}', "
            f"role={self.role.name}, "
            f"failed_attempts={self._failed_login_attempts}, "
            f"threat_level={self._threat_level.value}, "
            f"last_login={last_login})"
        )
