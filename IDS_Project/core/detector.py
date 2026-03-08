""
Base detector class for intrusion detection.
"""
from abc import ABC, abstractmethod
from typing import List, Dict, Any
from datetime import datetime

from .packet import Packet

class Detector(ABC):
    """Abstract base class for all intrusion detection modules."""
    
    def __init__(self, name: str, description: str = ""):
        """Initialize the detector with a name and description."""
        self.name = name
        self.description = description
        self.enabled = True
        self.threshold = 0.7  # Default threshold for threat level
        self.last_updated = datetime.now()
    
    @abstractmethod
    def analyze(self, packet: Packet) -> Dict[str, Any]:
        """
        Analyze a network packet for potential threats.
        
        Args:
            packet: The network packet to analyze
            
        Returns:
            Dict containing analysis results including 'threat_level' (float 0-1)
            and 'details' (dict with specific findings)
        """
        pass
    
    def update_threshold(self, new_threshold: float) -> None:
        """Update the detection threshold."""
        if 0 <= new_threshold <= 1:
            self.threshold = new_threshold
            self.last_updated = datetime.now()
    
    def enable(self) -> None:
        """Enable the detector."""
        self.enabled = True
    
    def disable(self) -> None:
        """Disable the detector."""
        self.enabled = False
    
    def get_status(self) -> Dict[str, Any]:
        """Get the current status of the detector."""
        return {
            'name': self.name,
            'description': self.description,
            'enabled': self.enabled,
            'threshold': self.threshold,
            'last_updated': self.last_updated.isoformat()
        }
