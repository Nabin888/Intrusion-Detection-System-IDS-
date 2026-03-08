"""
Threat Calculator module for evaluating and classifying security threats.

This module provides the ThreatCalculator class which calculates threat scores
based on packet activities and classifies them into appropriate threat levels.
"""
from typing import Dict, Tuple, Literal
from dataclasses import dataclass
from .packet import Packet, ActivityType

# Type alias for threat level classification
ThreatLevel = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]

@dataclass
class ThreatAssessment:
    """Data class to hold threat assessment results."""
    score: int
    threat_level: ThreatLevel

class ThreatCalculator:
    """
    A class to calculate and classify threat levels based on packet activities.
    
    This class provides methods to evaluate network packets, calculate threat scores,
    and classify them into different threat levels based on predefined rules.
    """
    
    def __init__(self) -> None:
        """
        Initialize the ThreatCalculator with default scoring rules.
        
        The scoring rules define how different activities contribute to the threat score.
        """
        self.score_rules: Dict[str, int] = {
            "login_failed": 40,
            "suspicious_activity": 60,
            "normal_activity": 5,
            "blacklisted_ip": 100
        }
    
    def calculate_score(self, packet: Packet, is_blacklisted: bool = False) -> int:
        """
        Calculate the threat score for a given packet.
        
        Args:
            packet: The Packet object to evaluate
            is_blacklisted: Whether the packet's IP is blacklisted
            
        Returns:
            int: The calculated threat score
        """
        score = 0
        
        # Map ActivityType to score rule keys
        activity_mapping = {
            ActivityType.LOGIN_FAILED: "login_failed",
            ActivityType.SUSPICIOUS: "suspicious_activity",
            ActivityType.NORMAL: "normal_activity"
        }
        
        # Add base score based on activity type
        activity_key = activity_mapping.get(packet.activity_type, "normal_activity")
        score += self.score_rules.get(activity_key, 0)
        
        # Add additional score for blacklisted IPs
        if is_blacklisted:
            score += self.score_rules["blacklisted_ip"]
        
        return score
    
    def classify_threat(self, score: int) -> ThreatLevel:
        """
        Classify a threat score into a threat level category.
        
        Args:
            score: The threat score to classify
            
        Returns:
            ThreatLevel: The classified threat level (LOW, MEDIUM, HIGH, or CRITICAL)
        """
        if score > 80:
            return "CRITICAL"
        elif score > 50:
            return "HIGH"
        elif score > 20:
            return "MEDIUM"
        else:
            return "LOW"
    
    def evaluate(self, packet: Packet, is_blacklisted: bool = False) -> ThreatAssessment:
        """
        Evaluate a packet and return both score and threat level.
        
        This is a convenience method that combines calculate_score and classify_threat.
        
        Args:
            packet: The Packet object to evaluate
            is_blacklisted: Whether the packet's IP is blacklisted
            
        Returns:
            ThreatAssessment: A named tuple containing score and threat_level
        """
        score = self.calculate_score(packet, is_blacklisted)
        threat_level = self.classify_threat(score)
        return ThreatAssessment(score=score, threat_level=threat_level)