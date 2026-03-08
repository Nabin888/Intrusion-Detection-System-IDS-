"""
Model Trainer for Anomaly Detection in Network Security.

This module provides the ModelTrainer class which handles the training pipeline
for the anomaly detection model using simulated network traffic data.
"""
import numpy as np
from typing import List, Dict, Any, Optional
from pathlib import Path
import random
from datetime import datetime, timedelta

# Import local modules
from .model import AnomalyDetectionModel
from ..core.packet import Packet, ActivityType

class Simulator:
    """
    Simple simulator to generate network traffic data for training.
    
    This is a placeholder implementation. In a real-world scenario, this would be
    replaced with actual network traffic simulation or real network data.
    """
    
    @staticmethod
    def generate_packets(num_samples: int = 1000) -> List[Packet]:
        """
        Generate simulated network packets for training.
        
        Args:
            num_samples: Number of packets to generate
            
        Returns:
            List[Packet]: List of generated Packet objects
        """
        packets = []
        activity_types = list(ActivityType)
        
        for _ in range(num_samples):
            # Generate random IP
            ip = f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"
            
            # Randomly select activity type with higher probability for normal activity
            activity_type = np.random.choice(
                activity_types,
                p=[0.7, 0.1, 0.1, 0.1]  # 70% normal, 10% for each other type
            )
            
            # Create packet with random data
            packet = Packet(
                ip_address=ip,
                username=f"user{random.randint(1, 100)}",
                timestamp=datetime.now() - timedelta(minutes=random.randint(0, 10080)),  # Up to 1 week old
                activity_type=activity_type,
                threat_score=random.uniform(0, 100)
            )
            packets.append(packet)
            
        return packets


class ModelTrainer:
    """
    Handles the training pipeline for the anomaly detection model.
    
    This class is responsible for generating training data, extracting features,
    training the model, and saving the trained model.
    """
    
    def __init__(self) -> None:
        """Initialize the ModelTrainer with a new AnomalyDetectionModel instance."""
        self.model = AnomalyDetectionModel()
        self.training_data: Optional[np.ndarray] = None
        self.labels: Optional[np.ndarray] = None
    
    def _extract_features(self, packets: List[Packet]) -> np.ndarray:
        """
        Extract features from Packet objects for model training.
        
        Args:
            packets: List of Packet objects
            
        Returns:
            numpy.ndarray: Feature matrix of shape (n_samples, n_features)
        """
        features = []
        
        for packet in packets:
            # Encode activity type as integer
            activity_encoded = {
                ActivityType.NORMAL: 0,
                ActivityType.LOGIN_FAILED: 1,
                ActivityType.SUSPICIOUS: 2,
                ActivityType.BLACKLISTED: 3
            }.get(packet.activity_type, 0)
            
            # Create feature vector for this packet
            feature_vector = [
                packet.threat_score,
                activity_encoded,
                # Add more features here as needed
            ]
            
            features.append(feature_vector)
        
        return np.array(features)
    
    def generate_training_data(self, num_samples: int = 1000) -> np.ndarray:
        """
        Generate and prepare training data for the model.
        
        Args:
            num_samples: Number of samples to generate
            
        Returns:
            numpy.ndarray: Feature matrix of shape (n_samples, n_features)
        """
        # Generate simulated packets
        packets = Simulator.generate_packets(num_samples)
        
        # Extract features from packets
        self.training_data = self._extract_features(packets)
        
        # In a real scenario, we would have labeled data or use unsupervised learning
        # For this example, we'll assume all data is normal (1) for training
        self.labels = np.ones(len(packets))
        
        # Add some anomalies (5% of data)
        num_anomalies = int(0.05 * len(self.labels))
        if num_anomalies > 0:
            self.labels[-num_anomalies:] = -1  # Mark as anomalies
            
            # Make anomaly features more extreme
            for i in range(-num_anomalies, 0):
                self.training_data[i, 0] *= 2  # Higher threat score
                self.training_data[i, 1] = 2  # Mark as suspicious activity
        
        return self.training_data
    
    def train_model(self, num_samples: int = 1000) -> None:
        """
        Train the anomaly detection model using generated data.
        
        Args:
            num_samples: Number of training samples to generate
            
        Raises:
            RuntimeError: If training data generation fails
        """
        # Generate training data if not already done
        if self.training_data is None:
            self.generate_training_data(num_samples)
        
        if self.training_data is None or len(self.training_data) == 0:
            raise RuntimeError("Failed to generate training data")
        
        # Define feature names for better model interpretability
        feature_names = [
            'threat_score',
            'activity_type_encoded',
            # Add more feature names as needed
        ]
        
        # Train the model
        self.model.train(
            training_data=self.training_data,
            feature_names=feature_names
        )
    
    def save_model(self, filepath: str) -> None:
        """
        Save the trained model to disk.
        
        Args:
            filepath: Path where the model should be saved
            
        Raises:
            RuntimeError: If the model has not been trained
        """
        if not self.model.is_trained:
            raise RuntimeError("Model has not been trained. Call train_model() first.")
        
        self.model.save_model(filepath)
        print(f"Model saved successfully to {filepath}")
    
    def evaluate_model(self, test_data: Optional[np.ndarray] = None) -> Dict[str, float]:
        """
        Evaluate the trained model on test data.
        
        Args:
            test_data: Optional test data to evaluate on. If None, uses training data.
            
        Returns:
            Dict containing evaluation metrics
            
        Raises:
            RuntimeError: If the model has not been trained
        """
        if not self.model.is_trained:
            raise RuntimeError("Model has not been trained. Call train_model() first.")
        
        if test_data is None:
            if self.training_data is None:
                raise ValueError("No test data provided and no training data available")
            test_data = self.training_data
        
        # Make predictions
        predictions = np.array([self.model.predict(x) for x in test_data])
        
        # Calculate metrics (simplified for demonstration)
        # In a real scenario, you would use actual labels and calculate metrics like precision, recall, etc.
        num_samples = len(test_data)
        num_anomalies = np.sum(predictions == -1)
        anomaly_ratio = num_anomalies / num_samples if num_samples > 0 else 0.0
        
        return {
            'num_samples': num_samples,
            'num_anomalies_detected': int(num_anomalies),
            'anomaly_ratio': float(anomaly_ratio)
        }
