"""
Anomaly Detection Model for network security using Isolation Forest.

This module provides the AnomalyDetectionModel class which uses scikit-learn's
IsolationForest algorithm to detect anomalous network activity.
"""
import numpy as np
from typing import List, Union, Optional, Dict, Any
from pathlib import Path
import joblib
from sklearn.ensemble import IsolationForest

class AnomalyDetectionModel:
    """
    Anomaly detection model using Isolation Forest algorithm.
    
    This class provides methods to train, predict, save, and load an anomaly
    detection model for network security monitoring.
    """
    
    def __init__(self) -> None:
        """
        Initialize the AnomalyDetectionModel with default parameters.
        
        The model uses IsolationForest with contamination=0.05 and random_state=42
        for reproducible results.
        """
        self.model = IsolationForest(
            contamination=0.05,
            random_state=42,
            n_estimators=100,
            max_samples='auto',
            max_features=1.0,
            bootstrap=False,
            n_jobs=-1,
            verbose=0
        )
        self.is_trained: bool = False
        self.feature_names: List[str] = []
    
    def train(self, training_data: np.ndarray, feature_names: Optional[List[str]] = None) -> None:
        """
        Train the anomaly detection model on the provided training data.
        
        Args:
            training_data: 2D numpy array of shape (n_samples, n_features)
                          containing the training data
            feature_names: Optional list of feature names for better interpretability
            
        Raises:
            ValueError: If training_data is not a 2D array or has insufficient samples
        """
        if not isinstance(training_data, np.ndarray) or training_data.ndim != 2:
            raise ValueError("training_data must be a 2D numpy array")
        
        if training_data.shape[0] < 2:
            raise ValueError("Insufficient samples for training")
        
        self.model.fit(training_data)
        self.is_trained = True
        
        if feature_names is not None:
            if len(feature_names) != training_data.shape[1]:
                raise ValueError(
                    f"Number of feature names ({len(feature_names)}) "
                    f"does not match number of features ({training_data.shape[1]})"
                )
            self.feature_names = feature_names
        else:
            self.feature_names = [f"feature_{i}" for i in range(training_data.shape[1])]
    
    def predict(self, packet: Union[Dict[str, Any], np.ndarray]) -> int:
        """
        Predict whether the given packet is normal or anomalous.
        
        Args:
            packet: Either a dictionary containing packet features or a numpy array.
                   If a dictionary is provided, the values will be converted to a
                   numpy array in the order of feature_names.
                   
        Returns:
            int: 1 for normal, -1 for anomaly
            
        Raises:
            RuntimeError: If the model is not trained
            ValueError: If the input format is invalid
        """
        if not self.is_trained:
            raise RuntimeError("Model has not been trained. Call train() first.")
        
        # Convert packet to feature vector if it's a dictionary
        if isinstance(packet, dict):
            if not self.feature_names:
                raise ValueError("Feature names not set. Cannot process dictionary input.")
            try:
                features = np.array([packet[feature] for feature in self.feature_names])
            except KeyError as e:
                raise ValueError(f"Missing feature in packet: {e}") from e
            features = features.reshape(1, -1)
        elif isinstance(packet, np.ndarray):
            if packet.ndim == 1:
                features = packet.reshape(1, -1)
            elif packet.ndim == 2 and packet.shape[0] == 1:
                features = packet
            else:
                raise ValueError("Input array must be 1D or a single sample 2D array")
        else:
            raise ValueError("packet must be either a dictionary or numpy array")
        
        return int(self.model.predict(features)[0])
    
    def save_model(self, filepath: Union[str, Path]) -> None:
        """
        Save the trained model to disk using joblib.
        
        Args:
            filepath: Path where the model should be saved
            
        Raises:
            RuntimeError: If the model has not been trained
        """
        if not self.is_trained:
            raise RuntimeError("Cannot save an untrained model")
            
        model_data = {
            'model': self.model,
            'is_trained': self.is_trained,
            'feature_names': self.feature_names
        }
        
        # Create directory if it doesn't exist
        filepath = Path(filepath)
        filepath.parent.mkdir(parents=True, exist_ok=True)
        
        joblib.dump(model_data, filepath)
    
    @classmethod
    def load_model(cls, filepath: Union[str, Path]) -> 'AnomalyDetectionModel':
        """
        Load a trained model from disk.
        
        Args:
            filepath: Path to the saved model file
            
        Returns:
            AnomalyDetectionModel: The loaded model instance
            
        Raises:
            FileNotFoundError: If the model file doesn't exist
            Exception: If there's an error loading the model
        """
        try:
            model_data = joblib.load(filepath)
            
            instance = cls()
            instance.model = model_data['model']
            instance.is_trained = model_data['is_trained']
            instance.feature_names = model_data['feature_names']
            
            return instance
        except Exception as e:
            raise Exception(f"Error loading model: {str(e)}") from e
    
    def get_feature_importances(self) -> np.ndarray:
        """
        Get feature importances from the trained model.
        
        Returns:
            numpy.ndarray: Array of feature importances
            
        Raises:
            RuntimeError: If the model has not been trained
        """
        if not self.is_trained:
            raise RuntimeError("Model has not been trained")
        return self.model.feature_importances_
