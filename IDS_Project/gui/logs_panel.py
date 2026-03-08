"""
Logs panel showing system and security logs.
"""
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QTextEdit, QHBoxLayout, QPushButton
from PyQt5.QtCore import Qt

class LogsPanel(QWidget):
    """Panel for displaying system and security logs."""
    
    def __init__(self, parent=None):
        """Initialize the logs panel with a text area and controls."""
        super().__init__(parent)
        self.setup_ui()
    
    def setup_ui(self):
        """Set up the user interface components."""
        layout = QVBoxLayout(self)
        
        # Create controls
        controls = QHBoxLayout()
        
        self.refresh_btn = QPushButton("Refresh")
        self.clear_btn = QPushButton("Clear")
        
        controls.addWidget(self.refresh_btn)
        controls.addStretch()
        controls.addWidget(self.clear_btn)
        
        # Create log display
        self.log_display = QTextEdit()
        self.log_display.setReadOnly(True)
        self.log_display.setLineWrapMode(QTextEdit.NoWrap)
        
        # Add widgets to layout
        layout.addLayout(controls)
        layout.addWidget(self.log_display)
        
        # Connect signals
        self.refresh_btn.clicked.connect(self.refresh_logs)
        self.clear_btn.clicked.connect(self.clear_logs)
        
        # Load initial logs
        self.refresh_logs()
    
    def refresh_logs(self):
        """Refresh the log display with current logs."""
        # In a real application, this would read from a log file or database
        sample_logs = """[2023-01-01 10:00:00] INFO: System initialized
[2023-01-01 10:01:15] WARNING: Unusual network activity detected
[2023-01-01 10:02:30] INFO: Security scan completed
[2023-01-01 10:03:45] ERROR: Failed to connect to update server
"""
        self.log_display.setPlainText(sample_logs)
        
        # Auto-scroll to bottom
        self.log_display.verticalScrollBar().setValue(
            self.log_display.verticalScrollBar().maximum()
        )
    
    def clear_logs(self):
        """Clear the log display."""
        self.log_display.clear()
