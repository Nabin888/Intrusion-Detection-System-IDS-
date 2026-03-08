"""
Alerts panel showing real-time security alerts and notifications with filtering.
"""
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, 
                             QTableWidgetItem, QHeaderView, QLabel, QPushButton, 
                             QComboBox, QLineEdit, QFrame, QSplitter)
from PyQt5.QtCore import QTimer, pyqtSignal, QThread, Qt
from PyQt5.QtGui import QColor, QFont
from datetime import datetime
from typing import List, Dict, Any
from core.ids_manager import IDSManager

class AlertUpdateThread(QThread):
    """Background thread for monitoring and generating alerts."""
    alert_received = pyqtSignal(dict)
    
    def __init__(self, ids_manager):
        super().__init__()
        self.ids_manager = ids_manager
        self.running = True
        self.last_alert_count = 0
        
    def run(self):
        """Monitor IDS for new threats and generate alerts."""
        while self.running:
            # Process packets from queue
            alerts_generated = 0
            for _ in range(min(10, self.ids_manager.packet_queue.qsize())):
                result = self.ids_manager.process_packet()
                
                if result['threat_detected'] and result['status'] == 'processed':
                    packet = result['packet']
                    user = result.get('user')
                    
                    # Determine alert severity based on threat score
                    if packet.threat_score > 80:
                        severity = "CRITICAL"
                        alert_type = "Critical Threat"
                    elif packet.threat_score > 60:
                        severity = "HIGH"
                        alert_type = "High Threat"
                    elif packet.threat_score > 40:
                        severity = "MEDIUM"
                        alert_type = "Suspicious Activity"
                    else:
                        severity = "LOW"
                        alert_type = "Anomaly Detected"
                    
                    # Create alert
                    alert = {
                        'timestamp': datetime.now(),
                        'severity': severity,
                        'source_ip': packet.ip_address,
                        'username': packet.username,
                        'activity': packet.activity_type.value,
                        'threat_score': packet.threat_score,
                        'description': f"{alert_type}: {packet.activity_type.value} from {packet.ip_address}",
                        'port': packet.port,
                        'protocol': packet.protocol
                    }
                    
                    # Auto-blacklist high threat IPs
                    if packet.threat_score > 85:
                        self.ids_manager.blacklist_ip(packet.ip_address)
                        alert['description'] += " [IP AUTO-BLACKLISTED]"
                    
                    self.alert_received.emit(alert)
                    alerts_generated += 1
            
            # Check for blacklisted IP activity
            blacklisted_ips = self.ids_manager.get_blacklisted_ips()
            for ip in blacklisted_ips:
                # Simulate detection of blacklisted IP activity
                if alerts_generated > 0:  # Only if there's recent activity
                    alert = {
                        'timestamp': datetime.now(),
                        'severity': "CRITICAL",
                        'source_ip': ip,
                        'username': "unknown",
                        'activity': "BLACKLISTED_IP_ACCESS",
                        'threat_score': 100,
                        'description': f"Blacklisted IP {ip} attempted network access",
                        'port': 0,
                        'protocol': "ANY"
                    }
                    self.alert_received.emit(alert)
            
            self.msleep(3000)  # Check every 3 seconds
    
    def stop(self):
        """Stop the alert monitoring thread."""
        self.running = False

class AlertsPanel(QWidget):
    """Advanced panel for displaying real-time security alerts with filtering."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.ids_manager = IDSManager()
        self.alerts = []
        self.setup_ui()
        self.setup_monitoring()
        
    def setup_ui(self):
        """Set up the user interface components."""
        main_layout = QVBoxLayout(self)
        
        # Header with title and controls
        header_frame = QFrame()
        header_frame.setFrameStyle(QFrame.Box)
        header_frame.setStyleSheet("""
            QFrame {
                background-color: #f8f9fa;
                border: 1px solid #dee2e6;
                border-radius: 8px;
                padding: 10px;
            }
        """)
        
        header_layout = QHBoxLayout(header_frame)
        
        title = QLabel("Security Alerts")
        title.setStyleSheet("font-size: 20px; font-weight: bold; color: #2c3e50;")
        header_layout.addWidget(title)
        
        # Alert counter
        self.alert_counter = QLabel("Total Alerts: 0")
        self.alert_counter.setStyleSheet("font-size: 14px; color: #6c757d; font-weight: bold;")
        header_layout.addWidget(self.alert_counter)
        
        header_layout.addStretch()
        
        # Filter controls
        self.severity_filter = QComboBox()
        self.severity_filter.addItems(["All Severities", "CRITICAL", "HIGH", "MEDIUM", "LOW"])
        self.severity_filter.setStyleSheet("""
            QComboBox {
                padding: 5px;
                border: 1px solid #ced4da;
                border-radius: 4px;
                background-color: white;
            }
        """)
        self.severity_filter.currentTextChanged.connect(self.filter_alerts)
        header_layout.addWidget(QLabel("Severity:"))
        header_layout.addWidget(self.severity_filter)
        
        # Search box
        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("Search alerts...")
        self.search_box.setStyleSheet("""
            QLineEdit {
                padding: 5px;
                border: 1px solid #ced4da;
                border-radius: 4px;
                background-color: white;
            }
        """)
        self.search_box.textChanged.connect(self.filter_alerts)
        header_layout.addWidget(self.search_box)
        
        # Clear button
        self.clear_btn = QPushButton("Clear All")
        self.clear_btn.setStyleSheet("""
            QPushButton {
                background-color: #dc3545;
                color: white;
                border: none;
                padding: 5px 15px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #c82333;
            }
        """)
        self.clear_btn.clicked.connect(self.clear_alerts)
        header_layout.addWidget(self.clear_btn)
        
        main_layout.addWidget(header_frame)
        
        # Alerts table
        self.alerts_table = QTableWidget()
        self.alerts_table.setColumnCount(6)
        self.alerts_table.setHorizontalHeaderLabels([
            "Time", "Severity", "Source IP", "User", "Activity", "Description"
        ])
        
        # Configure table properties
        self.alerts_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.alerts_table.verticalHeader().setVisible(False)
        self.alerts_table.setAlternatingRowColors(True)
        self.alerts_table.setStyleSheet("""
            QTableWidget {
                gridline-color: #dee2e6;
                background-color: white;
                alternate-background-color: #f8f9fa;
            }
            QTableWidget::item {
                padding: 5px;
                border-bottom: 1px solid #dee2e6;
            }
        """)
        
        main_layout.addWidget(self.alerts_table)
        
        # Status bar
        status_frame = QFrame()
        status_frame.setStyleSheet("""
            QFrame {
                background-color: #e9ecef;
                border: 1px solid #dee2e6;
                border-radius: 4px;
                padding: 5px;
            }
        """)
        
        status_layout = QHBoxLayout(status_frame)
        self.status_label = QLabel("Monitoring active...")
        self.status_label.setStyleSheet("color: #28a745; font-weight: bold;")
        status_layout.addWidget(self.status_label)
        status_layout.addStretch()
        
        main_layout.addWidget(status_frame)
        
    def setup_monitoring(self):
        """Set up the alert monitoring thread."""
        self.alert_thread = AlertUpdateThread(self.ids_manager)
        self.alert_thread.alert_received.connect(self.add_alert)
        self.alert_thread.start()
        
    def add_alert(self, alert: Dict[str, Any]):
        """Add a new alert to the table."""
        self.alerts.append(alert)
        
        # Insert at the top (most recent first)
        row = 0
        self.alerts_table.insertRow(row)
        
        # Format timestamp
        time_str = alert['timestamp'].strftime('%H:%M:%S')
        
        # Add items to table
        self.alerts_table.setItem(row, 0, QTableWidgetItem(time_str))
        
        # Severity with color coding
        severity_item = QTableWidgetItem(alert['severity'])
        severity_item.setTextAlignment(Qt.AlignCenter)
        if alert['severity'] == 'CRITICAL':
            severity_item.setBackground(QColor('#f8d7da'))
            severity_item.setForeground(QColor('#721c24'))
        elif alert['severity'] == 'HIGH':
            severity_item.setBackground(QColor('#fff3cd'))
            severity_item.setForeground(QColor('#856404'))
        elif alert['severity'] == 'MEDIUM':
            severity_item.setBackground(QColor('#fff3cd'))
            severity_item.setForeground(QColor('#856404'))
        else:  # LOW
            severity_item.setBackground(QColor('#d4edda'))
            severity_item.setForeground(QColor('#155724'))
        
        self.alerts_table.setItem(row, 1, severity_item)
        self.alerts_table.setItem(row, 2, QTableWidgetItem(alert['source_ip']))
        self.alerts_table.setItem(row, 3, QTableWidgetItem(alert['username']))
        self.alerts_table.setItem(row, 4, QTableWidgetItem(alert['activity']))
        self.alerts_table.setItem(row, 5, QTableWidgetItem(alert['description']))
        
        # Update counter
        self.update_alert_counter()
        
        # Auto-scroll to top
        self.alerts_table.scrollToTop()
        
        # Limit to last 100 alerts for performance
        if self.alerts_table.rowCount() > 100:
            self.alerts_table.removeRow(100)
            self.alerts.pop(100)
    
    def filter_alerts(self):
        """Filter alerts based on severity and search text."""
        severity_filter = self.severity_filter.currentText()
        search_text = self.search_box.text().lower()
        
        for row in range(self.alerts_table.rowCount()):
            show_row = True
            
            # Severity filter
            if severity_filter != "All Severities":
                severity_item = self.alerts_table.item(row, 1)
                if severity_item and severity_item.text() != severity_filter:
                    show_row = False
            
            # Search filter
            if search_text:
                row_text = ""
                for col in range(self.alerts_table.columnCount()):
                    item = self.alerts_table.item(row, col)
                    if item:
                        row_text += item.text().lower() + " "
                
                if search_text not in row_text:
                    show_row = False
            
            self.alerts_table.setRowHidden(row, not show_row)
    
    def clear_alerts(self):
        """Clear all alerts from the table."""
        self.alerts_table.setRowCount(0)
        self.alerts.clear()
        self.update_alert_counter()
    
    def update_alert_counter(self):
        """Update the alert counter display."""
        total = len(self.alerts)
        critical = len([a for a in self.alerts if a['severity'] == 'CRITICAL'])
        high = len([a for a in self.alerts if a['severity'] == 'HIGH'])
        
        counter_text = f"Total: {total}"
        if critical > 0:
            counter_text += f" | Critical: {critical}"
        if high > 0:
            counter_text += f" | High: {high}"
            
        self.alert_counter.setText(counter_text)
        
        # Update status based on critical alerts
        if critical > 0:
            self.status_label.setText(f"CRITICAL: {critical} critical alerts detected!")
            self.status_label.setStyleSheet("color: #dc3545; font-weight: bold;")
        elif high > 0:
            self.status_label.setText(f"WARNING: {high} high-priority alerts")
            self.status_label.setStyleSheet("color: #fd7e14; font-weight: bold;")
        else:
            self.status_label.setText("Monitoring active - No critical threats")
            self.status_label.setStyleSheet("color: #28a745; font-weight: bold;")
    
    def closeEvent(self, event):
        """Clean up when closing the alerts panel."""
        if hasattr(self, 'alert_thread'):
            self.alert_thread.stop()
            self.alert_thread.wait()
        event.accept()
