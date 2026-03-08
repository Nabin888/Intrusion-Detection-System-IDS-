"""
IP Blacklist Management Interface for the IDS.
"""
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QTableWidget, QTableWidgetItem, QHeaderView, QPushButton,
                             QLineEdit, QComboBox, QFrame, QMessageBox, QDialog,
                             QDialogButtonBox, QFormLayout, QTextEdit)
from PyQt5.QtCore import QTimer, pyqtSignal, QThread, Qt
from PyQt5.QtGui import QColor, QFont
from datetime import datetime, timedelta
from typing import List, Dict, Any
from core.ids_manager import IDSManager

class BlacklistUpdateThread(QThread):
    """Background thread for monitoring blacklist activity."""
    blacklist_updated = pyqtSignal(dict)
    
    def __init__(self, ids_manager):
        super().__init__()
        self.ids_manager = ids_manager
        self.running = True
        
    def run(self):
        """Monitor blacklist activity and emit updates."""
        while self.running:
            # Get current blacklist data
            blacklisted_ips = self.ids_manager.get_blacklisted_ips()
            stats = self.ids_manager.get_stats()
            
            # Prepare blacklist data
            blacklist_data = {
                'total_blacklisted': len(blacklisted_ips),
                'blacklisted_ips': list(blacklisted_ips),
                'recent_blocks': self._get_recent_blocks(),
                'blocked_attempts': self._get_blocked_attempts(),
                'stats': stats
            }
            
            self.blacklist_updated.emit(blacklist_data)
            self.msleep(5000)  # Update every 5 seconds
    
    def _get_recent_blocks(self):
        """Get recent IP blocks (simulated)."""
        # In a real system, this would query actual block logs
        import random
        recent_blocks = []
        
        for ip in list(self.ids_manager.get_blacklisted_ips())[:5]:
            recent_blocks.append({
                'ip': ip,
                'timestamp': datetime.now() - timedelta(minutes=random.randint(1, 60)),
                'reason': random.choice(['Threat Score > 85', 'Manual Blacklist', 'Brute Force Attack', 'Malicious Activity']),
                'source': 'Automated Detection' if random.random() > 0.3 else 'Manual'
            })
        
        return recent_blocks
    
    def _get_blocked_attempts(self):
        """Get count of blocked attempts (simulated)."""
        import random
        return random.randint(10, 100)
    
    def stop(self):
        """Stop the blacklist monitoring thread."""
        self.running = False

class AddBlacklistDialog(QDialog):
    """Dialog for adding IP to blacklist."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Add IP to Blacklist")
        self.setModal(True)
        self.resize(400, 300)
        self.setup_ui()
        
    def setup_ui(self):
        """Set up the dialog UI."""
        layout = QVBoxLayout(self)
        
        # Form layout
        form_layout = QFormLayout()
        
        # IP address input
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("e.g., 192.168.1.100")
        form_layout.addRow("IP Address:", self.ip_input)
        
        # Reason dropdown
        self.reason_combo = QComboBox()
        self.reason_combo.addItems([
            "Manual Blacklist",
            "Brute Force Attack", 
            "Port Scan",
            "DDoS Attack",
            "Malware Communication",
            "Data Exfiltration",
            "Suspicious Activity",
            "Other"
        ])
        form_layout.addRow("Reason:", self.reason_combo)
        
        # Duration dropdown
        self.duration_combo = QComboBox()
        self.duration_combo.addItems([
            "Permanent",
            "1 Hour",
            "6 Hours", 
            "24 Hours",
            "7 Days",
            "30 Days"
        ])
        self.duration_combo.setCurrentText("Permanent")
        form_layout.addRow("Duration:", self.duration_combo)
        
        # Notes
        self.notes_text = QTextEdit()
        self.notes_text.setPlaceholderText("Additional notes about this blacklist entry...")
        self.notes_text.setMaximumHeight(80)
        form_layout.addRow("Notes:", self.notes_text)
        
        layout.addLayout(form_layout)
        
        # Buttons
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)
        
    def get_blacklist_data(self):
        """Get the blacklist data from the dialog."""
        return {
            'ip': self.ip_input.text().strip(),
            'reason': self.reason_combo.currentText(),
            'duration': self.duration_combo.currentText(),
            'notes': self.notes_text.toPlainText().strip()
        }

class BlacklistManager(QWidget):
    """IP Blacklist Management Interface."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.ids_manager = IDSManager()
        self.blacklist_history = []
        self.setup_ui()
        self.setup_monitoring()
        
    def setup_ui(self):
        """Set up the user interface components."""
        main_layout = QVBoxLayout(self)
        
        # Header
        header_frame = QFrame()
        header_frame.setStyleSheet("""
            QFrame {
                background-color: #f8f9fa;
                border: 1px solid #dee2e6;
                border-radius: 8px;
                padding: 15px;
            }
        """)
        
        header_layout = QHBoxLayout(header_frame)
        
        title = QLabel("IP Blacklist Manager")
        title.setStyleSheet("font-size: 20px; font-weight: bold; color: #2c3e50;")
        header_layout.addWidget(title)
        
        header_layout.addStretch()
        
        # Statistics labels
        self.total_label = QLabel("Total Blacklisted: 0")
        self.total_label.setStyleSheet("font-size: 14px; font-weight: bold; color: #6c757d;")
        header_layout.addWidget(self.total_label)
        
        self.blocked_label = QLabel("Blocked Attempts: 0")
        self.blocked_label.setStyleSheet("font-size: 14px; font-weight: bold; color: #dc3545;")
        header_layout.addWidget(self.blocked_label)
        
        main_layout.addWidget(header_frame)
        
        # Control buttons
        controls_frame = QFrame()
        controls_layout = QHBoxLayout(controls_frame)
        
        # Add IP button
        self.add_btn = QPushButton("Add IP to Blacklist")
        self.add_btn.setStyleSheet("""
            QPushButton {
                background-color: #dc3545;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #c82333;
            }
        """)
        self.add_btn.clicked.connect(self.add_ip_dialog)
        controls_layout.addWidget(self.add_btn)
        
        # Remove IP button
        self.remove_btn = QPushButton("Remove Selected")
        self.remove_btn.setStyleSheet("""
            QPushButton {
                background-color: #ffc107;
                color: #212529;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #e0a800;
            }
        """)
        self.remove_btn.clicked.connect(self.remove_selected_ip)
        controls_layout.addWidget(self.remove_btn)
        
        # Clear all button
        self.clear_btn = QPushButton("Clear All")
        self.clear_btn.setStyleSheet("""
            QPushButton {
                background-color: #6c757d;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #5a6268;
            }
        """)
        self.clear_btn.clicked.connect(self.clear_all_blacklist)
        controls_layout.addWidget(self.clear_btn)
        
        controls_layout.addStretch()
        
        # Search box
        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("Search IPs...")
        self.search_box.setStyleSheet("""
            QLineEdit {
                padding: 5px;
                border: 1px solid #ced4da;
                border-radius: 4px;
                background-color: white;
                min-width: 200px;
            }
        """)
        self.search_box.textChanged.connect(self.filter_blacklist)
        controls_layout.addWidget(self.search_box)
        
        main_layout.addWidget(controls_frame)
        
        # Blacklist table
        self.blacklist_table = QTableWidget()
        self.blacklist_table.setColumnCount(5)
        self.blacklist_table.setHorizontalHeaderLabels([
            "IP Address", "Added On", "Reason", "Duration", "Status"
        ])
        
        # Configure table
        self.blacklist_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.blacklist_table.verticalHeader().setVisible(False)
        self.blacklist_table.setAlternatingRowColors(True)
        self.blacklist_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.blacklist_table.setStyleSheet("""
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
        
        main_layout.addWidget(self.blacklist_table)
        
        # Recent activity frame
        activity_frame = QFrame()
        activity_frame.setStyleSheet("""
            QFrame {
                background-color: white;
                border: 1px solid #dee2e6;
                border-radius: 4px;
                padding: 10px;
            }
        """)
        
        activity_layout = QVBoxLayout(activity_frame)
        
        activity_title = QLabel("Recent Blacklist Activity")
        activity_title.setStyleSheet("font-size: 16px; font-weight: bold; color: #2c3e50;")
        activity_layout.addWidget(activity_title)
        
        self.activity_text = QTextEdit()
        self.activity_text.setReadOnly(True)
        self.activity_text.setMaximumHeight(120)
        activity_layout.addWidget(self.activity_text)
        
        main_layout.addWidget(activity_frame)
        
    def setup_monitoring(self):
        """Set up the blacklist monitoring thread."""
        self.blacklist_thread = BlacklistUpdateThread(self.ids_manager)
        self.blacklist_thread.blacklist_updated.connect(self.update_blacklist_display)
        self.blacklist_thread.start()
        
    def add_ip_dialog(self):
        """Show dialog to add IP to blacklist."""
        dialog = AddBlacklistDialog(self)
        if dialog.exec_() == QDialog.Accepted:
            data = dialog.get_blacklist_data()
            if data['ip']:
                self.add_ip_to_blacklist(data)
            else:
                QMessageBox.warning(self, "Invalid Input", "Please enter a valid IP address.")
                
    def add_ip_to_blacklist(self, data):
        """Add IP to blacklist."""
        try:
            ip = data['ip']
            success = self.ids_manager.blacklist_ip(ip)
            
            if success:
                # Add to history
                self.blacklist_history.append({
                    'ip': ip,
                    'added_on': datetime.now(),
                    'reason': data['reason'],
                    'duration': data['duration'],
                    'notes': data['notes']
                })
                
                QMessageBox.information(self, "Success", f"IP {ip} has been added to the blacklist.")
                self.update_blacklist_display({})
            else:
                QMessageBox.warning(self, "Already Blacklisted", f"IP {ip} is already in the blacklist.")
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to add IP to blacklist: {str(e)}")
            
    def remove_selected_ip(self):
        """Remove selected IP from blacklist."""
        current_row = self.blacklist_table.currentRow()
        if current_row >= 0:
            ip_item = self.blacklist_table.item(current_row, 0)
            if ip_item:
                ip = ip_item.text()
                reply = QMessageBox.question(self, 'Confirm Removal', 
                                         f'Are you sure you want to remove {ip} from the blacklist?',
                                         QMessageBox.Yes | QMessageBox.No)
                
                if reply == QMessageBox.Yes:
                    success = self.ids_manager.remove_from_blacklist(ip)
                    if success:
                        QMessageBox.information(self, "Success", f"IP {ip} has been removed from the blacklist.")
                        self.update_blacklist_display({})
                    else:
                        QMessageBox.warning(self, "Error", f"Failed to remove IP {ip} from blacklist.")
        else:
            QMessageBox.information(self, "No Selection", "Please select an IP address to remove.")
            
    def clear_all_blacklist(self):
        """Clear all IPs from blacklist."""
        reply = QMessageBox.question(self, 'Confirm Clear All', 
                                 'Are you sure you want to clear all IPs from the blacklist?',
                                 QMessageBox.Yes | QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            try:
                # Get all blacklisted IPs and remove them
                blacklisted_ips = self.ids_manager.get_blacklisted_ips().copy()
                for ip in blacklisted_ips:
                    self.ids_manager.remove_from_blacklist(ip)
                
                self.blacklist_history.clear()
                QMessageBox.information(self, "Success", "All IPs have been removed from the blacklist.")
                self.update_blacklist_display({})
                
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to clear blacklist: {str(e)}")
                
    def filter_blacklist(self):
        """Filter blacklist based on search text."""
        search_text = self.search_box.text().lower()
        
        for row in range(self.blacklist_table.rowCount()):
            show_row = True
            
            if search_text:
                ip_item = self.blacklist_table.item(row, 0)
                if ip_item and search_text not in ip_item.text().lower():
                    show_row = False
            
            self.blacklist_table.setRowHidden(row, not show_row)
            
    def update_blacklist_display(self, data):
        """Update the blacklist display with current data."""
        try:
            blacklisted_ips = self.ids_manager.get_blacklisted_ips()
            
            # Update statistics
            self.total_label.setText(f"Total Blacklisted: {len(blacklisted_ips)}")
            self.blocked_label.setText(f"Blocked Attempts: {data.get('blocked_attempts', 0)}")
            
            # Update table
            self.blacklist_table.setRowCount(len(blacklisted_ips))
            
            for i, ip in enumerate(blacklisted_ips):
                # IP Address
                self.blacklist_table.setItem(i, 0, QTableWidgetItem(ip))
                
                # Added On (get from history or use current time)
                added_on = "Unknown"
                for entry in self.blacklist_history:
                    if entry['ip'] == ip:
                        added_on = entry['added_on'].strftime('%Y-%m-%d %H:%M:%S')
                        break
                self.blacklist_table.setItem(i, 1, QTableWidgetItem(added_on))
                
                # Reason (get from history)
                reason = "Manual"
                for entry in self.blacklist_history:
                    if entry['ip'] == ip:
                        reason = entry['reason']
                        break
                self.blacklist_table.setItem(i, 2, QTableWidgetItem(reason))
                
                # Duration
                duration = "Permanent"
                for entry in self.blacklist_history:
                    if entry['ip'] == ip:
                        duration = entry['duration']
                        break
                self.blacklist_table.setItem(i, 3, QTableWidgetItem(duration))
                
                # Status
                status_item = QTableWidgetItem("Active")
                status_item.setBackground(QColor('#f8d7da'))
                status_item.setForeground(QColor('#721c24'))
                status_item.setTextAlignment(Qt.AlignCenter)
                self.blacklist_table.setItem(i, 4, status_item)
            
            # Update recent activity
            recent_blocks = data.get('recent_blocks', [])
            activity_text = "Recent Blacklist Activity:\n"
            activity_text += "-" * 40 + "\n"
            
            for block in recent_blocks[:5]:  # Show last 5
                activity_text += f"{block['timestamp'].strftime('%H:%M:%S')} - {block['ip']}\n"
                activity_text += f"  Reason: {block['reason']}\n"
                activity_text += f"  Source: {block['source']}\n\n"
            
            if not recent_blocks:
                activity_text += "No recent blacklist activity."
                
            self.activity_text.setPlainText(activity_text)
            
        except Exception as e:
            print(f"Error updating blacklist display: {e}")
            
    def closeEvent(self, event):
        """Clean up when closing the blacklist manager."""
        if hasattr(self, 'blacklist_thread'):
            self.blacklist_thread.stop()
            self.blacklist_thread.wait()
        event.accept()
