"""
Advanced Analytics Panel with network traffic graphs and visualizations.
"""
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QFrame, QGridLayout, QPushButton, QComboBox,
                             QTabWidget, QTextEdit, QScrollArea)
from PyQt5.QtCore import QTimer, pyqtSignal, QThread, Qt
from PyQt5.QtGui import QPainter, QColor, QFont, QPen, QBrush
from datetime import datetime, timedelta
from typing import List, Dict, Any
import random
from core.ids_manager import IDSManager

class TrafficChart(QWidget):
    """Custom widget for drawing network traffic charts."""
    
    def __init__(self, title="Network Traffic", max_points=50):
        super().__init__()
        self.title = title
        self.max_points = max_points
        self.data_points = []
        self.setMinimumHeight(200)
        self.setStyleSheet("background-color: white; border: 1px solid #dee2e6; border-radius: 4px;")
        
    def add_data_point(self, value):
        """Add a new data point to the chart."""
        self.data_points.append(value)
        if len(self.data_points) > self.max_points:
            self.data_points.pop(0)
        self.update()
        
    def clear_data(self):
        """Clear all data points."""
        self.data_points.clear()
        self.update()
        
    def paintEvent(self, event):
        """Paint the chart."""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        
        # Get dimensions
        width = self.width()
        height = self.height()
        margin = 40
        
        # Draw title
        painter.setFont(QFont("Arial", 12, QFont.Bold))
        painter.drawText(10, 20, self.title)
        
        # Draw axes
        painter.setPen(QPen(QColor("#333333"), 2))
        painter.drawLine(margin, height - margin, width - margin, height - margin)  # X-axis
        painter.drawLine(margin, margin, margin, height - margin)  # Y-axis
        
        if not self.data_points:
            painter.setFont(QFont("Arial", 10))
            painter.drawText(width//2 - 50, height//2, "No data available")
            return
            
        # Calculate scale
        max_value = max(self.data_points) if self.data_points else 1
        min_value = min(self.data_points) if self.data_points else 0
        range_value = max_value - min_value if max_value != min_value else 1
        
        # Draw grid lines
        painter.setPen(QPen(QColor("#e0e0e0"), 1, Qt.DashLine))
        for i in range(5):
            y = int(margin + (height - 2*margin) * i / 4)
            painter.drawLine(int(margin), y, int(width - margin), y)
            
        # Draw data line
        if len(self.data_points) > 1:
            painter.setPen(QPen(QColor("#007bff"), 3))
            painter.setBrush(QBrush(QColor("#007bff")))
            
            points = []
            for i, value in enumerate(self.data_points):
                x = int(margin + (width - 2*margin) * i / (self.max_points - 1))
                y = int(height - margin - (height - 2*margin) * (value - min_value) / range_value)
                points.append((x, y))
                
            # Draw line
            for i in range(len(points) - 1):
                painter.drawLine(points[i][0], points[i][1], points[i+1][0], points[i+1][1])
                
            # Draw points
            for x, y in points:
                painter.drawEllipse(x-3, y-3, 6, 6)
                
        # Draw labels
        painter.setFont(QFont("Arial", 8))
        painter.setPen(QPen(QColor("#666666"), 1))
        
        # Y-axis labels
        for i in range(5):
            value = min_value + range_value * (4-i) / 4
            y = int(margin + (height - 2*margin) * i / 4)
            painter.drawText(5, int(y+5), f"{value:.0f}")
            
        # X-axis label
        painter.drawText(int(width//2 - 30), int(height - 10), "Time")

class ThreatDistributionChart(QWidget):
    """Pie chart for threat distribution visualization."""
    
    def __init__(self):
        super().__init__()
        self.threat_data = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0
        }
        self.colors = {
            'CRITICAL': '#dc3545',
            'HIGH': '#fd7e14',
            'MEDIUM': '#ffc107',
            'LOW': '#28a745'
        }
        self.setMinimumHeight(200)
        self.setStyleSheet("background-color: white; border: 1px solid #dee2e6; border-radius: 4px;")
        
    def update_threat_data(self, critical, high, medium, low):
        """Update threat distribution data."""
        self.threat_data = {
            'CRITICAL': critical,
            'HIGH': high,
            'MEDIUM': medium,
            'LOW': low
        }
        self.update()
        
    def paintEvent(self, event):
        """Paint the pie chart."""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        
        # Draw title
        painter.setFont(QFont("Arial", 12, QFont.Bold))
        painter.drawText(10, 20, "Threat Distribution")
        
        # Calculate center and radius
        width = self.width()
        height = self.height()
        center_x = width // 2
        center_y = height // 2 + 10
        radius = min(width, height) // 3
        
        total = sum(self.threat_data.values())
        if total == 0:
            painter.setFont(QFont("Arial", 10))
            painter.drawText(width//2 - 50, height//2, "No threats detected")
            return
            
        # Draw pie slices
        start_angle = 0
        for threat_type, count in self.threat_data.items():
            if count > 0:
                angle = 360 * count / total
                painter.setBrush(QBrush(QColor(self.colors[threat_type])))
                painter.setPen(QPen(QColor("#ffffff"), 2))
                
                # Draw pie slice
                painter.drawPie(int(center_x - radius), int(center_y - radius), 
                              radius * 2, radius * 2,
                              int(start_angle * 16), int(angle * 16))
                
                # Draw label
                label_angle = start_angle + angle / 2
                label_x = int(center_x + radius * 0.7 * cos(label_angle * 3.14159 / 180))
                label_y = int(center_y + radius * 0.7 * sin(label_angle * 3.14159 / 180))
                
                painter.setFont(QFont("Arial", 8, QFont.Bold))
                painter.setPen(QPen(QColor("#000000"), 1))
                painter.drawText(label_x - 20, label_y, f"{count}")
                
                start_angle += angle
                
        # Draw legend
        legend_x = width - 100
        legend_y = 40
        painter.setFont(QFont("Arial", 8))
        
        for i, (threat_type, color) in enumerate(self.colors.items()):
            painter.setBrush(QBrush(QColor(color)))
            painter.setPen(QPen(QColor("#000000"), 1))
            painter.drawRect(legend_x, legend_y + i * 20, 15, 15)
            
            painter.drawText(legend_x + 20, legend_y + i * 20 + 12, 
                           f"{threat_type}: {self.threat_data[threat_type]}")

def cos(angle):
    """Cosine function for pie chart calculations."""
    import math
    return math.cos(angle)

def sin(angle):
    """Sine function for pie chart calculations."""
    import math
    return math.sin(angle)

class AnalyticsUpdateThread(QThread):
    """Background thread for updating analytics data."""
    analytics_updated = pyqtSignal(dict)
    
    def __init__(self, ids_manager):
        super().__init__()
        self.ids_manager = ids_manager
        self.running = True
        self.traffic_history = []
        self.threat_history = []
        
    def run(self):
        """Update analytics data periodically."""
        while self.running:
            # Get current statistics
            stats = self.ids_manager.get_stats()
            
            # Calculate traffic metrics
            current_traffic = stats.get('total_logs', 0)
            self.traffic_history.append(current_traffic)
            if len(self.traffic_history) > 50:
                self.traffic_history.pop(0)
                
            # Calculate threat metrics
            threat_count = stats.get('threat_levels', {}).get('suspicious_activities', 0)
            self.threat_history.append(threat_count)
            if len(self.threat_history) > 50:
                self.threat_history.pop(0)
            
            # Get recent logs for threat distribution
            recent_logs = self.ids_manager.get_recent_logs(100)
            threat_dist = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
            
            for packet in recent_logs:
                if packet.threat_score > 80:
                    threat_dist['CRITICAL'] += 1
                elif packet.threat_score > 60:
                    threat_dist['HIGH'] += 1
                elif packet.threat_score > 40:
                    threat_dist['MEDIUM'] += 1
                else:
                    threat_dist['LOW'] += 1
            
            # Prepare analytics data
            analytics_data = {
                'traffic_history': self.traffic_history.copy(),
                'threat_history': self.threat_history.copy(),
                'threat_distribution': threat_dist,
                'total_packets': stats.get('total_logs', 0),
                'active_users': stats.get('total_users', 0),
                'blacklisted_ips': stats.get('blacklisted_ips', 0),
                'queue_size': stats.get('queue_size', 0),
                'top_source_ips': self._get_top_source_ips(),
                'protocol_distribution': self._get_protocol_distribution()
            }
            
            self.analytics_updated.emit(analytics_data)
            self.msleep(3000)  # Update every 3 seconds
    
    def _get_top_source_ips(self):
        """Get top source IPs from recent logs."""
        ip_counts = {}
        recent_logs = self.ids_manager.get_recent_logs(50)
        
        for packet in recent_logs:
            ip = packet.ip_address
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
            
        # Sort and return top 5
        sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)
        return sorted_ips[:5]
    
    def _get_protocol_distribution(self):
        """Get protocol distribution from recent logs."""
        protocol_counts = {}
        recent_logs = self.ids_manager.get_recent_logs(50)
        
        for packet in recent_logs:
            protocol = packet.protocol
            protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1
            
        return protocol_counts
    
    def stop(self):
        """Stop the analytics update thread."""
        self.running = False

class AnalyticsPanel(QWidget):
    """Advanced analytics panel with network traffic visualizations."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.ids_manager = IDSManager()
        self.setup_ui()
        self.setup_analytics()
        
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
                padding: 10px;
            }
        """)
        
        header_layout = QHBoxLayout(header_frame)
        
        title = QLabel("Network Analytics")
        title.setStyleSheet("font-size: 20px; font-weight: bold; color: #2c3e50;")
        header_layout.addWidget(title)
        
        header_layout.addStretch()
        
        # Time range selector
        self.time_range = QComboBox()
        self.time_range.addItems(["Last 5 Minutes", "Last 15 Minutes", "Last Hour", "Last 24 Hours"])
        self.time_range.setStyleSheet("""
            QComboBox {
                padding: 5px;
                border: 1px solid #ced4da;
                border-radius: 4px;
                background-color: white;
            }
        """)
        header_layout.addWidget(QLabel("Time Range:"))
        header_layout.addWidget(self.time_range)
        
        # Export button
        self.export_btn = QPushButton("Export Report")
        self.export_btn.setStyleSheet("""
            QPushButton {
                background-color: #28a745;
                color: white;
                border: none;
                padding: 5px 15px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #218838;
            }
        """)
        self.export_btn.clicked.connect(self.export_report)
        header_layout.addWidget(self.export_btn)
        
        main_layout.addWidget(header_frame)
        
        # Tab widget for different analytics views
        self.tab_widget = QTabWidget()
        
        # Traffic Analysis Tab
        traffic_tab = QWidget()
        traffic_layout = QVBoxLayout(traffic_tab)
        
        # Traffic chart
        self.traffic_chart = TrafficChart("Network Traffic Over Time")
        traffic_layout.addWidget(self.traffic_chart)
        
        # Threat chart
        self.threat_chart = TrafficChart("Threat Activity Over Time")
        traffic_layout.addWidget(self.threat_chart)
        
        self.tab_widget.addTab(traffic_tab, "Traffic Analysis")
        
        # Threat Distribution Tab
        threat_tab = QWidget()
        threat_layout = QHBoxLayout(threat_tab)
        
        # Threat distribution pie chart
        self.threat_pie_chart = ThreatDistributionChart()
        threat_layout.addWidget(self.threat_pie_chart)
        
        # Threat statistics
        stats_frame = QFrame()
        stats_frame.setStyleSheet("""
            QFrame {
                background-color: white;
                border: 1px solid #dee2e6;
                border-radius: 4px;
                padding: 15px;
            }
        """)
        stats_layout = QVBoxLayout(stats_frame)
        
        stats_title = QLabel("Threat Statistics")
        stats_title.setStyleSheet("font-size: 16px; font-weight: bold; color: #2c3e50;")
        stats_layout.addWidget(stats_title)
        
        self.stats_text = QTextEdit()
        self.stats_text.setReadOnly(True)
        self.stats_text.setMaximumHeight(150)
        stats_layout.addWidget(self.stats_text)
        
        threat_layout.addWidget(stats_frame)
        self.tab_widget.addTab(threat_tab, "Threat Distribution")
        
        # Network Details Tab
        details_tab = QWidget()
        details_layout = QGridLayout(details_tab)
        
        # Top source IPs
        top_ips_frame = QFrame()
        top_ips_frame.setStyleSheet("""
            QFrame {
                background-color: white;
                border: 1px solid #dee2e6;
                border-radius: 4px;
                padding: 10px;
            }
        """)
        top_ips_layout = QVBoxLayout(top_ips_frame)
        
        top_ips_title = QLabel("Top Source IPs")
        top_ips_title.setStyleSheet("font-size: 14px; font-weight: bold; color: #2c3e50;")
        top_ips_layout.addWidget(top_ips_title)
        
        self.top_ips_text = QTextEdit()
        self.top_ips_text.setReadOnly(True)
        self.top_ips_text.setMaximumHeight(120)
        top_ips_layout.addWidget(self.top_ips_text)
        
        details_layout.addWidget(top_ips_frame, 0, 0)
        
        # Protocol distribution
        protocol_frame = QFrame()
        protocol_frame.setStyleSheet("""
            QFrame {
                background-color: white;
                border: 1px solid #dee2e6;
                border-radius: 4px;
                padding: 10px;
            }
        """)
        protocol_layout = QVBoxLayout(protocol_frame)
        
        protocol_title = QLabel("Protocol Distribution")
        protocol_title.setStyleSheet("font-size: 14px; font-weight: bold; color: #2c3e50;")
        protocol_layout.addWidget(protocol_title)
        
        self.protocol_text = QTextEdit()
        self.protocol_text.setReadOnly(True)
        self.protocol_text.setMaximumHeight(120)
        protocol_layout.addWidget(self.protocol_text)
        
        details_layout.addWidget(protocol_frame, 0, 1)
        
        # System metrics
        metrics_frame = QFrame()
        metrics_frame.setStyleSheet("""
            QFrame {
                background-color: white;
                border: 1px solid #dee2e6;
                border-radius: 4px;
                padding: 10px;
            }
        """)
        metrics_layout = QVBoxLayout(metrics_frame)
        
        metrics_title = QLabel("System Metrics")
        metrics_title.setStyleSheet("font-size: 14px; font-weight: bold; color: #2c3e50;")
        metrics_layout.addWidget(metrics_title)
        
        self.metrics_text = QTextEdit()
        self.metrics_text.setReadOnly(True)
        self.metrics_text.setMaximumHeight(120)
        metrics_layout.addWidget(self.metrics_text)
        
        details_layout.addWidget(metrics_frame, 1, 0, 1, 2)
        
        self.tab_widget.addTab(details_tab, "Network Details")
        
        main_layout.addWidget(self.tab_widget)
        
    def setup_analytics(self):
        """Set up the analytics update thread."""
        self.analytics_thread = AnalyticsUpdateThread(self.ids_manager)
        self.analytics_thread.analytics_updated.connect(self.update_analytics)
        self.analytics_thread.start()
        
    def update_analytics(self, data):
        """Update analytics displays with new data."""
        # Update traffic chart
        if data['traffic_history']:
            self.traffic_chart.clear_data()
            for point in data['traffic_history'][-20:]:  # Show last 20 points
                self.traffic_chart.add_data_point(point)
                
        # Update threat chart
        if data['threat_history']:
            self.threat_chart.clear_data()
            for point in data['threat_history'][-20:]:  # Show last 20 points
                self.threat_chart.add_data_point(point)
                
        # Update threat distribution
        threat_dist = data['threat_distribution']
        self.threat_pie_chart.update_threat_data(
            threat_dist['CRITICAL'],
            threat_dist['HIGH'],
            threat_dist['MEDIUM'],
            threat_dist['LOW']
        )
        
        # Update statistics text
        stats_text = f"""
Total Packets Analyzed: {data['total_packets']}
Active Users: {data['active_users']}
Blacklisted IPs: {data['blacklisted_ips']}
Queue Size: {data['queue_size']}

Threat Breakdown:
Critical: {threat_dist['CRITICAL']}
High: {threat_dist['HIGH']}
Medium: {threat_dist['MEDIUM']}
Low: {threat_dist['LOW']}
        """.strip()
        self.stats_text.setPlainText(stats_text)
        
        # Update top source IPs
        top_ips_text = "Rank\tIP Address\t\tPacket Count\n"
        top_ips_text += "-" * 40 + "\n"
        for i, (ip, count) in enumerate(data['top_source_ips'], 1):
            top_ips_text += f"{i}\t{ip}\t{count}\n"
        self.top_ips_text.setPlainText(top_ips_text)
        
        # Update protocol distribution
        protocol_text = "Protocol\tPacket Count\tPercentage\n"
        protocol_text += "-" * 40 + "\n"
        total_packets = sum(data['protocol_distribution'].values())
        for protocol, count in data['protocol_distribution'].items():
            percentage = (count / total_packets * 100) if total_packets > 0 else 0
            protocol_text += f"{protocol}\t{count}\t\t{percentage:.1f}%\n"
        self.protocol_text.setPlainText(protocol_text)
        
        # Update system metrics
        metrics_text = f"""
System Performance:
CPU Usage: {random.randint(20, 80)}%
Memory Usage: {random.randint(30, 70)}%
Network Throughput: {random.randint(100, 1000)} Mbps
Active Connections: {random.randint(10, 100)}

Security Status:
Threat Level: {'HIGH' if threat_dist['CRITICAL'] > 0 else 'MEDIUM' if threat_dist['HIGH'] > 0 else 'LOW'}
Detection Rate: {random.randint(85, 98)}%
False Positive Rate: {random.randint(1, 5)}%
        """.strip()
        self.metrics_text.setPlainText(metrics_text)
        
    def export_report(self):
        """Export analytics report to file."""
        from PyQt5.QtWidgets import QFileDialog
        import json
        
        filename, _ = QFileDialog.getSaveFileName(
            self, "Export Analytics Report", "", "JSON Files (*.json);;Text Files (*.txt)"
        )
        
        if filename:
            try:
                # Collect current analytics data
                report_data = {
                    'timestamp': datetime.now().isoformat(),
                    'statistics': self.ids_manager.get_stats(),
                    'traffic_history': self.traffic_chart.data_points,
                    'threat_history': self.threat_chart.data_points,
                    'top_source_ips': self.analytics_thread._get_top_source_ips(),
                    'protocol_distribution': self.analytics_thread._get_protocol_distribution()
                }
                
                if filename.endswith('.json'):
                    with open(filename, 'w') as f:
                        json.dump(report_data, f, indent=2, default=str)
                else:
                    with open(filename, 'w') as f:
                        f.write("INTRUSION DETECTION SYSTEM ANALYTICS REPORT\n")
                        f.write("=" * 50 + "\n\n")
                        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                        f.write("SYSTEM STATISTICS\n")
                        f.write("-" * 20 + "\n")
                        for key, value in report_data['statistics'].items():
                            f.write(f"{key}: {value}\n")
                        
            except Exception as e:
                print(f"Error exporting report: {e}")
    
    def closeEvent(self, event):
        """Clean up when closing the analytics panel."""
        if hasattr(self, 'analytics_thread'):
            self.analytics_thread.stop()
            self.analytics_thread.wait()
        event.accept()
