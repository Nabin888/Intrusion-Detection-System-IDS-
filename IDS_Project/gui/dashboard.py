"""
Dashboard view showing system status and key metrics with real-time updates.
"""
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QFrame, QGridLayout, QProgressBar, QPushButton)
from PyQt5.QtCore import pyqtSignal, QThread
import random
from datetime import datetime
from core.ids_manager import IDSManager
from core.packet_generator import PacketGenerator, ThreatType

class MetricsUpdateThread(QThread):
    """Background thread for updating metrics with realistic packet simulation."""
    metrics_updated = pyqtSignal(dict)
    
    def __init__(self, ids_manager):
        super().__init__()
        self.ids_manager = ids_manager
        self.packet_generator = PacketGenerator(ids_manager)
        self.running = True
        self.packet_count = 0
        
    def run(self):
        """Generate realistic network traffic and update metrics."""
        # Start packet generation in background
        import threading
        packet_thread = threading.Thread(
            target=self.packet_generator.start_continuous_generation,
            args=(3,)  # 3 packets per second
        )
        packet_thread.daemon = True
        packet_thread.start()
        
        while self.running:
            # Process packets from queue
            for _ in range(min(5, self.ids_manager.packet_queue.qsize())):
                result = self.ids_manager.process_packet()
                if result['status'] == 'processed' and result['threat_detected']:
                    self.packet_count += 1
            
            # Get updated statistics
            stats = self.ids_manager.get_stats()
            stats['current_time'] = datetime.now().strftime('%H:%M:%S')
            stats['cpu_usage'] = random.randint(20, 80)
            stats['memory_usage'] = random.randint(30, 70)
            stats['network_throughput'] = random.randint(100, 1000)
            stats['active_connections'] = random.randint(10, 100)
            
            # Calculate threat level based on actual processed packets
            threat_score = min(100, (
                stats.get('threat_levels', {}).get('suspicious_activities', 0) * 10 +
                stats.get('queue_size', 0) * 2 +
                len(self.ids_manager.get_blacklisted_ips()) * 15 +
                random.randint(0, 10)
            ))
            
            if threat_score > 70:
                threat_level = "CRITICAL"
                threat_color = "#dc3545"
            elif threat_score > 50:
                threat_level = "HIGH"
                threat_color = "#fd7e14"
            elif threat_score > 30:
                threat_level = "MEDIUM"
                threat_color = "#ffc107"
            else:
                threat_level = "LOW"
                threat_color = "#28a745"
                
            stats['threat_level'] = threat_level
            stats['threat_color'] = threat_color
            stats['threat_score'] = threat_score
            
            self.metrics_updated.emit(stats)
            self.msleep(2000)  # Update every 2 seconds
    
    def stop(self):
        """Stop the thread and packet generation."""
        self.running = False
        self.packet_generator.stop_generation()

class MetricCard(QFrame):
    """A card widget for displaying a single metric."""
    
    def __init__(self, title, value, color="#007bff"):
        super().__init__()
        self.setFrameStyle(QFrame.Box)
        self.setStyleSheet(f"""
            QFrame {{
                border: 2px solid {color};
                border-radius: 10px;
                background-color: #f8f9fa;
                padding: 10px;
            }}
        """)
        
        layout = QVBoxLayout(self)
        
        self.title_label = QLabel(title)
        self.title_label.setStyleSheet("font-size: 12px; color: #6c757d; font-weight: bold;")
        layout.addWidget(self.title_label)
        
        self.value_label = QLabel(str(value))
        self.value_label.setStyleSheet(f"font-size: 24px; font-weight: bold; color: {color};")
        layout.addWidget(self.value_label)
        
        layout.addStretch()

class Dashboard(QWidget):
    """Main dashboard showing system status and key metrics with real-time updates."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.ids_manager = IDSManager()
        self.setup_ui()
        self.setup_timer()
        
    def setup_ui(self):
        """Set up the user interface components."""
        main_layout = QVBoxLayout(self)
        
        # Header
        header_layout = QHBoxLayout()
        title = QLabel("System Dashboard")
        title.setStyleSheet("font-size: 28px; font-weight: bold; color: #2c3e50;")
        header_layout.addWidget(title)
        
        self.status_label = QLabel("● Active")
        self.status_label.setStyleSheet("font-size: 16px; color: #28a745; font-weight: bold;")
        header_layout.addWidget(self.status_label)
        header_layout.addStretch()
        
        # Refresh button
        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.setStyleSheet("""
            QPushButton {
                background-color: #007bff;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 5px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #0056b3;
            }
        """)
        self.refresh_btn.clicked.connect(self.manual_refresh)
        header_layout.addWidget(self.refresh_btn)
        
        main_layout.addLayout(header_layout)
        
        # Metrics Grid
        metrics_layout = QGridLayout()
        
        # Create metric cards
        self.packets_card = MetricCard("Packets Analyzed", "0", "#007bff")
        self.threats_card = MetricCard("Threats Detected", "0", "#dc3545")
        self.users_card = MetricCard("Active Users", "0", "#28a745")
        self.blacklisted_card = MetricCard("Blacklisted IPs", "0", "#fd7e14")
        
        metrics_layout.addWidget(self.packets_card, 0, 0)
        metrics_layout.addWidget(self.threats_card, 0, 1)
        metrics_layout.addWidget(self.users_card, 1, 0)
        metrics_layout.addWidget(self.blacklisted_card, 1, 1)
        
        main_layout.addLayout(metrics_layout)
        
        # System Performance Section
        perf_frame = QFrame()
        perf_frame.setFrameStyle(QFrame.Box)
        perf_frame.setStyleSheet("""
            QFrame {
                border: 1px solid #dee2e6;
                border-radius: 8px;
                background-color: white;
                padding: 15px;
            }
        """)
        
        perf_layout = QVBoxLayout(perf_frame)
        perf_title = QLabel("System Performance")
        perf_title.setStyleSheet("font-size: 18px; font-weight: bold; color: #495057;")
        perf_layout.addWidget(perf_title)
        
        # Progress bars for system metrics
        self.cpu_bar = self.create_progress_bar("CPU Usage", "#007bff")
        self.memory_bar = self.create_progress_bar("Memory Usage", "#28a745")
        self.network_bar = self.create_progress_bar("Network Throughput", "#17a2b8")
        
        perf_layout.addWidget(self.cpu_bar)
        perf_layout.addWidget(self.memory_bar)
        perf_layout.addWidget(self.network_bar)
        
        main_layout.addWidget(perf_frame)
        
        # Threat Level Indicator
        threat_frame = QFrame()
        threat_frame.setFrameStyle(QFrame.Box)
        threat_frame.setStyleSheet("""
            QFrame {
                border: 2px solid #dc3545;
                border-radius: 8px;
                background-color: #f8d7da;
                padding: 15px;
            }
        """)
        
        threat_layout = QHBoxLayout(threat_frame)
        self.threat_label = QLabel("Threat Level: LOW")
        self.threat_label.setStyleSheet("font-size: 20px; font-weight: bold; color: #155724;")
        threat_layout.addWidget(self.threat_label)
        
        self.threat_score_label = QLabel("Score: 0")
        self.threat_score_label.setStyleSheet("font-size: 16px; color: #155724;")
        threat_layout.addWidget(self.threat_score_label)
        threat_layout.addStretch()
        
        main_layout.addWidget(threat_frame)
        
        main_layout.addStretch()
        
    def create_progress_bar(self, label, color):
        """Create a progress bar with label."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        label_widget = QLabel(label)
        label_widget.setStyleSheet("font-size: 14px; font-weight: bold;")
        layout.addWidget(label_widget)
        
        progress_bar = QProgressBar()
        progress_bar.setStyleSheet(f"""
            QProgressBar {{
                border: 2px solid {color};
                border-radius: 5px;
                text-align: center;
                font-weight: bold;
            }}
            QProgressBar::chunk {{
                background-color: {color};
                border-radius: 3px;
            }}
        """)
        progress_bar.setRange(0, 100)
        progress_bar.setValue(0)
        layout.addWidget(progress_bar)
        
        # Store reference to progress bar
        setattr(self, f"{label.lower().replace(' ', '_')}_progress", progress_bar)
        
        return widget
        
    def setup_timer(self):
        """Set up the metrics update timer."""
        self.metrics_thread = MetricsUpdateThread(self.ids_manager)
        self.metrics_thread.metrics_updated.connect(self.update_metrics)
        self.metrics_thread.start()
        
    def update_metrics(self, stats):
        """Update dashboard metrics."""
        # Update metric cards
        self.packets_card.value_label.setText(str(stats.get('total_logs', 0)))
        self.threats_card.value_label.setText(str(stats.get('threat_levels', {}).get('suspicious_activities', 0)))
        self.users_card.value_label.setText(str(stats.get('total_users', 0)))
        self.blacklisted_card.value_label.setText(str(stats.get('blacklisted_ips', 0)))
        
        # Update progress bars
        self.cpu_usage_progress.setValue(stats.get('cpu_usage', 0))
        self.memory_usage_progress.setValue(stats.get('memory_usage', 0))
        self.network_throughput_progress.setValue(min(100, stats.get('network_throughput', 0) // 10))
        
        # Update threat level
        threat_level = stats.get('threat_level', 'LOW')
        threat_color = stats.get('threat_color', '#28a745')
        threat_score = stats.get('threat_score', 0)
        
        self.threat_label.setText(f"Threat Level: {threat_level}")
        self.threat_label.setStyleSheet(f"font-size: 20px; font-weight: bold; color: {threat_color};")
        self.threat_score_label.setText(f"Score: {threat_score}")
        self.threat_score_label.setStyleSheet(f"font-size: 16px; color: {threat_color};")
        
        # Update threat frame background
        self.threat_label.parent().setStyleSheet(f"""
            QFrame {{
                border: 2px solid {threat_color};
                border-radius: 8px;
                background-color: {threat_color}20;
                padding: 15px;
            }}
        """)
        
    def manual_refresh(self):
        """Manually refresh the dashboard."""
        stats = self.ids_manager.get_stats()
        self.update_metrics(stats)
        
    def closeEvent(self, event):
        """Clean up when closing the dashboard."""
        if hasattr(self, 'metrics_thread'):
            self.metrics_thread.stop()
            self.metrics_thread.wait()
        event.accept()
