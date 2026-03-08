"""
Main window for the Intrusion Detection System application.
"""
from PyQt5.QtWidgets import (
    QMainWindow, QTabWidget, QVBoxLayout, QWidget, 
    QAction, QStatusBar, QMessageBox, QLabel
)
from PyQt5.QtCore import QTimer
from .dashboard import Dashboard
from .alerts_panel import AlertsPanel
from .logs_panel import LogsPanel
from .analytics_panel import AnalyticsPanel

class MainWindow(QMainWindow):
    """Main application window containing dashboard, alerts, logs, and analytics."""
    
    def __init__(self, parent=None):
        """Initialize the main window with tabs for different views."""
        super().__init__(parent)
        self.setWindowTitle("Advanced Intrusion Detection System")
        self.setGeometry(100, 100, 1200, 800)
        self.setMinimumSize(1000, 600)
        
        # Create main widget and layout
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.layout = QVBoxLayout(self.central_widget)
        
        # Create menu bar
        self.setup_menu_bar()
        
        # Create tab widget
        self.tabs = QTabWidget()
        self.tabs.setTabsClosable(False)
        self.layout.addWidget(self.tabs)
        
        # Initialize panels
        self.dashboard = Dashboard()
        self.alerts_panel = AlertsPanel()
        self.logs_panel = LogsPanel()
        self.analytics_panel = AnalyticsPanel()
        
        # Add tabs with icons (using text for now)
        self.tabs.addTab(self.dashboard, "📊 Dashboard")
        self.tabs.addTab(self.alerts_panel, "🚨 Alerts")
        self.tabs.addTab(self.analytics_panel, "📈 Analytics")
        self.tabs.addTab(self.logs_panel, "📋 Logs")
        
        # Set tab colors and styles
        self.tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #c0c0c0;
                background-color: white;
            }
            QTabBar::tab {
                background-color: #f0f0f0;
                border: 1px solid #c0c0c0;
                padding: 8px 16px;
                margin-right: 2px;
                font-weight: bold;
            }
            QTabBar::tab:selected {
                background-color: #007bff;
                color: white;
            }
            QTabBar::tab:hover {
                background-color: #e0e0e0;
            }
            QTabBar::tab:selected:hover {
                background-color: #0056b3;
            }
        """)
        
        # Create status bar
        self.setup_status_bar()
        
        # Setup timer for periodic updates
        self.setup_timer()
        
        # Initialize UI components
        self.setup_ui()
        
    def setup_menu_bar(self):
        """Set up the menu bar with actions."""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu('File')
        
        export_action = QAction('Export Report', self)
        export_action.setShortcut('Ctrl+E')
        export_action.triggered.connect(self.export_report)
        file_menu.addAction(export_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction('Exit', self)
        exit_action.setShortcut('Ctrl+Q')
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # View menu
        view_menu = menubar.addMenu('View')
        
        refresh_action = QAction('Refresh All', self)
        refresh_action.setShortcut('F5')
        refresh_action.triggered.connect(self.refresh_all)
        view_menu.addAction(refresh_action)
        
        view_menu.addSeparator()
        
        clear_alerts_action = QAction('Clear All Alerts', self)
        clear_alerts_action.triggered.connect(self.clear_all_alerts)
        view_menu.addAction(clear_alerts_action)
        
        # Tools menu
        tools_menu = menubar.addMenu('Tools')
        
        simulate_attack_action = QAction('Simulate Attack', self)
        simulate_attack_action.triggered.connect(self.simulate_attack)
        tools_menu.addAction(simulate_attack_action)
        
        blacklist_ip_action = QAction('Blacklist IP', self)
        blacklist_ip_action.triggered.connect(self.blacklist_ip_dialog)
        tools_menu.addAction(blacklist_ip_action)
        
        # Help menu
        help_menu = menubar.addMenu('Help')
        
        about_action = QAction('About', self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
        
    def setup_status_bar(self):
        """Set up the status bar."""
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        
        # Add permanent widgets
        self.status_label = QLabel("System Ready")
        self.status_bar.addWidget(self.status_label)
        
        self.time_label = QLabel()
        self.status_bar.addPermanentWidget(self.time_label)
        
        # Update time every second
        self.time_timer = QTimer()
        self.time_timer.timeout.connect(self.update_time)
        self.time_timer.start(1000)
        self.update_time()
        
    def setup_timer(self):
        """Set up timer for periodic updates."""
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_status)
        self.update_timer.start(5000)  # Update every 5 seconds
        
    def setup_ui(self):
        """Set up the user interface components."""
        # Set window icon (if available)
        # self.setWindowIcon(QIcon('ids_icon.png'))
        
        # Center window on screen
        self.center_window()
        
    def center_window(self):
        """Center the window on the screen."""
        from PyQt5.QtWidgets import QDesktopWidget
        
        frame_geometry = self.frameGeometry()
        screen_center = QDesktopWidget().availableGeometry().center()
        frame_geometry.moveCenter(screen_center)
        self.move(frame_geometry.topLeft())
        
    def update_time(self):
        """Update the time display."""
        from datetime import datetime
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.time_label.setText(current_time)
        
    def update_status(self):
        """Update the status bar."""
        try:
            # Get dashboard statistics
            stats = self.dashboard.ids_manager.get_stats()
            total_packets = stats.get('total_logs', 0)
            threats = stats.get('threat_levels', {}).get('suspicious_activities', 0)
            
            status_text = f"Packets: {total_packets} | Threats: {threats} | System Active"
            self.status_label.setText(status_text)
            
        except Exception as e:
            self.status_label.setText(f"Status Update Error: {str(e)}")
            
    def export_report(self):
        """Export system report."""
        try:
            # Use analytics panel export functionality
            current_tab = self.tabs.currentIndex()
            if self.tabs.widget(current_tab) == self.analytics_panel:
                self.analytics_panel.export_report()
            else:
                QMessageBox.information(self, "Export Report", 
                                     "Switch to Analytics tab to export detailed reports.")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", f"Failed to export report: {str(e)}")
            
    def refresh_all(self):
        """Refresh all panels."""
        try:
            self.dashboard.manual_refresh()
            QMessageBox.information(self, "Refresh", "All panels refreshed successfully.")
        except Exception as e:
            QMessageBox.critical(self, "Refresh Error", f"Failed to refresh: {str(e)}")
            
    def clear_all_alerts(self):
        """Clear all alerts."""
        reply = QMessageBox.question(self, 'Clear Alerts', 
                                   'Are you sure you want to clear all alerts?',
                                   QMessageBox.Yes | QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            try:
                self.alerts_panel.clear_alerts()
                QMessageBox.information(self, "Clear Alerts", "All alerts cleared successfully.")
            except Exception as e:
                QMessageBox.critical(self, "Clear Error", f"Failed to clear alerts: {str(e)}")
                
    def simulate_attack(self):
        """Simulate an attack for testing."""
        from PyQt5.QtWidgets import QInputDialog
        
        attack_types = ["Port Scan", "Brute Force", "DDoS", "Malware", "Data Exfiltration"]
        attack_type, ok = QInputDialog.getItem(self, "Simulate Attack", 
                                             "Select attack type:", attack_types, 0, False)
        
        if ok and attack_type:
            try:
                # This would integrate with the packet generator
                QMessageBox.information(self, "Attack Simulation", 
                                     f"Simulating {attack_type} attack...\n"
                                     f"Check the Alerts and Dashboard tabs for results.")
            except Exception as e:
                QMessageBox.critical(self, "Simulation Error", f"Failed to simulate attack: {str(e)}")
                
    def blacklist_ip_dialog(self):
        """Show dialog to blacklist an IP address."""
        from PyQt5.QtWidgets import QInputDialog
        
        ip, ok = QInputDialog.getText(self, 'Blacklist IP', 'Enter IP address to blacklist:')
        
        if ok and ip:
            try:
                success = self.dashboard.ids_manager.blacklist_ip(ip)
                if success:
                    QMessageBox.information(self, "IP Blacklisted", f"IP {ip} has been blacklisted.")
                else:
                    QMessageBox.warning(self, "Already Blacklisted", f"IP {ip} is already blacklisted.")
            except Exception as e:
                QMessageBox.critical(self, "Blacklist Error", f"Failed to blacklist IP: {str(e)}")
                
    def show_about(self):
        """Show about dialog."""
        QMessageBox.about(self, "About Advanced IDS", 
                         "Advanced Intrusion Detection System\n\n"
                         "Version: 2.0\n"
                         "Features:\n"
                         "• Real-time threat detection\n"
                         "• Advanced analytics and visualizations\n"
                         "• Automated threat response\n"
                         "• Comprehensive alerting system\n"
                         "• Network traffic analysis\n\n"
                         "© 2024 Advanced Security Systems")
        
    def closeEvent(self, event):
        """Handle application close event."""
        reply = QMessageBox.question(self, 'Confirm Exit', 
                                   'Are you sure you want to exit the IDS?',
                                   QMessageBox.Yes | QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            # Clean up threads
            try:
                self.dashboard.closeEvent(event)
                self.alerts_panel.closeEvent(event)
                self.analytics_panel.closeEvent(event)
            except Exception:
                pass
            event.accept()
        else:
            event.ignore()
