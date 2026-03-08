# Intrusion Detection System (IDS)

A comprehensive, enterprise-grade Intrusion Detection System built with Python, featuring real-time threat detection, machine learning-based anomaly detection, and a modern PyQt5 GUI interface.

## 🚀 Features

### Core Detection Capabilities
- **Real-time Packet Analysis** - Monitor network activities and detect suspicious patterns
- **User Behavior Monitoring** - Track login attempts and calculate threat levels
- **IP Blacklist Management** - Block and manage malicious IP addresses
- **Threat Scoring System** - Automated risk assessment (0-100 scale)
- **Brute Force Detection** - Identify and alert on repeated login attempts

### Machine Learning Integration
- **Anomaly Detection** - Isolation Forest algorithm for zero-day threat detection
- **Pattern Recognition** - Learn normal network behavior and flag deviations
- **Model Persistence** - Save and load trained models for consistent detection

### User Interface
- **Real-time Dashboard** - Live monitoring of system status and threats
- **Alert Management** - Comprehensive threat notification system
- **Analytics Panel** - Data visualization and statistical analysis
- **Log Viewer** - Detailed activity history and audit trails
- **Blacklist Manager** - GUI-based IP blacklist operations

## 📋 System Requirements

### Dependencies
- Python 3.8+
- PyQt5
- scikit-learn
- numpy
- joblib

### Installation
```bash
# Clone the repository
git clone https://github.com/Nabin888/Intrusion-Detection-System-IDS-.git

# Navigate to project directory
cd Intrusion-Detection-System-IDS-/IDS_Project

# Install dependencies
pip install PyQt5 scikit-learn numpy joblib

# Run the application
python main.py
```

## 🏗️ Project Structure

```
IDS_Project/
├── main.py                    # Application entry point
├── core/                      # Core IDS functionality
│   ├── packet.py             # Network packet representation
│   ├── ids_manager.py        # Central IDS controller
│   ├── detector.py           # Base detector interface
│   ├── brute_force_detector.py
│   ├── packet_generator.py
│   ├── threat_calculator.py
│   └── user.py               # User management
├── gui/                       # Graphical user interface
│   ├── main_window.py        # Main application window
│   ├── dashboard.py           # Real-time monitoring dashboard
│   ├── alerts_panel.py       # Threat alerts panel
│   ├── analytics_panel.py    # Analytics and visualizations
│   ├── logs_panel.py         # System logs viewer
│   └── blacklist_manager.py  # IP blacklist management
├── ml/                        # Machine learning components
│   ├── model.py              # Anomaly detection model
│   └── trainer.py            # Model training utilities
└── utils/                     # Utility functions
```

## 🎯 How It Works

### 1. Packet Processing
- Network activities are captured as `Packet` objects
- Each packet contains IP, username, activity type, timestamp, and metadata
- Automated threat scoring based on activity patterns

### 2. Threat Detection
- **Signature-based Detection**: Identifies known attack patterns
- **Anomaly Detection**: Machine learning identifies unusual behavior
- **User Behavior Analysis**: Tracks failed login attempts and suspicious activities

### 3. Alert System
- Real-time threat notifications
- Severity-based alert prioritization
- Comprehensive alert history and management

### 4. Analytics & Reporting
- Statistical analysis of network activities
- Visual charts and graphs for threat trends
- Export functionality for security reports

## 🖥️ Usage Guide

### Starting the Application
```bash
python main.py
```

### Main Interface Tabs

#### 📊 Dashboard
- Real-time system statistics
- Active threat monitoring
- User activity summaries
- System health indicators

#### 🚨 Alerts
- Live threat notifications
- Alert severity levels
- Detailed threat information
- Alert acknowledgment and management

#### 📈 Analytics
- Threat trend analysis
- User behavior patterns
- Network traffic statistics
- Exportable reports

#### 📋 Logs
- Comprehensive activity logs
- Searchable log entries
- Filter by date, user, or activity type
- Export log data

### Key Operations

#### Blacklisting an IP
1. Go to **Tools** → **Blacklist IP**
2. Enter the IP address
3. Confirm the action

#### Simulating Attacks
1. Go to **Tools** → **Simulate Attack**
2. Select attack type (Port Scan, Brute Force, DDoS, etc.)
3. Monitor results in Alerts and Dashboard

#### Exporting Reports
1. Navigate to **Analytics** tab
2. Click **Export Report**
3. Choose format and save location

## 🔧 Configuration

### Threat Scoring
The system uses the following threat score thresholds:
- **LOGIN_SUCCESS**: 0 (no threat)
- **LOGIN_FAILED**: 40 (potential brute force)
- **SUSPICIOUS_ACTIVITY**: 70 (highly suspicious)
- **FILE_ACCESS**: 20 (monitoring required)
- **DATA_TRANSFER**: 15 (monitoring required)
- **SYSTEM_COMMAND**: 25 (monitoring required)
- **BLACKLISTED_IP_ACCESS**: 100 (critical threat)
- **NORMAL**: 5 (background noise)

### User Threat Levels
- **LOW**: 0-2 failed login attempts
- **MEDIUM**: 3-5 failed login attempts
- **HIGH**: 6-10 failed login attempts
- **CRITICAL**: 10+ failed login attempts

## 🛡️ Security Features

### Authentication & Authorization
- Role-based access control (Admin, Analyst, Viewer)
- User activity tracking and audit trails
- Failed login attempt monitoring

### Network Security
- IP blacklist enforcement
- Real-time threat detection
- Automated response capabilities

### Data Protection
- Encrypted data storage (configurable)
- Secure log management
- Audit trail maintenance

## 📊 Monitoring Capabilities

### Real-time Detection
- Continuous packet processing
- Live threat level updates
- Instant alert generation

### Historical Analysis
- Comprehensive activity logs
- Trend analysis and reporting
- Pattern recognition over time

## 🔄 Advanced Features

### Machine Learning Model
- **Algorithm**: Isolation Forest
- **Contamination Rate**: 5% (adjustable)
- **Features**: Multi-dimensional packet analysis
- **Training**: Automated with historical data

### Custom Detectors
- Extensible detector framework
- Plugin architecture for custom detection rules
- Configurable detection thresholds

## 🐛 Troubleshooting

### Common Issues

#### Application Won't Start
```bash
# Check Python version
python --version

# Install missing dependencies
pip install PyQt5 scikit-learn numpy joblib
```

#### No Alerts Generated
- Verify packet generator is running
- Check detection thresholds
- Ensure ML model is trained

#### Performance Issues
- Reduce log retention period
- Optimize ML model parameters
- Check system resources

### Debug Mode
Enable debug logging by setting environment variable:
```bash
export IDS_DEBUG=True
python main.py
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- PyQt5 for the GUI framework
- scikit-learn for machine learning capabilities
- Open-source security community for inspiration and best practices

## 📞 Support

For support, please open an issue on GitHub or contact:
- Email: [your-email@example.com]
- GitHub Issues: [Create New Issue]

---

**⚠️ Disclaimer**: This IDS is for educational and demonstration purposes. For production environments, please ensure proper security hardening and regular updates.

## 🔮 Future Enhancements

- [ ] Web-based dashboard
- [ ] Integration with SIEM systems
- [ ] Mobile alert notifications
- [ ] Advanced ML models (Deep Learning)
- [ ] Cloud deployment support
- [ ] Multi-tenant architecture
- [ ] API for third-party integration
- [ ] Automated incident response
- [ ] Threat intelligence feeds integration
- [ ] Compliance reporting templates
