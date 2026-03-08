#!/usr/bin/env python3
"""
Main entry point for the Intrusion Detection System (IDS) application.
Initializes the application and starts the main event loop.
"""
import sys
import os

# Add current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from PyQt5.QtWidgets import QApplication
from gui.main_window import MainWindow

def main():
    """Initialize and start the IDS application."""
    app = QApplication(sys.argv)
    
    # Set application information
    app.setApplicationName("Intrusion Detection System")
    app.setApplicationVersion("1.0.0")
    
    # Create and show main window
    window = MainWindow()
    window.show()
    
    # Start the event loop
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
