import sys
import os
import traceback
import subprocess
import json

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QTextEdit, QLabel, QFileDialog, QInputDialog, QMessageBox
)
from PySide6.QtGui import QFont
from PySide6.QtCore import Qt, QThread, Signal

from src.model_scanner import get_file_info as scan_model_file
from src.dataset_scanner import get_file_info as scan_dataset_file
from src.dependency_check import scan_project_dependencies
from src.mitre_atlas_integration import MITREAtlasIntegration

class ScanWorker(QThread):
    result_ready = Signal(object)
    error_occurred = Signal(str)

    def __init__(self, function, *args):
        super().__init__()
        self.function = function
        self.args = args

    def run(self):
        try:
            result = self.function(*self.args)
            self.result_ready.emit(result)
        except Exception:
            self.error_occurred.emit(traceback.format_exc())

class ScannerGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.worker = None
        self.mitre_mapper = MITREAtlasIntegration()
        self.setup_ui()

    def setup_ui(self):
        self.setWindowTitle("CypherChain-AI Security Scanner")
        self.resize(1100, 750)
        self.setStyleSheet(self.get_stylesheet())

        main_layout = QVBoxLayout(self)
        title = QLabel("CypherChain-AI Security Scanner")
        title.setFont(QFont("Segoe UI", 24, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(title)

        button_layout = QHBoxLayout()
        self.model_button = QPushButton("Scan Model File...")
        self.dataset_button = QPushButton("Scan Dataset File...")
        self.deps_button = QPushButton("Scan Project Folder...")
        self.watermark_button = QPushButton("Create Watermark...")

        self.model_button.clicked.connect(self.select_and_scan_model)
        self.dataset_button.clicked.connect(self.select_and_scan_dataset)
        self.deps_button.clicked.connect(self.select_and_scan_dependencies)
        self.watermark_button.clicked.connect(self.create_watermark)

        button_layout.addWidget(self.model_button)
        button_layout.addWidget(self.dataset_button)
        button_layout.addWidget(self.deps_button)
        button_layout.addWidget(self.watermark_button)
        main_layout.addLayout(button_layout)

        self.target_label = QLabel("Current Target: None")
        self.target_label.setFont(QFont("Segoe UI", 10, italic=True))
        main_layout.addWidget(self.target_label)

        self.output = QTextEdit()
        self.output.setReadOnly(True)
        self.output.setFont(QFont("Consolas", 11))
        self.output.setPlaceholderText("Scan reports will be displayed here.")
        main_layout.addWidget(self.output)

        self.status_label = QLabel("Ready")
        self.status_label.setAlignment(Qt.AlignRight)
        main_layout.addWidget(self.status_label)

    def start_scan(self, function, path):
        self.output.clear()
        self.target_label.setText(f"Current Target: {os.path.basename(path)}")
        self.log(f"Starting scan on: {path}")
        self.set_buttons_enabled(False)
        self.worker = ScanWorker(function, path)
        self.worker.result_ready.connect(self.on_scan_complete)
        self.worker.error_occurred.connect(self.on_scan_error)
        self.worker.start()

    def select_and_scan_model(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select Model File", "", "Model Files (*.pt *.pth *.onnx *.pb *.pkl)")
        if path:
            self.start_scan(scan_model_file, path)

    def select_and_scan_dataset(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select Dataset File", "", "Data Files (*.csv *.json *.xlsx *.parquet *.zip)")
        if path:
            self.start_scan(scan_dataset_file, path)

    def select_and_scan_dependencies(self):
        path = QFileDialog.getExistingDirectory(self, "Select Project Folder")
        if path:
            self.start_scan(scan_project_dependencies, path)

    def on_scan_complete(self, result):
        if isinstance(result, str):
            self.output.setText(result)
        else:
            self.output.setHtml(self.format_dict_report(result))
        self.set_buttons_enabled(True)

    def on_scan_error(self, error_msg):
        self.output.setText(f"--- SCAN FAILED ---\n{error_msg}")
        self.set_buttons_enabled(True)

    def create_watermark(self):
        model_path, _ = QFileDialog.getOpenFileName(self, "Select Model to Watermark", "", "Model Files (*.pt *.pth *.onnx *.pb *.pkl)")
        if not model_path: return
        author, ok1 = QInputDialog.getText(self, "Author", "Enter Author Name:")
        if not ok1 or not author.strip(): return
        project, ok2 = QInputDialog.getText(self, "Project", "Enter Project Name:")
        if not ok2 or not project.strip(): return

        watermarker_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'tools', 'watermarker.py'))

        try:
            self.status_label.setText("Creating watermark...")
            QApplication.processEvents()
            result = subprocess.run(
                [sys.executable, watermarker_path, model_path, "--author", author, "--project", project],
                capture_output=True, text=True, check=True
            )
            QMessageBox.information(self, "Success", f"Watermark created successfully!\n\nOutput:\n{result.stdout}")
        except FileNotFoundError:
            QMessageBox.critical(self, "Error", f"Could not find watermarker script at:\n{watermarker_path}")
        except subprocess.CalledProcessError as e:
            QMessageBox.critical(self, "Error", f"Failed to create watermark.\n\nError:\n{e.stderr}")
        finally:
            self.status_label.setText("Ready")

    def set_buttons_enabled(self, enabled):
        self.model_button.setEnabled(enabled)
        self.dataset_button.setEnabled(enabled)
        self.deps_button.setEnabled(enabled)
        self.watermark_button.setEnabled(enabled)
        self.status_label.setText("Ready" if enabled else "Scanning in background...")

    def log(self, message):
        self.output.append(message)
        self.output.ensureCursorVisible()

    def format_dict_report(self, result):
        html = ""
        def format_value(val):
            if isinstance(val, list) and val:
                items = "".join([f"<li>{item}</li>" for item in val])
                return f"<ul>{items}</ul>"
            return str(val)

        for key, value in result.items():
            if value is None or (key == 'watermark' and value and value.get('status') == 'VALID'): continue

            formatted_key = key.replace("_", " ").title()
            html += f"<h3>{formatted_key}</h3>"

            if isinstance(value, dict):
                for sub_key, sub_value in value.items():
                    sub_key_fmt = sub_key.replace("_", " ").title()
                    color = "#ff6b6b" if "CRITICAL" in str(sub_value) else ("#ffcc00" if "WARNING" in str(sub_value) else "#f0f0f0")
                    html += f"<p style='color: {color};'><b>{sub_key_fmt}:</b> {format_value(sub_value)}</p>"
            else:
                html += f"<p>{format_value(value)}</p>"

        threats = result.get('suspicious_patterns', []) + result.get('security_findings', [])
        if result.get('watermark', {}):
            if result.get('watermark').get('status') == 'TAMPERED':
                threats.append('backdoor')

        if threats:
            mitre_report = self.mitre_mapper.generate_report(threats)
            html += f"<h3>MITRE ATLAS Threat Mapping</h3><p>{mitre_report.replace(os.linesep, '<br>')}</p>"

        return html

    def get_stylesheet(self):
        return """
            QWidget { background-color: #2c313c; color: #f0f0f0; }
            QPushButton { 
                background-color: #568af2; color: white; border-radius: 8px;
                font-size: 14px; font-weight: bold; padding: 12px; border: none;
            }
            QPushButton:hover { background-color: #6c9eff; }
            QPushButton:disabled { background-color: #4a5568; color: #a0aec0; }
            QTextEdit { 
                background-color: #1a202c; border: 1px solid #4a5568; 
                border-radius: 8px; padding: 10px;
            }
            QLabel { font-size: 14px; }
        """

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ScannerGUI()
    window.show()
    sys.exit(app.exec())