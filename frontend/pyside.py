from PySide6.QtWidgets import (
    QApplication, QPushButton, QVBoxLayout, QWidget,
    QTextEdit, QFileDialog, QLabel, QFrame, QHBoxLayout
)
from PySide6.QtGui import QFont
from PySide6.QtCore import Qt

class ScannerGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CypherChain-AI Scanner")
        self.resize(800, 600)

        # Main layout
        main_layout = QVBoxLayout()
        main_layout.setSpacing(20)
        main_layout.setContentsMargins(20, 20, 20, 20)

        # Title
        title = QLabel("CypherChain-AI Scanner")
        title.setFont(QFont("Segoe UI", 18, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(title)

        # Button grid layout
        button_layout = QHBoxLayout()
        desc_layout = QHBoxLayout()

        # Dependency Scanner
        self.dep_button = QPushButton("Dependency Scanner")
        self.dep_button.clicked.connect(self.run_dependency_scan)
        self.style_button(self.dep_button)
        button_layout.addWidget(self.dep_button)

        dep_desc = QLabel("Checks the code libraries for known security issues.")
        dep_desc.setWordWrap(True)
        dep_desc.setAlignment(Qt.AlignCenter)
        desc_layout.addWidget(dep_desc)

        # Model Scanner
        self.model_button = QPushButton("Model Scanner")
        self.model_button.clicked.connect(self.select_model_file)
        self.style_button(self.model_button)
        button_layout.addWidget(self.model_button)

        model_desc = QLabel("Verifies AI model files are authentic and tamper-free.")
        model_desc.setWordWrap(True)
        model_desc.setAlignment(Qt.AlignCenter)
        desc_layout.addWidget(model_desc)

        # Dataset Scanner
        self.dataset_button = QPushButton("Dataset Scanner")
        self.dataset_button.clicked.connect(self.select_dataset_file)
        self.style_button(self.dataset_button)
        button_layout.addWidget(self.dataset_button)

        dataset_desc = QLabel("Analyzes datasets for format, completeness, and corruption.")
        dataset_desc.setWordWrap(True)
        dataset_desc.setAlignment(Qt.AlignCenter)
        desc_layout.addWidget(dataset_desc)

        # Add layouts
        main_layout.addLayout(button_layout)
        main_layout.addLayout(desc_layout)

        # Output log area (fills bottom space)
        self.output = QTextEdit()
        self.output.setReadOnly(True)
        self.output.setFont(QFont("Consolas", 11))
        self.output.setStyleSheet("""
            QTextEdit {
                background-color: #1e1e1e;
                color: #d4d4d4;
                border-radius: 8px;
                padding: 10px;
            }
        """)
        main_layout.addWidget(self.output, stretch=1)

        # Status bar
        self.status = QLabel("Ready.")
        self.status.setAlignment(Qt.AlignRight)
        self.status.setStyleSheet("color: #aaa; font-size: 12px;")
        main_layout.addWidget(self.status)

        self.setLayout(main_layout)

    def style_button(self, btn):
        btn.setMinimumHeight(50)
        btn.setStyleSheet("""
            QPushButton {
                background-color: #2e3b4e;
                color: white;
                border-radius: 8px;
                font-size: 14px;
                padding: 10px;
            }
            QPushButton:hover {
                background-color: #44566c;
            }
        """)

    def log(self, message):
        self.output.append(message)
        self.output.ensureCursorVisible()
        self.status.setText(message)

    def run_dependency_scan(self):
        self.log("Running Dependency Scanner...")

    def select_model_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select Model File", "", "Model Files (*.pt *.pth *.onnx)")
        if path:
            self.log(f"Selected model file: {path}")
            self.log("Running Model Scanner...")

    def select_dataset_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select Dataset File", "", "Data Files (*.csv *.json *.xlsx *.parquet *.zip)")
        if path:
            self.log(f"Selected dataset file: {path}")
            self.log("Running Dataset Scanner...")

if __name__ == "__main__":
    app = QApplication([])
    window = ScannerGUI()
    window.show()
    app.exec()
