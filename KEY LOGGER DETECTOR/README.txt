Keylogger Detector – Cross-Platform GUI

Project Overview

Keylogger Detector is a cross-platform Python application designed to detect and alert users about suspicious processes, including potential keyloggers, on their system. The tool features a GUI dashboard and real-time system notifications. It allows users to terminate suspicious processes and view detailed information, providing an additional layer of security.

🎯 Project Goals

Detect suspicious processes using behavioral heuristics:

Temp file writes

High CPU/memory usage

Network connections

Keyboard hooks (Windows only)

Send system notifications when a suspicious process is detected.

Provide a GUI dashboard to monitor, terminate, and view details of suspicious processes.

Support cross-platform operation (Windows, Linux, macOS).

⚙️ Tech Stack

Language: Python 3

Libraries:

psutil → process and network monitoring

tkinter → GUI

plyer → cross-platform system notifications

hashlib → SHA256 hashing for process integrity

OS Support: Windows, Linux, macOS

🛠️ Features

Process Scanning

Lists all running processes with PID, name, path, SHA256, score, and status.

Flags suspicious processes based on heuristic scoring.

Behavior-based Detection

Detects processes writing to temp folders.

Detects unusually high CPU/memory usage.

Detects network connections.

Detects potential keyboard hooks (Windows).

System Notifications

Sends real-time alerts when a suspicious process appears.

GUI automatically highlights the flagged process.

GUI Dashboard

View all processes with live updates.

Terminate suspicious processes.

View details including path, SHA256, and score.

Cross-Platform

Works on Windows, Linux, and macOS.

🚀 How to Run
Requirements

Python 3.8+

Dependencies:
