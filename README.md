# 🔐 SmartGuard Pro

**SmartGuard Pro** is an AI-powered network intrusion detection and vulnerability analysis system built with Flask. It allows users to upload `.pcapng` or `.csv` network capture files and generates a detailed report highlighting suspicious activities, protocols, and threat patterns — all via a sleek web dashboard.

---

## 🚀 Features

- 📁 Upload `.pcapng` or `.csv` capture files
- 📊 Interactive bar charts for protocol analysis
- 🕵️‍♂️ Detection of malformed packets and DNS amplification threats
- 🔒 Secure user authentication (register/login/logout)
- 🗂️ Archive page with full scan history and timestamps
- 🌗 Sleek and intuitive UI (light/dark mode ready)
- 📜 Detailed threat summaries and vulnerability mapping
- 📈 Auto-generated protocol graph visualizations

---

## 🛠️ Tech Stack

- **Backend:** Flask, Flask-Login, Flask-Migrate, SQLAlchemy
- **Frontend:** HTML, Jinja2 templates, custom CSS (with 3D-style design)
- **Database:** SQLite (portable, local, easy to deploy)
- **Data Analysis:** PyShark, Pandas, Matplotlib

---

## 📦 Installation

```bash
git clone https://github.com/Ugochi56/SmartGuard.git
cd SmartGuard
python -m venv venv
venv\\Scripts\\activate   # On Windows
pip install -r requirements.txt
