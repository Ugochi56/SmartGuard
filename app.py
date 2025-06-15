from flask import Flask, render_template, request, redirect, url_for, flash, send_file, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
from dotenv import load_dotenv
import os
import datetime
import uuid
import pandas as pd
import asyncio
import pyshark
import matplotlib.pyplot as plt
from collections import Counter

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'fallback_secret_key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///smartguard.db'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['GRAPH_FOLDER'] = 'static/graphs'

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['GRAPH_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200))
    graph_filename = db.Column(db.String(200))
    total_packets = db.Column(db.Integer)
    suspicious_ips = db.Column(db.PickleType)
    vulnerabilities = db.Column(db.PickleType)
    protocol_chart = db.Column(db.String(200))
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def analyze_capture(file_path):
    extension = os.path.splitext(file_path)[1].lower()

    if extension == '.csv':
        try:
            df = pd.read_csv(file_path)
            total_packets = len(df)
            suspicious_ips = {}
            vulnerabilities = {}
            protocols = df['Protocol'].tolist()

            for _, row in df.iterrows():
                src = row.get('Source', 'unknown')
                protocol = row.get('Protocol', '')
                info = row.get('Info', '').lower()

                if protocol in ['ICMP', 'TCP', 'UDP'] and 'malformed' in info:
                    suspicious_ips[src] = suspicious_ips.get(src, 0) + 1
                    vulnerabilities[src] = vulnerabilities.get(src, []) + [f"Suspicious {protocol} packet"]
                elif 'dns' in protocol.lower() and 'any' in info:
                    suspicious_ips[src] = suspicious_ips.get(src, 0) + 1
                    vulnerabilities[src] = vulnerabilities.get(src, []) + ['Potential DNS amplification']

            return {
                'total_packets': total_packets,
                'protocols': protocols,
                'suspicious_ips': suspicious_ips,
                'vulnerabilities': vulnerabilities
            }
        except Exception as e:
            return {'error': str(e), 'total_packets': 0, 'protocols': [], 'suspicious_ips': {}, 'vulnerabilities': {}}

    elif extension == '.pcapng':
        try:
            try:
                asyncio.get_event_loop()
            except RuntimeError:
                asyncio.set_event_loop(asyncio.new_event_loop())

            cap = pyshark.FileCapture(file_path, only_summaries=True)
            total_packets = 0
            protocols = []
            suspicious_ips = {}
            vulnerabilities = {}

            for packet in cap:
                total_packets += 1
                proto = packet.protocol
                src = getattr(packet, 'source', 'unknown')
                info = packet.info.lower()
                protocols.append(proto)

                if 'malformed' in info:
                    suspicious_ips[src] = suspicious_ips.get(src, 0) + 1
                    vulnerabilities[src] = vulnerabilities.get(src, []) + ['Malformed packet']
                elif 'dns' in proto.lower() and 'any' in info:
                    suspicious_ips[src] = suspicious_ips.get(src, 0) + 1
                    vulnerabilities[src] = vulnerabilities.get(src, []) + ['Potential DNS amplification']

            cap.close()

            return {
                'total_packets': total_packets,
                'protocols': protocols,
                'suspicious_ips': suspicious_ips,
                'vulnerabilities': vulnerabilities
            }

        except Exception as e:
            print(f"Error during capture analysis: {e}")
            return {
                'total_packets': 0,
                'protocols': [],
                'suspicious_ips': {},
                'vulnerabilities': {},
                'error': str(e)
            }
    else:
        return {'error': 'Unsupported file type', 'total_packets': 0, 'protocols': [], 'suspicious_ips': {}, 'vulnerabilities': {}}

def generate_protocol_chart(protocols, output_dir):
    if not protocols:
        return ""

    count = Counter(protocols)
    fig, ax = plt.subplots(figsize=(10, 6))
    ax.bar(count.keys(), count.values(), color='mediumslateblue')
    ax.set_title('Protocols Observed in Capture File')
    ax.set_xlabel('Protocol')
    ax.set_ylabel('Frequency')
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()

    filename = f"protocol_chart_{uuid.uuid4().hex}.png"
    path = os.path.join(output_dir, filename)
    plt.savefig(path)
    plt.close()
    return path

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))
        hashed_pw = generate_password_hash(password)
        new_user = User(username=username, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful. Please log in.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    last_scan = Scan.query.filter_by(user_id=current_user.id).order_by(Scan.timestamp.desc()).first()
    return render_template('dashboard.html', last_scan=last_scan)

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        file = request.files['file']
        if file:
            filename = secure_filename(file.filename)
            path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(path)

            result = analyze_capture(path)
            graph_path = generate_protocol_chart(result['protocols'], app.config['GRAPH_FOLDER'])

            scan = Scan(
                filename=filename,
                graph_filename=os.path.basename(graph_path),
                total_packets=result['total_packets'],
                suspicious_ips=result['suspicious_ips'],
                vulnerabilities=result['vulnerabilities'],
                protocol_chart=os.path.basename(graph_path),
                user_id=current_user.id
            )
            db.session.add(scan)
            db.session.commit()
            flash('Scan completed successfully.')
            return redirect(url_for('report', scan_id=scan.id))
    return render_template('upload.html')

@app.route('/report/<int:scan_id>')
@login_required
def report(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    return render_template('report.html', scan=scan)

@app.route('/archive')
@login_required
def archive():
    scans = Scan.query.filter_by(user_id=current_user.id).order_by(Scan.timestamp.desc()).all()
    return render_template('archive.html', scans=scans)

if __name__ == '__main__':
    app.run(debug=True)
