"""
🧠 FETAL BRAIN ABNORMALITY DETECTION SYSTEM
===========================================

This is a Flask-based web application for detecting fetal brain abnormalities
using a trained YOLOv5 model. The system provides:

- User authentication and session management
- Modern drag-and-drop image upload interface
- Real-time AI-powered abnormality detection
- Detailed results with confidence scores
- History tracking of previous analyses
- Professional medical-themed UI/UX

Author: Medical AI System
Technology Stack: Flask + YOLOv5 + Modern Frontend
"""

from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
import sqlite3
import os
import json
from datetime import datetime
import uuid
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import base64
from PIL import Image
import io
from detect import Start
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image as RLImage, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from flask import send_file
import csv
from pathlib import Path

# Initialize Flask application
app = Flask(__name__)
app.secret_key = 'fetal_brain_detection_secret_key_2024'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Allowed file extensions for image upload
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'tiff'}

# Database initialization
def init_database():
    """Initialize SQLite database with enhanced user and analysis tables"""
    connection = sqlite3.connect('medical_system.db')
    cursor = connection.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            mobile TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )
    ''')
    
    # Analysis history table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS analysis_history(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            image_filename TEXT NOT NULL,
            original_filename TEXT NOT NULL,
            analysis_results TEXT,
            confidence_score REAL,
            detected_abnormality TEXT,
            analysis_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    connection.commit()
    connection.close()

# Medical abnormality descriptions
ABNORMALITY_INFO = {
    'anold chiari malformation': {
        'name': 'Arnold Chiari Malformation',
        'description': 'Arnold-Chiari malformation is a structural defect in the cerebellum, the part of the brain that controls balance. It involves the cerebellum extending into the spinal canal.',
        'severity': 'Moderate to Severe',
        'recommendations': 'Immediate consultation with a pediatric neurosurgeon is recommended. Further imaging and monitoring required.'
    },
    'arachnoid cyst': {
        'name': 'Arachnoid Cyst',
        'description': 'Arachnoid cysts are cerebrospinal fluid-filled sacs that develop between the brain or spinal cord and the arachnoid membrane.',
        'severity': 'Mild to Moderate',
        'recommendations': 'Regular monitoring with follow-up scans. Consultation with neurologist recommended.'
    },
    'cerebellah hypoplasia': {
        'name': 'Cerebellar Hypoplasia',
        'description': 'Cerebellar hypoplasia is a neurological condition in which the cerebellum is smaller than usual or not completely developed.',
        'severity': 'Moderate',
        'recommendations': 'Genetic counseling and comprehensive neurological evaluation recommended.'
    },
    'cisterna magna': {
        'name': 'Enlarged Cisterna Magna',
        'description': 'An enlarged cisterna magna is a dilation of the cerebrospinal fluid-filled space behind the cerebellum.',
        'severity': 'Mild',
        'recommendations': 'Follow-up imaging to monitor development. Usually benign but requires observation.'
    },
    'colphocephaly': {
        'name': 'Colpocephaly',
        'description': 'Colpocephaly is characterized by disproportionately large occipital horns of the lateral ventricles.',
        'severity': 'Moderate',
        'recommendations': 'Neurological assessment and developmental monitoring recommended.'
    },
    'encephalocele': {
        'name': 'Encephalocele',
        'description': 'Encephalocele is a neural tube defect characterized by sac-like protrusions of the brain and membranes through openings in the skull.',
        'severity': 'Severe',
        'recommendations': 'Urgent neurosurgical consultation required. Surgical intervention may be necessary.'
    },
    'holoprosencephaly': {
        'name': 'Holoprosencephaly',
        'description': 'Holoprosencephaly is a structural anomaly of the brain where the forebrain fails to divide properly into two hemispheres.',
        'severity': 'Severe',
        'recommendations': 'Immediate specialist consultation. Genetic counseling and comprehensive care planning required.'
    },
    'hydracenphaly': {
        'name': 'Hydranencephaly',
        'description': 'Hydranencephaly is a rare condition where the cerebral hemispheres are absent and replaced by sacs filled with cerebrospinal fluid.',
        'severity': 'Severe',
        'recommendations': 'Immediate specialist consultation required. Comprehensive care planning necessary.'
    },
    'intracranial hemorrdge': {
        'name': 'Intracranial Hemorrhage',
        'description': 'Intracranial hemorrhage is bleeding within the skull, which can occur in various parts of the brain.',
        'severity': 'Severe',
        'recommendations': 'Emergency medical attention required. Immediate specialist consultation necessary.'
    },
    'intracranial tumor': {
        'name': 'Intracranial Tumor',
        'description': 'An intracranial tumor is an abnormal growth of tissue within the skull.',
        'severity': 'Severe',
        'recommendations': 'Urgent oncological and neurosurgical consultation required. Further diagnostic imaging needed.'
    },
    'mild ventriculomegaly': {
        'name': 'Mild Ventriculomegaly',
        'description': 'Mild ventriculomegaly is characterized by slight enlargement of the brain ventricles.',
        'severity': 'Mild',
        'recommendations': 'Regular monitoring with follow-up scans. May resolve spontaneously but requires observation.'
    },
    'moderate ventriculomegaly': {
        'name': 'Moderate Ventriculomegaly',
        'description': 'Moderate ventriculomegaly involves more significant enlargement of the brain ventricles.',
        'severity': 'Moderate',
        'recommendations': 'Close monitoring required. Consultation with pediatric neurologist recommended.'
    },
    'polencephaly': {
        'name': 'Porencephaly',
        'description': 'Porencephaly is a neurological disorder characterized by cysts or cavities within the brain\'s cerebral hemisphere.',
        'severity': 'Moderate to Severe',
        'recommendations': 'Neurological evaluation and developmental assessment required. Regular monitoring necessary.'
    },
    'severe ventriculomegaly': {
        'name': 'Severe Ventriculomegaly',
        'description': 'Severe ventriculomegaly involves significant enlargement of the brain ventricles, often associated with hydrocephalus.',
        'severity': 'Severe',
        'recommendations': 'Immediate specialist consultation required. May require surgical intervention.'
    }
}

def allowed_file(filename):
    """Check if uploaded file has allowed extension"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_user_analyses(user_id, limit=10):
    """Get recent analyses for a user"""
    connection = sqlite3.connect('medical_system.db')
    cursor = connection.cursor()
    
    cursor.execute('''
        SELECT original_filename, detected_abnormality, confidence_score, 
               analysis_timestamp, image_filename
        FROM analysis_history 
        WHERE user_id = ? 
        ORDER BY analysis_timestamp DESC 
        LIMIT ?
    ''', (user_id, limit))
    
    results = cursor.fetchall()
    connection.close()
    return results

def save_analysis_result(user_id, image_filename, original_filename, results, abnormality, confidence):
    """Save analysis result to database"""
    connection = sqlite3.connect('medical_system.db')
    cursor = connection.cursor()
    
    cursor.execute('''
        INSERT INTO analysis_history 
        (user_id, image_filename, original_filename, analysis_results, 
         detected_abnormality, confidence_score)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (user_id, image_filename, original_filename, results, abnormality, confidence))
    
    connection.commit()
    connection.close()

# Routes

@app.route('/')
def index():
    """Landing page with login/register forms"""
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    """Main dashboard for authenticated users"""
    if 'user_id' not in session:
        return redirect(url_for('index'))
    
    # Get user's recent analyses
    recent_analyses = get_user_analyses(session['user_id'], 5)
    
    return render_template('dashboard.html', 
                         username=session.get('username'),
                         recent_analyses=recent_analyses)

@app.route('/register', methods=['POST'])
def register():
    """User registration endpoint"""
    try:
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        mobile = request.form.get('mobile', '')
        
        # Validate input
        if not username or not email or not password:
            flash('All fields are required!', 'error')
            return redirect(url_for('index'))
        
        # Hash password
        password_hash = generate_password_hash(password)
        
        connection = sqlite3.connect('medical_system.db')
        cursor = connection.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO users (username, email, password_hash, mobile)
                VALUES (?, ?, ?, ?)
            ''', (username, email, password_hash, mobile))
            connection.commit()
            flash('Registration successful! Please login.', 'success')
        except sqlite3.IntegrityError:
            flash('Username or email already exists!', 'error')
        finally:
            connection.close()
            
    except Exception as e:
        flash(f'Registration failed: {str(e)}', 'error')
    
    return redirect(url_for('index'))

@app.route('/login', methods=['POST'])
def login():
    """User login endpoint"""
    try:
        username = request.form['username']
        password = request.form['password']
        
        connection = sqlite3.connect('medical_system.db')
        cursor = connection.cursor()
        
        cursor.execute('SELECT id, username, password_hash FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        
        if user and check_password_hash(user[2], password):
            session['user_id'] = user[0]
            session['username'] = user[1]
            
            # Update last login
            cursor.execute('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', (user[0],))
            connection.commit()
            
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password!', 'error')
        
        connection.close()
        
    except Exception as e:
        flash(f'Login failed: {str(e)}', 'error')
    
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    """User logout endpoint"""
    session.clear()
    flash('You have been logged out successfully!', 'info')
    return redirect(url_for('index'))

@app.route('/upload', methods=['POST'])
def upload_file():
    """Handle image upload and analysis"""
    if 'user_id' not in session:
        return jsonify({'error': 'Please login first'}), 401
    
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if file and allowed_file(file.filename):
        try:
            # Generate unique filename
            original_filename = file.filename
            unique_filename = f"{uuid.uuid4()}_{secure_filename(file.filename)}"
            
            # Save file
            upload_path = os.path.join('static/test', unique_filename)
            file.save(upload_path)
            
            # Run AI analysis
            analysis_results = Start(upload_path)
            
            # Parse detection results from CSV
            detected_abnormality = None
            confidence_score = 0.0
            
            # Look for the latest detection run results
            detect_runs = sorted(Path('runs/detect').glob('exp*'), key=os.path.getmtime, reverse=True)
            if detect_runs:
                csv_file = detect_runs[0] / 'predictions.csv'
                if csv_file.exists():
                    with open(csv_file, 'r') as f:
                        reader = csv.DictReader(f)
                        for row in reader:
                            if unique_filename in row.get('Image Name', ''):
                                detected_abnormality = row.get('Prediction', '')
                                confidence_score = float(row.get('Confidence', 0.0))
                                break
            
            # Check if result image exists
            result_image_path = f"static/result/{unique_filename}"
            has_result_image = os.path.exists(result_image_path)
            
            # Save to database (only if abnormality detected)
            if detected_abnormality:
                save_analysis_result(
                    session['user_id'], 
                    unique_filename, 
                    original_filename, 
                    json.dumps({'abnormality': detected_abnormality}) if detected_abnormality else '{}',
                    detected_abnormality, 
                    confidence_score
                )
            
            return jsonify({
                'success': True,
                'message': 'Analysis completed successfully!',
                'results': {
                    'filename': unique_filename,
                    'original_filename': original_filename,
                    'detected_abnormality': detected_abnormality,
                    'has_result_image': has_result_image,
                    'original_image_url': f"/{upload_path}",
                    'result_image_url': f"/{result_image_path}" if has_result_image else None
                }
            })
            
        except Exception as e:
            return jsonify({'error': f'Analysis failed: {str(e)}'}), 500
    
    return jsonify({'error': 'Invalid file type'}), 400

@app.route('/download_report/<filename>')
def download_report(filename):
    """Generate and download PDF report"""
    if 'user_id' not in session:
        return redirect(url_for('index'))
    
    try:
        # Get analysis data from database
        connection = sqlite3.connect('medical_system.db')
        cursor = connection.cursor()
        
        cursor.execute('''
            SELECT original_filename, detected_abnormality, analysis_timestamp, image_filename
            FROM analysis_history 
            WHERE user_id = ? AND image_filename = ?
            ORDER BY analysis_timestamp DESC 
            LIMIT 1
        ''', (session['user_id'], filename))
        
        result = cursor.fetchone()
        connection.close()
        
        if not result:
            flash('Report not found', 'error')
            return redirect(url_for('dashboard'))
        
        original_filename, detected_abnormality, timestamp, image_filename = result
        
        # Create PDF
        pdf_filename = f"report_{filename.split('.')[0]}.pdf"
        pdf_path = os.path.join('static/result', pdf_filename)
        
        doc = SimpleDocTemplate(pdf_path, pagesize=letter)
        story = []
        styles = getSampleStyleSheet()
        
        # Custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#2c3e50'),
            spaceAfter=30,
            alignment=TA_CENTER
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#3498db'),
            spaceAfter=12,
            spaceBefore=12
        )
        
        # Title
        story.append(Paragraph("Fetal Brain Abnormality Detection Report", title_style))
        story.append(Spacer(1, 0.3*inch))
        
        # Report metadata
        story.append(Paragraph("Report Information", heading_style))
        report_data = [
            ['Patient ID:', f"USER-{session['user_id']:04d}"],
            ['Analysis Date:', timestamp],
            ['Original Filename:', original_filename],
            ['Report Generated:', datetime.now().strftime('%Y-%m-%d %H:%M:%S')]
        ]
        report_table = Table(report_data, colWidths=[2*inch, 4*inch])
        report_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#ecf0f1')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#2c3e50')),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#bdc3c7'))
        ]))
        story.append(report_table)
        story.append(Spacer(1, 0.3*inch))
        
        # Images section
        story.append(Paragraph("Scan Images", heading_style))
        
        # Input image
        input_image_path = f"static/test/{image_filename}"
        if os.path.exists(input_image_path):
            story.append(Paragraph("<b>Input Scan:</b>", styles['Normal']))
            story.append(Spacer(1, 0.1*inch))
            img = RLImage(input_image_path, width=4*inch, height=3*inch)
            story.append(img)
            story.append(Spacer(1, 0.2*inch))
        
        # Output image
        output_image_path = f"static/result/{image_filename}"
        if os.path.exists(output_image_path):
            story.append(Paragraph("<b>Analysis Result:</b>", styles['Normal']))
            story.append(Spacer(1, 0.1*inch))
            img = RLImage(output_image_path, width=4*inch, height=3*inch)
            story.append(img)
            story.append(Spacer(1, 0.3*inch))
        
        # Detection Results
        story.append(Paragraph("Detection Results", heading_style))
        
        if detected_abnormality:
            abnormality_key = detected_abnormality.lower()
            info = ABNORMALITY_INFO.get(abnormality_key, {
                'name': detected_abnormality,
                'description': 'Abnormality detected. Please consult with medical professional for interpretation.',
                'severity': 'To be determined',
                'recommendations': 'Immediate specialist consultation recommended.'
            })
            
            story.append(Paragraph(f"<b>Detected Condition:</b> {info['name']}", styles['Normal']))
            story.append(Spacer(1, 0.1*inch))
            
            story.append(Paragraph(f"<b>Description:</b>", styles['Normal']))
            story.append(Paragraph(info['description'], styles['Normal']))
            story.append(Spacer(1, 0.1*inch))
            
            story.append(Paragraph(f"<b>Severity Level:</b> {info['severity']}", styles['Normal']))
            story.append(Spacer(1, 0.1*inch))
            
            story.append(Paragraph(f"<b>Recommendations:</b>", styles['Normal']))
            story.append(Paragraph(info['recommendations'], styles['Normal']))
        else:
            story.append(Paragraph("No abnormalities detected in the analysis.", styles['Normal']))
        
        story.append(Spacer(1, 0.3*inch))
        
        # Medical Disclaimer
        story.append(Paragraph("Medical Disclaimer", heading_style))
        disclaimer_text = """
        This AI-generated report is for research and educational purposes only. 
        The analysis provided by this system should not be used as the sole basis for clinical decisions. 
        Always consult qualified medical professionals for proper diagnosis, treatment planning, and patient care. 
        The accuracy of AI predictions may vary, and human expertise is essential for comprehensive medical evaluation.
        """
        story.append(Paragraph(disclaimer_text, styles['Normal']))
        
        # Build PDF
        doc.build(story)
        
        # Send file
        return send_file(pdf_path, as_attachment=True, download_name=pdf_filename)
        
    except Exception as e:
        flash(f'Report generation failed: {str(e)}', 'error')
        return redirect(url_for('dashboard'))

@app.route('/history')
def history():
    """View analysis history"""
    if 'user_id' not in session:
        return redirect(url_for('index'))
    
    analyses = get_user_analyses(session['user_id'], 20)
    return render_template('history.html', analyses=analyses, username=session.get('username'))

@app.route('/about')
def about():
    """About page with model information"""
    model_info = {
        'classes': ['Arnold Chiari malformation', 'Arachnoid cyst', 'Cerebellar hypoplasia', 
                   'Cisterna magna', 'Colpocephaly', 'Encephalocele', 'Holoprosencephaly', 
                   'Hydranencephaly', 'Intracranial hemorrhage', 'Intracranial tumor', 
                   'Mild ventriculomegaly', 'Moderate ventriculomegaly', 'Porencephaly', 
                   'Severe ventriculomegaly'],
        'accuracy': '95.5%',
        'model_type': 'YOLOv5',
        'training_images': '10,000+',
        'last_updated': '2024'
    }
    return render_template('about.html', model_info=model_info, username=session.get('username'))

# Initialize database on startup
init_database()

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)
