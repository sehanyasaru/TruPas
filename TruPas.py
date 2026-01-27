import json
import urllib.parse
import functools
import uuid
from werkzeug.utils import secure_filename
from flask import Flask, request, render_template, jsonify, session, redirect, url_for, flash
import os
import tempfile
import time
import logging
from pydrive2.auth import GoogleAuth
from pydrive2.drive import GoogleDrive
from oauth2client.service_account import ServiceAccountCredentials
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import re
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from firebase_admin import credentials, auth, firestore
from firebase_admin.auth import ActionCodeSettings
from datetime import datetime
import firebase_admin
import requests  # For Firebase REST API calls
import boto3
from botocore.exceptions import ClientError

app = Flask(__name__,static_folder='static', static_url_path='/static')
app.secret_key = 'your_secret_key'  # Needed for session
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Google Drive credentials and folder ID
SCOPES = ['https://www.googleapis.com/auth/drive']
UPLOAD_FOLDER_ID = "1Xvnbs_Js8FacizjnCW9pBHUWs1t1mWLm"  # Replace with your Google Drive folder ID

SERVICE_ACCOUNT_FILE = "disco-dispatch-468911-e3-1150a9893570.json"
SCOPES = ['https://www.googleapis.com/auth/drive.file']

# Firebase Web API Key (get from Firebase Console > Project Settings > General > Web API Key)
FIREBASE_API_KEY = "AIzaSyDCLQhzWD_xofZWSyyOfTDkhj12fqHADWk"  # Replace with your actual Web API Key

# Initialize Firebase (run once on startup)
if not firebase_admin._apps:
    cred = credentials.Certificate('firebase-service-account.json')  # Update path to your actual service account JSON
    firebase_admin.initialize_app(cred)
db = firestore.client()  # Firestore instance

S3_BUCKET_NAME = "learnxplus-backups"
S3_FOLDER = "references/"  # Folder where certificates will be stored
S3_REGION = "ap-southeast-2"  # Your region from screenshot

# ⚠️ SECURITY WARNING: Remove these after testing! Use environment variables instead
AWS_ACCESS_KEY_ID = "AKIA2OOB4MWJQDB4QSGY"
AWS_SECRET_ACCESS_KEY = "0YBIXyOnlD/qaKxLL/vB7WDr4PYji6IbJeoPId94"

# Initialize S3 client
s3_client = boto3.client(
    's3',
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    region_name=S3_REGION
)

def upload_to_s3(file_storage):
    try:
        filename    = secure_filename(file_storage.filename)
        unique_name = f"{uuid.uuid4().hex[:12]}_{filename}"
        s3_key      = f"{S3_FOLDER}{unique_name}"

        file_storage.seek(0)

        # FIXED: NO ACL parameter anymore
        s3_client.upload_fileobj(
            file_storage,
            S3_BUCKET_NAME,
            s3_key,
            ExtraArgs={
                'ContentType': file_storage.content_type or 'application/octet-stream',
            }
        )

        url = f"https://{S3_BUCKET_NAME}.s3.{S3_REGION}.amazonaws.com/{s3_key}"
        logger.info(f"S3 upload OK → {url}")
        return url

    except ClientError as e:
        code = e.response['Error']['Code']
        msg  = e.response['Error']['Message']
        logger.error(f"S3 error {code}: {msg}")
        raise Exception(f"S3 upload failed: {code} – {msg}")
    except Exception as e:
        logger.exception("Unexpected S3 upload error")
        raise

@app.route('/check-email', methods=['GET', 'POST'])
def check_email():
    if request.method == 'GET':
        return render_template('email_verification_DHERST.html')
    try:
        email = request.form.get('email')

        if not email:
            return jsonify({'error': 'Email is required'}), 400
        try:
            user = auth.get_user_by_email(email)
            return jsonify({'exists': True, 'firstname': user.display_name})
        except auth.UserNotFoundError:
            return jsonify({'exists': False})
    except Exception as e:
        print(f"Error: {e}")
        return jsonify({'error': 'Error checking email'}), 500

# @app.route('/forgot-password', methods=['GET', 'POST'])
# def forgot_password():
#     if request.method == 'GET':
#         email = request.args.get('email')
#         print(f"GET /forgot-password: email={email}")
#         if email:
#             session['reset_email'] = email
#         return render_template('forgot_password.html', email=email)
#
#     if request.method == 'POST':
#         connection = get_database_connection()
#         if connection is None:
#             print("POST /forgot-password: Database connection failed")
#             return jsonify({"error": "Database connection failed"}), 500
#
#         try:
#             data = request.form
#             new_password = data.get('newPassword')
#             username = session.get('reset_email') or data.get('email') or request.args.get('email')
#             print(f"POST /forgot-password: username={username}, newPassword={'*' * len(new_password) if new_password else None}")
#
#             if not username:
#                 print("POST /forgot-password: No email in session, form, or args")
#                 return jsonify({"error": "Invalid or missing email. Please use the password reset link."}), 400
#
#             if not new_password:
#                 print("POST /forgot-password: Missing newPassword")
#                 return jsonify({"error": "New password is required"}), 400
#
#             if len(new_password) < 8:
#                 print(f"POST /forgot-password: Password too short, length={len(new_password)}")
#                 return jsonify({"error": "Password must be at least 8 characters"}), 400
#
#             cursor = connection.cursor(dictionary=True)
#             cursor.execute("SELECT * FROM registration WHERE username = %s", (username,))
#             user = cursor.fetchone()
#             print(f"POST /forgot-password: User query result={user}")
#
#             if not user:
#                 cursor.close()
#                 print(f"POST /forgot-password: Username {username} not found")
#                 return jsonify({"error": "Username not found."}), 404
#
#             hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
#             cursor.execute("UPDATE registration SET password = %s WHERE username = %s", (hashed_password, username))
#             connection.commit()
#             cursor.close()
#             print(f"POST /forgot-password: Password updated for username={username}")
#             session.pop('reset_email', None)  # Clear session
#             return jsonify({"message": "Password reset successful!"})
#         except Error as e:
#             print(f"POST /forgot-password: Database error: {e}")
#             return jsonify({"error": f"Failed to reset password: {str(e)}"}), 500
#         finally:
#             connection.close()

def require_login(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in first.', 'warning')
            return redirect(url_for('DHERST_login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/get_upload/<upload_id>', methods=['GET'])
@require_login
def get_upload(upload_id):
    """
    Fetch existing upload data for editing/updating
    """
    user_id = session['user_id']
    
    try:
        # Get the upload document
        upload_ref = db.collection(f'users/{user_id}/uploads').document(upload_id)
        upload_doc = upload_ref.get()
        
        if not upload_doc.exists:
            return jsonify({"error": "Upload not found"}), 404
            
        data = upload_doc.to_dict()
        
        # Return only the fields needed for the modal
        return jsonify({
            "success": True,
            "data": {
                "applicant_name": data.get('applicant_name', ''),
                "gender": data.get('gender', ''),
                "province": data.get('province', ''),
                "university": data.get('university', ''),
                "course_name": data.get('course_name', ''),
                "index_number": data.get('index_number', ''),
                "doc_name": data.get('doc_name', ''),
                "title": data.get('title', '')  # For display
                # Don't include file_url - let user choose new file if needed
            }
        })
        
    except Exception as e:
        logger.error(f"Error fetching upload {upload_id}: {str(e)}")
        return jsonify({"error": "Failed to load upload details"}), 500

def send_verification_email(to_email, link, firstname):
    smtp_server = "smtp.gmail.com"
    smtp_port = 587
    sender_email = "lecturerportal@learnx.ac.pg"
    sender_password = "sebb xlll wixa bemy"
    subject = "Verify your email address"

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = to_email
    msg['Subject'] = subject

    body = f"""
    <html>
      <body>
        <div style="text-align: left;">
          <img src="static/uploads/logo_new.jpg" alt="LearnX Logo" style="width: 150px; height: auto; margin-bottom: 20px;" />
          <p>Hello {firstname}!</p>
          <p>Thank you for signing up! Please verify your email by clicking the link below:</p>
          <p><a href="{link}" style="color: #1d4ed8;">Verify your email</a></p>
          <p>If you didn't sign up, please ignore this email.</p>
          <br>
          <p>Regards,<br>The LearnX Team</p>
        </div>
      </body>
    </html>
    """

    msg.attach(MIMEText(body, 'html'))

    try:
        with open("static/uploads/logo_new.jpg", "rb") as f:
            img = MIMEImage(f.read())
            img.add_header('CONTENT_ID', '<logo_image>')
            img.add_header('CONTENT-Disposition', 'inline', filename="logo_new.jpg")
            msg.attach(img)
    except FileNotFoundError:
        logger.warning("Logo file not found, sending without image")

    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(sender_email, sender_password)
        server.send_message(msg)
        server.quit()
        logger.info(f"Verification email sent to {to_email}")
    except Exception as e:
        logger.error(f"Failed to send email: {e}")


def admin_required(f):
    """Decorator to check if admin is logged in"""
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session:
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    return render_template('TruPass_splashscreen.html')

@app.route('/home')
@require_login
def home():
    user_id = session['user_id']  # This is now the Firebase UID
    try:
        # Fetch user profile
        user_doc = db.collection('users').document(user_id).get()
        if not user_doc.exists:
            flash('User profile not found. Please log in again.', 'error')
            return redirect(url_for('login'))
        user_data = user_doc.to_dict()
        first_name = user_data.get('first_name', 'User')

        # Fetch all credentials
        credentials_query = db.collection(f'users/{user_id}/credentials').order_by('created_at', direction=firestore.Query.DESCENDING).stream()
        credentials = []
        for doc in credentials_query:
            cred_data = doc.to_dict()
            cred_data['id'] = doc.id  # Use Firestore doc ID as cred_id
            credentials.append(cred_data)

        # Fetch pending credentials
        pending_query = db.collection(f'users/{user_id}/credentials').where('status', '==', 'pending').stream()
        pending_credentials = []
        for doc in pending_query:
            cred_data = doc.to_dict()
            cred_data['id'] = doc.id
            pending_credentials.append(cred_data)

        return render_template('TruPas_home.html',
                               credentials=credentials,
                               pending_credentials=pending_credentials,
                               first_name=first_name)
    except Exception as e:
        logger.error(f"Firestore error in home: {str(e)}")
        flash('Failed to load data. Please try again.', 'error')
        return redirect(url_for('login'))

@app.route('/claim/<cred_id>', methods=['POST'])
@require_login
def claim_credential(cred_id):
    user_id = session['user_id']
    try:
        cred_ref = db.collection(f'users/{user_id}/credentials').document(cred_id)
        cred_ref.update({'status': 'claimed'})
        return jsonify({"message": "Credential claimed successfully!"})
    except Exception as e:
        logger.error(f"Firestore error in claim_credential: {str(e)}")
        return jsonify({"error": "Failed to claim credential"}), 500

@app.route('/download/<cred_id>')
@require_login
def download_credential(cred_id):
    user_id = session['user_id']
    try:
        cred_doc = db.collection(f'users/{user_id}/credentials').document(cred_id).get()
        if not cred_doc.exists:
            return "Credential not found", 404
        cred = cred_doc.to_dict()
        return redirect(cred['badge_url'])
    except Exception as e:
        logger.error(f"Firestore error in download_credential: {str(e)}")
        return "Failed to load credential", 500

@app.route('/share/<cred_id>')
@require_login
def share_credential(cred_id):
    user_id = session['user_id']
    try:
        cred_doc = db.collection(f'users/{user_id}/credentials').document(cred_id).get()
        if not cred_doc.exists:
            return "Credential not found", 404
        cred = cred_doc.to_dict()
        share_url = f"https://{request.host}/credential/{cred_id}"
        return jsonify({
            "share_url": share_url,
            "title": cred['title'],
            "message": f"I earned '{cred['title']}' from {cred['issuer']}! View it here: {share_url}"
        })
    except Exception as e:
        logger.error(f"Firestore error in share_credential: {str(e)}")
        return jsonify({"error": "Failed to share credential"}), 500

@app.route('/profile')
@require_login
def profile():
    user_id = session['user_id']
    try:
        user_doc = db.collection('users').document(user_id).get()
        if not user_doc.exists:
            return "User not found", 404
        user = user_doc.to_dict()
        user['id'] = user_id  # Add UID for template if needed
        return render_template('profile.html', user=user)
    except Exception as e:
        logger.error(f"Firestore error in profile: {str(e)}")
        flash('Failed to load profile.', 'error')
        return redirect(url_for('home'))

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('index'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('wpu_SignIn.html')

    try:
        data = request.form
        email = data.get('username')
        password = data.get('password')

        if not email or not password:
            return jsonify({"error": "Email and password are required"}), 400

        # Use Firebase REST API to sign in (Admin SDK doesn't support direct password verification)
        url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={FIREBASE_API_KEY}"
        payload = {
            "email": email,
            "password": password,
            "returnSecureToken": True
        }
        response = requests.post(url, json=payload)
        response_data = response.json()

        if 'error' in response_data:
            return jsonify({"error": "Invalid email or password"}), 401

        id_token = response_data['idToken']
        uid = response_data['localId']

        # Verify the ID token (optional but recommended)
        decoded_token = auth.verify_id_token(id_token)

        # Fetch user doc from Firestore
        user_doc = db.collection('users').document(uid).get()
        if not user_doc.exists:
            return jsonify({"error": "User profile not found"}), 404

        user_data = user_doc.to_dict()

        # Check if email is verified in Firebase Auth
        firebase_user = auth.get_user(uid)
        if not firebase_user.email_verified:
            return jsonify({"error": "Please verify your email before logging in."}), 403

        # Update verified in Firestore if not already set (redundant now but safe)
        if not user_data.get('verified', False):
            db.collection('users').document(uid).update({'verified': True})

        # Set session
        session['user_id'] = uid  # Use UID
        session['user_email'] = email
        session['first_name'] = user_data['first_name']

        if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json:
            return jsonify({"success": True, "email": email, "message": "Login successful!"})
        else:
            flash('Login successful! Welcome back.', 'success')
            return redirect(url_for('home'))

    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({"error": f"Failed to log in: {str(e)}"}), 500

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'GET':
        return render_template('wpu_SignUp.html')

    try:
        data = request.form
        email = data.get('username')
        password = data.get('password')
        firstname = data.get('firstname')
        lastname = data.get('lastname')

        if not email or not re.match(r'^[a-zA-Z0-9_.+-]+@gmail\.com$', email):
            return jsonify({"error": "Invalid email format."}), 400

        if not email or not password:
            return jsonify({"error": "Email and password are required"}), 400

        # Check if user exists in Firebase Auth
        try:
            auth.get_user_by_email(email)
            return jsonify({"error": "Account already exists. Please log in."}), 409
        except auth.UserNotFoundError:
            pass  # Proceed

        # Create user in Firebase Auth
        user = auth.create_user(email=email, password=password)
        uid = user.uid

        # Store additional data in Firestore
        db.collection('users').document(uid).set({
            'email': email,
            'first_name': firstname,
            'last_name': lastname,
            'verified': False  # Will be updated after verification
        }, merge=True)

        # Generate Firebase verification link
        acs = ActionCodeSettings(
            url=f"http://localhost:5000/verify_email?email={urllib.parse.quote(email)}",
            handle_code_in_app=True
        )
        verify_link = auth.generate_email_verification_link(email, acs)

        send_verification_email(email, verify_link, firstname)

        return jsonify({"message": "Please check your email for verification."})

    except auth.EmailAlreadyExistsError:
        return jsonify({"error": "Account already exists. Please log in."}), 409
    except Exception as e:
        logger.error(f"Signup error: {str(e)}")
        return jsonify({"error": f"Failed to register: {str(e)}"}), 500

# Add this import at the top if not already there
import json

@app.route('/claim', methods=['GET', 'POST'])
@require_login
def claim():
    user_id = session['user_id']

    # Dropdown data (unchanged)
    province_universities = {
        "National Capital District": ["University of Papua New Guinea", "Pacific Adventist University"],
        "Central": ["Don Bosco Technological Institute"],
        "Milne Bay": ["Milne Bay Technical College"],
        "Oro": ["Popondetta Teachers College"],
        "Morobe": ["Papua New Guinea University of Technology", "Lae University of Technology"],
        "Madang": ["Divine Word University", "Madang Technical College"],
        "East Sepik": ["University of Natural Resources and Environment"],
        "East New Britain": ["Pacific Adventist University (Raluana)"],
        "West New Britain": ["Kimbe College of Health Sciences"],
        "Bougainville": ["Bougainville Technical College"],
        "Western Highlands": ["Highlands Agricultural College", "Mt Hagen Technical College"],
        "Southern Highlands": ["Mendi School of Nursing"],
        "Enga": ["Enga Teachers College"],
        "Chimbu": ["Kundiawa School of Nursing"],
        "Western": ["Western Pacific University"],
        "Gulf": [], "West Sepik": [], "New Ireland": [], "Manus": [], "Jiwaka": [], "Hela": []
    }

    courses_list = [
        "Bachelor of Science in Engineering",
        "Bachelor of Science in Transformative Leadership and Studies",
        "Bachelor of Education (Primary)",
        "Bachelor of Education (Secondary)",
        "Bachelor of Nursing",
        "Bachelor of Medicine and Bachelor of Surgery (MBBS)",
        "Bachelor of Business Administration",
        "Bachelor of Accounting",
        "Bachelor of Information Technology",
        "Bachelor of Civil Engineering",
        "Bachelor of Electrical Engineering",
        "Bachelor of Mechanical Engineering",
        "Bachelor of Agriculture",
        "Bachelor of Environmental Science",
        "Bachelor of Law (LLB)",
        "Bachelor of Arts in Social Work",
        "Bachelor of Public Policy and Management",
        "Bachelor of Economics",
        "Diploma in Teaching (Primary)",
        "Diploma in Nursing",
        "Diploma in Business Studies",
        "Diploma in Information Technology",
        "Certificate in Carpentry and Joinery",
        "Certificate in Electrical Installation",
        "Certificate in Automotive Mechanics",
        "Certificate in Hospitality and Tourism",
        "Certificate in Agriculture",
        "Certificate in Early Childhood Education",
        "Certificate in Community Development",
        "Certificate in Project Management",
        "Certificate in Accounting",
        "Certificate in Office Administration",
        "Certificate in Graphic Design",
        "Certificate in Web Development",
        "Certificate in Cybersecurity"
    ]

    # ────────────────────────────────────────────────────────
    # GET: Show the claim page
    # ────────────────────────────────────────────────────────
    if request.method == 'GET':
        try:
            # Pending uploads (reviewing)
            uploads_query = (
                db.collection(f'users/{user_id}/uploads')
                .where('status', '==', 'reviewing')
                .order_by('created_at', direction=firestore.Query.DESCENDING)
                .stream()
            )
            uploads = [doc.to_dict() | {'id': doc.id} for doc in uploads_query]

            # Verified badges
            verified_query = (
                db.collection(f'users/{user_id}/credentials')
                .where('status', '==', 'verified')
                .order_by('created_at', direction=firestore.Query.DESCENDING)
                .stream()
            )
            verified_badges = [doc.to_dict() | {'id': doc.id} for doc in verified_query]

            return render_template(
                'claim.html',
                uploads=uploads,
                verified_badges=verified_badges,
                first_name=session.get('first_name', 'User'),
                provinces=sorted(province_universities.keys()),
                universities_json=json.dumps(province_universities),
                courses=courses_list
            )

        except Exception as e:
            logger.exception("Error loading claim page")
            flash('Failed to load uploads. Please try again.', 'error')
            return render_template(
                'claim.html',
                uploads=[], verified_badges=[],
                first_name=session.get('first_name', 'User'),
                provinces=[], universities_json="{}", courses=[]
            )

    # ────────────────────────────────────────────────────────
    # POST: Create new or Update existing
    # ────────────────────────────────────────────────────────
    if request.method == 'POST':
        try:
            # ── Read all incoming form data ──
            upload_id      = request.form.get('upload_id')                  # key for update
            doc_name       = request.form.get('doc_name', '').strip()
            applicant_name = request.form.get('applicant_name', '').strip()
            gender         = request.form.get('gender')
            province       = request.form.get('province')
            university     = request.form.get('university')
            course_name    = request.form.get('course_name')
            index_number   = request.form.get('index_number', '').strip()

            # ── File handling (new or replacement) ──
            file_url = None
            if 'file' in request.files and request.files['file'].filename:
                file = request.files['file']
                file_url = upload_to_s3(file)
                logger.info(f"File uploaded/replaced → {file_url}")

            # ── DEBUG: Log EVERYTHING received ──
            logger.info("═" * 70)
            logger.info("POST /claim received - raw form data:")
            for key, value in request.form.items(multi=True):
                logger.info(f"  {key:20} : {value}")
            logger.info(f"  file present       : {bool(file_url)}")
            logger.info(f"  upload_id detected : {upload_id}")
            logger.info("═" * 70)

            # ── Validation ──
            required = {
                'Applicant name': applicant_name,
                'Gender': gender,
                'Province': province,
                'University': university,
                'Course name': course_name,
            }
            missing = [name for name, val in required.items() if not val]
            if missing:
                return jsonify({
                    "error": f"Missing required field(s): {', '.join(missing)}"
                }), 400

            # ── Data to save/update ──
            data = {
                'applicant_name': applicant_name,
                'gender':         gender,
                'province':       province,
                'university':     university,
                'course_name':    course_name,
                'index_number':   index_number,
                'updated_at':     firestore.SERVER_TIMESTAMP,
            }

            # Include title/doc_name only if provided
            if doc_name:
                data['title'] = doc_name
                data['doc_name'] = doc_name

            # Include new file URL if uploaded
            if file_url:
                data['file_url'] = file_url

            # ── UPDATE path ──
            if upload_id:
                upload_ref = db.collection(f'users/{user_id}/uploads').document(upload_id)

                if not upload_ref.get().exists:
                    logger.warning(f"Upload not found: {upload_id}")
                    return jsonify({"error": "Upload not found"}), 404

                # Perform update
                upload_ref.update(data)
                logger.info(f"UPDATED upload {upload_id} → fields: {list(data.keys())}")

                return jsonify({
                    "success": True,
                    "message": "Certificate details updated successfully!"
                })

            # ── CREATE new upload ──
            else:
                # Require file for new submissions
                if not file_url:
                    return jsonify({"error": "Certificate file is required for new uploads"}), 400

                data.update({
                    'title': doc_name or course_name or "Certificate",
                    'unique_id': str(uuid.uuid4()),
                    'status': 'reviewing',
                    'created_at': firestore.SERVER_TIMESTAMP,
                    'course_type': 'Not specified',
                })

                new_doc = db.collection(f'users/{user_id}/uploads').add(data)
                new_id = new_doc[1].id

                logger.info(f"CREATED new upload → ID: {new_id}")

                return jsonify({
                    "success": True,
                    "message": "Certificate submitted successfully! Under review.",
                    "upload_id": new_id
                })

        except Exception as e:
            logger.exception("Critical error in /claim POST")
            return jsonify({
                "error": "Server error occurred. Please contact support."
            }), 500

@app.route('/update_upload/<upload_id>', methods=['POST'])
@require_login
def update_upload(upload_id):
    user_id = session['user_id']
    try:
        upload_ref = db.collection(f'users/{user_id}/uploads').document(upload_id)
        upload_doc = upload_ref.get()
        if not upload_doc.exists:
            return jsonify({"error": "Upload not found"}), 404

        # Get form data
        doc_name = request.form.get('doc_name', '').strip()
        applicant_name = request.form.get('applicant_name', '').strip()
        course_name = request.form.get('course_name', '').strip()
        organization_name = request.form.get('organization_name', '').strip()
        course_type = request.form.get('course_type', '').strip()
        index_number = request.form.get('index_number', '').strip()

        # Prepare update data
        update_data = {}
        if doc_name:
            update_data['title'] = doc_name[:50] if len(doc_name) <= 50 else doc_name[:47] + "..."
            update_data['doc_name'] = doc_name
        if applicant_name:
            update_data['applicant_name'] = applicant_name
        if course_name:
            update_data['course_name'] = course_name
        if organization_name:
            update_data['university'] = organization_name  # Assuming organization_name maps to university
        if course_type:
            update_data['course_type'] = course_type
        if index_number:
            update_data['index_number'] = index_number

        if update_data:
            upload_ref.update(update_data)
            logger.info(f"Updated upload {upload_id} for user {user_id}")

        return jsonify({"message": "Details updated successfully!"})

    except Exception as e:
        logger.error(f"Update error for upload {upload_id}: {str(e)}")
        return jsonify({"error": f"Failed to update: {str(e)}"}), 500

@app.route('/verify_upload/<upload_id>', methods=['POST'])
@require_login
def verify_upload(upload_id):
    user_id = session['user_id']

    try:
        # Reference to the document in uploads
        upload_ref = db.collection('users').document(user_id).collection('uploads').document(upload_id)
        upload_doc = upload_ref.get()

        if not upload_doc.exists:
            return jsonify({"error": "Upload not found"}), 404

        data = upload_doc.to_dict()

        # === MOVE TO CREDENTIALS (same document ID) ===
        cred_ref = db.collection('users').document(user_id).collection('credentials').document(upload_id)

        # Prepare clean credential data
        credential_data = {
            'title': data.get('title', 'Certificate'),
            'issuer': data.get('university', 'TruPas'),
            'badge_url': data.get('file_url'),
            'file_url': data.get('file_url'),
            'status': 'verified',
            'created_at': data.get('created_at', firestore.SERVER_TIMESTAMP),
            'verified_at': firestore.SERVER_TIMESTAMP,
            'applicant_name': data.get('applicant_name'),
            'course_name': data.get('course_name'),
            'course_type': data.get('course_type', 'Not specified'),
            'province': data.get('province'),
            'university': data.get('university'),
            'index_number': data.get('index_number'),
            'unique_id': data.get('unique_id', str(uuid.uuid4())),
        }

        # === ATOMIC MOVE USING BATCH (recommended over transaction for simple move) ===
        batch = db.batch()
        batch.set(cred_ref, credential_data)      # Create in credentials
        batch.delete(upload_ref)                  # Delete from uploads
        batch.commit()  # Execute both operations together

        logger.info(f"Successfully moved upload {upload_id} to credentials for user {user_id}")

        return jsonify({
            "message": "Certificate verified and added to your achievements!",
            "success": True
        })

    except Exception as e:
        logger.error(f"Verify upload failed: {str(e)}", exc_info=True)
        return jsonify({"error": "Failed to verify. Check server logs."}), 500

@app.route('/share', methods=['GET'])
@require_login
def share_credential_page():
    user_id = session['user_id']
    try:
        verified_query = db.collection(f'users/{user_id}/credentials').where('status', '==', 'verified').order_by('created_at', direction=firestore.Query.DESCENDING).stream()
        verified_badges = []
        for doc in verified_query:
            badge_data = doc.to_dict()
            badge_data['id'] = doc.id
            share_url = f"https://{request.host}/credential/{doc.id}"
            badge_data['share_url'] = share_url
            badge_data['share_message'] = f"I earned '{badge_data['title']}' from {badge_data.get('issuer', 'Issuer')}! View it here: {share_url}"
            verified_badges.append(badge_data)

        return render_template('share.html',
                               verified_badges=verified_badges,
                               first_name=session.get('first_name', 'User'))
    except Exception as e:
        logger.error(f"Error loading share page: {str(e)}")
        flash('Failed to load credentials. Please try again.', 'error')
        return redirect(url_for('home'))

@app.route('/credential/<cred_id>')
def public_credential(cred_id):
    try:
        cred_doc = db.collection('public_credentials').document(cred_id).get()
        if not cred_doc.exists:
            return "Credential not found", 404
        cred = cred_doc.to_dict()
        return render_template('public_credential.html', cred=cred)
    except Exception as e:
        logger.error(f"Error loading public credential: {str(e)}")
        return "Failed to load credential", 500


@app.route('/DHERST_login', methods=['GET', 'POST'])
def DHERST_login():
    if request.method == 'GET':
        return render_template('DHESRT_login.html')

    try:
        data = request.form
        email = data.get('username')
        password = data.get('password')

        if not email or not password:
            return jsonify({"error": "Email and password are required"}), 400

        url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={FIREBASE_API_KEY}"
        

        payload = {
            "email": email,
            "password": password,
            "returnSecureToken": True
        }
        response = requests.post(url, json=payload)
        response_data = response.json()

        if 'error' in response_data:
            return jsonify({"error": "Invalid email or password"}), 401

        id_token = response_data['idToken']
        uid = response_data['localId']

        user_doc = db.collection('users').document(uid).get()
        if not user_doc.exists:
            return jsonify({"error": "User profile not found"}), 404

        user_data = user_doc.to_dict()

        firebase_user = auth.get_user(uid)
        if not firebase_user.email_verified:
            return jsonify({"error": "Please verify your email before logging in."}), 403

        if not user_data.get('verified', False):
            db.collection('users').document(uid).update({'verified': True})

        session['user_id'] = uid  # Use UID
        session['user_email'] = email
        session['first_name'] = user_data['first_name']

        if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json:
            return jsonify({"success": True, "email": email, "message": "Login successful!"})
        else:
            flash('Login successful! Welcome back.', 'success')
            return redirect(url_for('home'))

    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({"error": f"Failed to log in: {str(e)}"}), 500

@app.route('/admin/register', methods=['GET', 'POST'])
def admin_register():
    if request.method == 'GET':
        return render_template('admin_register.html')

    try:
        data = request.form
        university_id = data.get('university_id')
        university_name = data.get('university_name')
        email = data.get('email')
        password = data.get('password')

        if not all([university_id, university_name, email, password]):
            return jsonify({"error": "All fields are required"}), 400

        # Check if university_id already exists in admins collection
        admin_ref = db.collection('admins').document(university_id)
        if admin_ref.get().exists:
            return jsonify({"error": "Admin with this University ID already exists"}), 409

        # Create user in Firebase Auth
        try:
            user = auth.create_user(email=email, password=password)
            uid = user.uid
        except auth.EmailAlreadyExistsError:
            return jsonify({"error": "Email already registered"}), 409
        except Exception as e:
             return jsonify({"error": f"Auth Error: {str(e)}"}), 500

        # Store admin details in Firestore
        admin_ref.set({
            'university_name': university_name,
            'email': email,
            'uid': uid,
            'created_at': firestore.SERVER_TIMESTAMP
        })

        return jsonify({"message": "Admin registered successfully!"})

    except Exception as e:
        logger.error(f"Admin Registration Error: {str(e)}")
        return jsonify({"error": "Registration failed"}), 500

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'GET':
        return render_template('admin_login.html')

    try:
        data = request.form
        university_id = data.get('university_id')
        password = data.get('password')

        if not university_id or not password:
            return jsonify({"error": "University ID and Password required"}), 400

        # Lookup admin email
        admin_doc = db.collection('admins').document(university_id).get()
        if not admin_doc.exists:
            return jsonify({"error": "Invalid University ID"}), 401
        
        admin_data = admin_doc.to_dict()
        email = admin_data.get('email')

        # Auth with Firebase REST API
        url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={FIREBASE_API_KEY}"
        payload = {
            "email": email,
            "password": password,
            "returnSecureToken": True
        }
        response = requests.post(url, json=payload)
        response_data = response.json()

        if 'error' in response_data:
            return jsonify({"error": "Invalid Password"}), 401

        # Set Session
        session['admin_id'] = university_id
        session['university_name'] = admin_data.get('university_name')

        return jsonify({"success": True, "message": "Login Successful"})

    except Exception as e:
        logger.error(f"Admin Login Error: {str(e)}")
        return jsonify({"error": "Login failed"}), 500

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    university_name = session.get('university_name')
    try:
        students = []
        
        # 1. Get Pending Uploads for this University
        # Note: 'university' field in upload must match 'university_name' exactly
        uploads = db.collection_group('uploads').where('university', '==', university_name).stream()
        
        for doc in uploads:
            data = doc.to_dict()
            data['id'] = doc.id
            data['doc_type'] = 'upload' # Helper to know where it came from
            # Need user_id to approve? The doc.reference.parent.parent.id gives user_id
            data['user_id'] = doc.reference.parent.parent.id 
            students.append(data)

        # 2. Get Verified Credentials (Optional, if we want to show history)
        # The requirement says "display students... allow approval... if approved update... otherwise keep pending"
        # It also says "Allow admins to download each student's certificates"
        # We can list verified ones too for download purposes.
        credentials = db.collection_group('credentials').where('issuer', '==', university_name).stream()
        for doc in credentials:
             data = doc.to_dict()
             data['id'] = doc.id
             data['doc_type'] = 'credential'
             students.append(data)

        return render_template('admin_dashboard.html', 
                               university_name=university_name, 
                               students=students)
                               
    except Exception as e:
        logger.error(f"Dashboard Error: {str(e)}")
        return f"Error loading dashboard: {str(e)}", 500

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_id', None)
    session.pop('university_name', None)
    return redirect(url_for('admin_login'))

@app.route('/admin/approve_credential/<doc_id>', methods=['POST'])
@admin_required
def approve_credential(doc_id):
    try:
        # We need to find the document. It could be in any user's subcollection.
        # Efficient way: Query collection group by ID (assuming Firestore IDs are unique enough or we use unique_id)
        # Firestore IDs are auto-generated and unique.
        
        # Try finding in uploads first (pending)
        # Problem: 'collection_group' doesn't support 'get()' for a single ID directly without a where clause if we don't know the path.
        # But we can query:
        
        # Strategy: Search in uploads first.
        results = db.collection_group('uploads').stream() # INEFFICIENT in production!
        # BETTER: Query by unique field if we have one. We have 'unique_id' in uploads? Yes.
        # modifying creating to use unique_id as well?
        
        # Let's use the property that we loaded the list with user_id in dashboard, 
        # BUT the route only takes doc_id. 
        # I should have passed user_id in the route. 
        # But for now, I will search using the doc_id, assuming I can find it.
        # Actually, simpler: The dashboard knows the user_id. 
        # I'll update the logic to accept optional user_id query param or just find it.
        
        # To make it robust without changing route signature too much (or if I can't change template easily now):
        # I'll use a collection group query on FieldPath.documentId()
        
        # searches = db.collection_group('uploads').where(firestore.FieldPath.document_id(), '==', doc_id).stream()
        # This works!
        
        target_doc = None
        for doc in db.collection_group('uploads').where(firestore.FieldPath.document_id(), '==', doc_id).stream():
            target_doc = doc
            break
            
        if not target_doc:
             return jsonify({"error": "Document not found"}), 404
             
        # Now verify/move it
        data = target_doc.to_dict()
        user_id = target_doc.reference.parent.parent.id
        
        # Credentials Ref
        cred_ref = db.collection('users').document(user_id).collection('credentials').document(doc_id)
        
        credential_data = {
            'title': data.get('title', 'Certificate'),
            'issuer': session.get('university_name', 'TruPas'), # The admin is the issuer
            'badge_url': data.get('file_url'),
            'file_url': data.get('file_url'),
            'status': 'verified',
            'created_at': data.get('created_at', firestore.SERVER_TIMESTAMP),
            'verified_at': firestore.SERVER_TIMESTAMP,
            'applicant_name': data.get('applicant_name'),
            'course_name': data.get('course_name'),
            'course_type': data.get('course_type', 'Not specified'),
            'province': data.get('province'),
            'university': data.get('university'),
            'index_number': data.get('index_number'),
            'unique_id': data.get('unique_id', str(uuid.uuid4())),
            'approved_by': session['admin_id']
        }

        batch = db.batch()
        batch.set(cred_ref, credential_data)
        batch.delete(target_doc.reference)
        batch.commit()
        
        return jsonify({"success": True})

    except Exception as e:
        logger.error(f"Approval Error: {str(e)}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8080)
