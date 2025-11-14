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

app = Flask(__name__)
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

def authenticate():
    try:
        logger.info("Authenticating with Google Drive API")
        creds = ServiceAccountCredentials.from_json_keyfile_name(
            SERVICE_ACCOUNT_FILE, scopes=SCOPES
        )
        gauth = GoogleAuth()
        gauth.credentials = creds
        drive = GoogleDrive(gauth)
        logger.info("Authentication successful")
        return drive
    except Exception as e:
        logger.error(f"Authentication failed: {str(e)}")
        raise

def upload_to_drive(file_storage, folder_id=UPLOAD_FOLDER_ID):
    tmp_file_path = None
    gfile_id = None  # Track for cleanup if needed
    try:
        drive = authenticate()

        # Save to temp file
        with tempfile.NamedTemporaryFile(delete=False, mode='wb') as tmp_file:
            file_storage.save(tmp_file.name)
            tmp_file_path = tmp_file.name
        logger.debug(f"Saved file to temporary path: {tmp_file_path}")

        # Create and upload file
        gfile = drive.CreateFile({
            'title': 'temp',
            'parents': [{'id': folder_id}]
        })
        # Explicit close before upload (helps Windows locks)
        file_storage.close()

        gfile.SetContentFile(tmp_file_path)
        gfile.Upload()
        logger.debug(f"File uploaded, temporary ID: {gfile['id']}")
        gfile_id = gfile['id']

        # Rename
        gfile['title'] = gfile['id']
        gfile.Upload()
        logger.info(f"File renamed to its ID: {gfile['id']}")

        # Safe permissions handling
        try:
            # Check existing permissions
            permissions = gfile.GetPermissions()
            has_public_reader = any(
                p.get('role') == 'reader' and p.get('type') == 'anyone'
                for p in permissions if isinstance(p, dict) and 'role' in p and 'type' in p
            )
            if not has_public_reader:
                gfile.InsertPermission({
                    'type': 'anyone',
                    'value': 'anyone',
                    'role': 'reader'
                })
                logger.debug("Explicitly set file permissions to public reader")
            else:
                logger.debug("Public reader permission already present/inherited; skipping")
        except HttpError as e:
            error_msg = str(e).lower()
            if 'cannotmodifyinheritedpermission' in error_msg:
                logger.warning(f"Permissions inherited from parent (file accessible via folder link). Skipping explicit set. Full error: {str(e)}")
                # Do NOT raise—continue as success (file is public via folder)
            else:
                # Re-raise other permission errors (e.g., auth issues)
                logger.error(f"Unexpected permissions error: {str(e)}")
                raise

        # Enhanced temp file cleanup (explicit checks/closes)
        if tmp_file_path:
            max_retries = 5
            for attempt in range(max_retries):
                try:
                    if os.path.exists(tmp_file_path):
                        os.unlink(tmp_file_path)  # Use unlink for cross-platform
                        logger.info(f"Temporary file deleted: {tmp_file_path}")
                    break
                except (PermissionError, OSError) as pe:
                    if attempt < max_retries - 1:
                        logger.warning(f"Temp file locked (attempt {attempt + 1}/{max_retries}): {str(pe)}. Retrying in 2s...")
                        time.sleep(2)  # Even longer for stubborn Windows locks
                    else:
                        logger.error(f"Failed to delete temp file after {max_retries} attempts: {str(pe)}. Clean manually from %TEMP%.")

        # Return shareable URL (works even if inherited)
        return f"https://drive.google.com/file/d/{gfile['id']}/view?usp=sharing"

    except Exception as e:
        logger.error(f"Core upload failed (file not saved): {str(e)}")
        # Emergency cleanup
        if tmp_file_path and os.path.exists(tmp_file_path):
            try:
                os.unlink(tmp_file_path)
                logger.info(f"Emergency cleanup: Deleted {tmp_file_path}")
            except Exception as cleanup_err:
                logger.error(f"Emergency cleanup failed: {str(cleanup_err)}")

        # Optional: Delete partial file from Drive if ID exists
        if gfile_id:
            try:
                trash_file = drive.CreateFile({'id': gfile_id})
                trash_file.Delete()
                logger.info(f"Partial file {gfile_id} trashed from Drive")
            except Exception as trash_err:
                logger.warning(f"Could not trash partial file {gfile_id}: {str(trash_err)}")

        raise

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

def require_login(f):
    """Decorator to check if user is logged in"""
    @functools.wraps(f)  # Preserve original function name and docstring
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    return render_template('RealMe.html')

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

@app.route('/claim', methods=['GET', 'POST'])
@require_login
def claim_badges():
    user_id = session['user_id']
    if request.method == 'GET':
        try:
            # Fetch uploads (only reviewing)
            uploads_query = db.collection(f'users/{user_id}/uploads').where('status', '==', 'reviewing').order_by('created_at', direction=firestore.Query.DESCENDING).stream()
            uploads = [doc.to_dict() | {'id': doc.id} for doc in uploads_query]

            # Fetch verified credentials
            verified_query = db.collection(f'users/{user_id}/credentials').where('status', '==', 'verified').order_by('created_at', direction=firestore.Query.DESCENDING).stream()
            verified_badges = [doc.to_dict() | {'id': doc.id} for doc in verified_query]

            return render_template('claim.html',
                                   uploads=uploads,
                                   verified_badges=verified_badges,
                                   first_name=session.get('first_name', 'User'))
        except Exception as e:
            logger.error(f"Error loading claim page: {str(e)}")
            flash('Failed to load data. Please try again.', 'error')
            return redirect(url_for('home'))

    if request.method == 'POST':
        if 'file' not in request.files:
            return jsonify({"error": "No file selected"}), 400
        file = request.files['file']
        if file.filename == '':
            return jsonify({"error": "No file selected"}), 400

        try:
            filename = secure_filename(file.filename)
            doc_name = request.form.get('doc_name', '').strip()
            applicant_name = request.form.get('applicant_name', '').strip()
            course_name = request.form.get('course_name', '').strip()
            organization_name = request.form.get('organization_name', '').strip()
            course_type = request.form.get('course_type', '').strip()
            index_number = request.form.get('index_number', '').strip()

            title = doc_name if doc_name and len(doc_name) <= 20 else f"{course_name} Certificate" if course_name else filename.rsplit('.', 1)[0]

            drive_url = upload_to_drive(file)
            unique_id = str(uuid.uuid4())

            upload_data = {
                'title': title,
                'unique_id': unique_id,
                'file_url': drive_url,
                'status': 'reviewing',
                'created_at': firestore.SERVER_TIMESTAMP,
                'applicant_name': applicant_name,
                'course_name': course_name,
                'organization_name': organization_name,
                'course_type': course_type,
                'index_number': index_number
            }

            db.collection(f'users/{user_id}/uploads').add(upload_data)

            return jsonify({"message": f"Certificate '{title}' uploaded successfully! Under review.", "unique_id": unique_id})
        except Exception as e:
            logger.error(f"Upload error: {str(e)}")
            return jsonify({"error": f"Failed to upload: {str(e)}"}), 500

@app.route('/update_upload/<upload_id>', methods=['POST'])
@require_login
def update_upload(upload_id):
    user_id = session['user_id']
    try:
        upload_ref = db.collection(f'users/{user_id}/uploads').document(upload_id)
        upload_doc = upload_ref.get()
        if not upload_doc.exists:
            return jsonify({"error": "Upload not found"}), 404

        doc_name = request.form.get('doc_name', '').strip()
        applicant_name = request.form.get('applicant_name', '').strip()
        course_name = request.form.get('course_name', '').strip()
        organization_name = request.form.get('organization_name', '').strip()
        course_type = request.form.get('course_type', '').strip()
        index_number = request.form.get('index_number', '').strip()

        update_data = {}
        if doc_name:
            update_data['title'] = doc_name[:20]
        if applicant_name:
            update_data['applicant_name'] = applicant_name
        if course_name:
            update_data['course_name'] = course_name
        if organization_name:
            update_data['organization_name'] = organization_name
        if course_type:
            update_data['course_type'] = course_type
        if index_number:
            update_data['index_number'] = index_number

        if update_data:
            upload_ref.update(update_data)

        return jsonify({"message": "Details updated successfully!"})
    except Exception as e:
        logger.error(f"Update error: {str(e)}")
        return jsonify({"error": f"Failed to update: {str(e)}"}), 500

@app.route('/verify_upload/<upload_id>', methods=['POST'])
@require_login
def verify_upload(upload_id):
    user_id = session['user_id']
    try:
        upload_ref = db.collection(f'users/{user_id}/uploads').document(upload_id)
        upload_doc = upload_ref.get()
        if not upload_doc.exists:
            return jsonify({"error": "Upload not found"}), 404

        upload_data = upload_doc.to_dict()
        doc_id = upload_doc.id

        # Copy to credentials
        credentials_ref = db.collection(f'users/{user_id}/credentials').document(doc_id)
        credentials_data = {
            **upload_data,
            'status': 'verified',
            'issuer': upload_data.get('organization_name', 'Issuer'),
            'badge_url': upload_data['file_url'],  # Use file_url as badge
            'verified_at': firestore.SERVER_TIMESTAMP
        }
        credentials_ref.set(credentials_data)

        # Delete from uploads
        upload_ref.delete()

        return jsonify({"message": f"Upload '{upload_data['title']}' verified and moved to credentials!"})
    except Exception as e:
        logger.error(f"Verify error: {str(e)}")
        return jsonify({"error": f"Failed to verify: {str(e)}"}), 500

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

if __name__ == '__main__':
    app.run(debug=True)