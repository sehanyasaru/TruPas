# admin.py
from flask import Flask, render_template, jsonify, redirect
import firebase_admin
from firebase_admin import credentials, firestore
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

# Initialize Flask
app = Flask(__name__)

# Initialize Firebase
cred = credentials.Certificate("firebase-service-account.json")
firebase_admin.initialize_app(cred)
db = firestore.client()


@app.route('/')
def home():
    return redirect('/admin')


@app.route('/admin')
def admin_panel():
    pending_docs = db.collection_group('uploads') \
        .where('status', '==', 'reviewing') \
        .order_by('created_at', direction=firestore.Query.DESCENDING) \
        .stream()

    pending_list = []
    for doc in pending_docs:
        data = doc.to_dict()
        data['doc_id'] = doc.id
        data['user_id'] = doc.reference.parent.parent.id

        user_doc = db.collection('users').document(data['user_id']).get()
        if user_doc.exists:
            u = user_doc.to_dict()
            data['display_name'] = f"{u.get('first_name','')} {u.get('last_name','')}".strip()
            data['email'] = u.get('email', '—')
        else:
            data['display_name'] = "Deleted User"
            data['email'] = "—"

        pending_list.append(data)

    return render_template('admin_panel.html', pending=pending_list)


#  EMAIL SENDING FUNCTION
def send_email(to_email, subject, message):
    smtp_server = "smtp.gmail.com"
    smtp_port = 587
    sender_email = "lecturerportal@learnx.ac.pg"
    sender_password = "sebb xlll wixa bemy" 

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = to_email
    msg['Subject'] = subject
    msg.attach(MIMEText(message, 'html'))

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, to_email, msg.as_string())
        return True
    except Exception as e:
        print("Email error:", e)
        return False


#  VERIFY + MOVE + SEND EMAIL
@app.route('/admin/verify/<user_id>/<doc_id>', methods=['POST'])
def admin_verify(user_id, doc_id):
    try:
        upload_ref = db.collection('users').document(user_id).collection('uploads').document(doc_id)
        doc = upload_ref.get()

        if not doc.exists:
            return jsonify({"error": "Not found"}), 404

        data = doc.to_dict()

        # New credential data
        cred_data = {
            'title': data.get('title', data.get('course_name', 'Certificate')),
            'issuer': data.get('university', 'TruPas'),
            'badge_url': data['file_url'],
            'file_url': data['file_url'],
            'status': 'verified',
            'created_at': data.get('created_at'),
            'verified_at': firestore.SERVER_TIMESTAMP,
            'applicant_name': data.get('applicant_name'),
            'course_name': data.get('course_name'),
            'province': data.get('province'),
            'university': data.get('university'),
            'index_number': data.get('index_number'),
            'unique_id': data.get('unique_id'),
        }

        cred_ref = db.collection('users').document(user_id).collection('credentials').document(doc_id)

        notif_ref = db.collection('users').document(user_id).collection('notifications').document()
        notif_ref.set({
            'title': 'Certificate Verified',
            'message': f"Your certificate '{data.get('course_name')}' has been verified!",
            'created_at': firestore.SERVER_TIMESTAMP,
            'status': 'unread'
        })


        batch = db.batch()
        batch.set(cred_ref, cred_data)
        batch.delete(upload_ref)
        batch.commit()

        # NOTIFY USER BY EMAIL
        user_doc = db.collection('users').document(user_id).get()

        if user_doc.exists:
            user_info = user_doc.to_dict()
            user_email = user_info.get('email')
            user_name = user_info.get('first_name', '')

            if user_email:
                subject = "Your Certificate Has Been Verified ✔"
                message = f"""
                <h2>Hi {user_name},</h2>
                <p>Your certificate <strong>{data.get('course_name')}</strong> has been 
                <strong style='color:green;'>successfully verified</strong> by TruPas.</p>
                <p>You can now view it in the <b>Verified Achievements</b> section of your account.</p>
                <br>
                <p>Best regards,<br>TruPas Team</p>
                """
                send_email(user_email, subject, message)

        return jsonify({"message": "Verified & email sent!"})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ===================== RUN SERVER =====================
if __name__ == '__main__':
    app.run(debug=True, port=5000)
