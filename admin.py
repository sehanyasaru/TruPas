# admin.py
from flask import Flask, render_template, jsonify, redirect
import firebase_admin
from firebase_admin import credentials, firestore

# Initialize Flask
app = Flask(__name__)

# Initialize Firebase (use your service account)
cred = credentials.Certificate("firebase-service-account.json")  # Change path if needed
firebase_admin.initialize_app(cred)
db = firestore.client()

@app.route('/')
def home():
    return redirect('/admin')

@app.route('/admin')
def admin_panel():
    # Get all pending uploads from ALL users
    pending_docs = db.collection_group('uploads') \
        .where('status', '==', 'reviewing') \
        .order_by('created_at', direction=firestore.Query.DESCENDING) \
        .stream()

    pending_list = []
    for doc in pending_docs:
        data = doc.to_dict()
        data['doc_id'] = doc.id
        data['user_id'] = doc.reference.parent.parent.id

        # Get user info
        user_doc = db.collection('users').document(data['user_id']).get()
        if user_doc.exists:
            u = user_doc.to_dict()
            data['display_name'] = f"{u.get('first_name','')} {u.get('last_name','')}".strip() or "Unknown User"
            data['email'] = u.get('email', '—')
        else:
            data['display_name'] = "Deleted User"
            data['email'] = "—"

        pending_list.append(data)

    return render_template('admin_panel.html', pending=pending_list)


# ===================== VERIFY CERTIFICATE =====================
@app.route('/admin/verify/<user_id>/<doc_id>', methods=['POST'])
def admin_verify(user_id, doc_id):
    try:
        upload_ref = db.collection('users').document(user_id).collection('uploads').document(doc_id)
        doc = upload_ref.get()
        if not doc.exists:
            return jsonify({"error": "Not found"}), 404

        data = doc.to_dict()

        # Prepare verified credential
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

        # Move document
        batch = db.batch()
        batch.set(cred_ref, cred_data)
        batch.delete(upload_ref)
        batch.commit()

        return jsonify({"message": "Verified & moved to credentials!"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ===================== RUN SERVER =====================
if __name__ == '__main__':
    app.run(debug=True, port=5000)