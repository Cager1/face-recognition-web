from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Face
import cv2
import face_recognition
import numpy as np

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///face_recognition_app.db'
db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


# Loading the user for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# on / get route redirect to dashboard
@app.route('/')
def home():
    return redirect(url_for('dashboard'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        print('register')
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()
        if user:
            flash('Username already exists.')
            return redirect(url_for('register'))

        new_user = User(username=username, password=generate_password_hash(password, method='pbkdf2:sha256'))
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful. Please log in.')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()

        if not user or not check_password_hash(user.password, password):
            flash('Invalid username or password')
            return redirect(url_for('login'))

        login_user(user)
        return redirect(url_for('dashboard'))

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', username=current_user.username)


@app.route('/upload', methods=['POST'])
@login_required
def upload_image():
    if 'file' not in request.files:
        return redirect(url_for('dashboard'))

    file = request.files['file']
    image = cv2.imdecode(np.fromstring(file.read(), np.uint8), cv2.IMREAD_COLOR)

    # Detect faces in the uploaded image
    face_locations, face_encodings = detect_faces(image)

    print('face - encodings', face_encodings)

    # Recognize any faces already saved by the logged-in user
    recognized_faces = recognize_faces(current_user.id, face_encodings)

    face_encodings_as_list = [encoding.tolist() for encoding in face_encodings]

    return render_template(
        'results.html',
        face_locations=face_locations,
        recognized_faces=recognized_faces,
        face_encodings=face_encodings_as_list)


def detect_faces(image):
    rgb_image = cv2.cvtColor(image, cv2.COLOR_BGR2RGB)
    face_locations = face_recognition.face_locations(rgb_image)
    face_encodings = face_recognition.face_encodings(rgb_image, face_locations)
    return face_locations, face_encodings


def recognize_faces(user_id, face_encodings):
    print("Recognizing faces for user ID: ", user_id)
    user_faces = Face.query.filter_by(user_id=user_id).all()

    # Extract known face encodings and names
    known_faces = [np.array(face.encoding).flatten() for face in user_faces]
    known_names = [face.name for face in user_faces]

    print("Known faces: ", known_faces)
    print("Known names: ", known_names)

    recognized_faces = []
    for face_encoding in face_encodings:
        if face_encoding.shape != (128,):
            print("Invalid face encoding shape:", face_encoding.shape)
            recognized_faces.append("Unknown")
            continue

        matches = face_recognition.compare_faces(known_faces, face_encoding, tolerance=0.7)
        face_distances = face_recognition.face_distance(known_faces, face_encoding)

        if np.any(matches):
            best_match_index = np.where(matches)[0][0]
            name = known_names[best_match_index]
            recognized_faces.append(name)
        else:
            recognized_faces.append("Unknown")

    return recognized_faces


@app.route('/save', methods=['POST'])
@login_required
def save_faces():
    face_encodings = request.form.getlist('face_encodings[]')
    names = request.form.getlist('names[]')
    for encoding, name in zip(face_encodings, names):
        encoding_array = np.array(eval(encoding))
        existing_face = Face.query.filter_by(name=name, user_id=current_user.id).first()
        if not existing_face:
            new_face = Face(name=name, encoding=encoding_array, user_id=current_user.id)
            db.session.add(new_face)
            db.session.commit()

    return redirect(url_for('dashboard'))
