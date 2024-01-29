from flask import Flask, render_template, redirect, url_for, flash, request, send_file
from flask_wtf import FlaskForm
from flask import send_file
from wtforms import FileField, SubmitField
from wtforms.validators import DataRequired
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import secrets
import time
import schedule
import threading
from datetime import datetime, timedelta
import json
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024 * 1024
app.config['SHARE_LINK_EXPIRY'] = 86400
app.config['MAX_FILE_AGE'] = 30 * 24 * 60 * 60
app.config['STATS_FILE'] = os.path.join(os.getcwd(), 'stats.json')
login_manager = LoginManager(app)
login_manager.login_view = 'login'
share_links = {}
file_uploads = {}
user_stats = {}  # Dictionary to store user statistics


class User(UserMixin):
    def __init__(self, username, password):
        self.id = username
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256')


users = {
    'example_user': User('example_user', 'password123')
}


@login_manager.user_loader
def load_user(user_id):
    return users.get(user_id)


class UploadForm(FlaskForm):
    file = FileField('File', validators=[DataRequired()])
    submit = SubmitField('Upload')


def encrypt_file(file_path, key):
    with open(file_path, 'rb') as f:
        plaintext = f.read()

    cipher = Cipher(algorithms.AES(key), modes.CFB(b'\0' * 16), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    with open(file_path, 'wb') as f:
        f.write(ciphertext)


def decrypt_file(file_path, key):
    with open(file_path, 'rb') as f:
        ciphertext = f.read()

    cipher = Cipher(algorithms.AES(key), modes.CFB(b'\0' * 16), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    with open(file_path, 'wb') as f:
        f.write(plaintext)


def cleanup_files():
    current_time = time.time()

    for token, info in list(share_links.items()):
        if info['expiry_time'] <= current_time:
            del share_links[token]

    for filename, upload_info in list(file_uploads.items()):
        if current_time - upload_info['upload_time'] >= app.config['MAX_FILE_AGE']:
            user = upload_info['user']
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            key = user.password_hash.encode('utf-8')[:32]
            decrypt_file(file_path, key)
            os.remove(file_path)
            del file_uploads[filename]

            # Notify the uploader
            flash(f"File '{filename}' has been automatically deleted. It was uploaded more than 30 days ago.")


def update_user_stats(action, user):
    if user.id not in user_stats:
        user_stats[user.id] = {'uploads': 0, 'downloads': 0}

    user_stats[user.id][action] += 1


def periodic_cleanup():
    schedule.every().day.at("03:00").do(cleanup_files)  # Run cleanup daily at 03:00 AM

    while True:
        schedule.run_pending()
        time.sleep(1)


cleanup_thread = threading.Thread(target=periodic_cleanup)
cleanup_thread.start()


def save_user_stats():
    with open(app.config['STATS_FILE'], 'w') as stats_file:
        json.dump(user_stats, stats_file)


def load_user_stats():
    try:
        if os.path.exists(app.config['STATS_FILE']):
            with open(app.config['STATS_FILE'], 'r') as stats_file:
                return json.load(stats_file)
    except (json.JSONDecodeError, FileNotFoundError):
        pass  # Handle the error, or simply return an empty dictionary
    return {}



user_stats = load_user_stats()


@app.route('/')
@login_required
def index():
    user_uploads = [filename for filename, upload_info in file_uploads.items() if upload_info['user'] == current_user]
    return render_template('index.html', user_stats=user_stats, user_uploads=user_uploads)
    #return render_template('index.html', user_stats=user_stats)


@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    form = UploadForm()

    if form.validate_on_submit():
        file = form.file.data
        filename = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(filename)

        key = os.urandom(32)
        encrypt_file(filename, key)

        share_token = secrets.token_urlsafe(16)
        share_links[share_token] = {
            'filename': filename,
            'expiry_time': int(time.time()) + app.config['SHARE_LINK_EXPIRY']
        }

        file_uploads[filename] = {
            'user': current_user,
            'upload_time': time.time()
        }

        update_user_stats('uploads', current_user)

        flash('File uploaded successfully.')
        return redirect(url_for('index'))

    return render_template('upload.html', form=form)


@app.route('/download/<filename>')
@login_required
def download(filename):
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    key = current_user.password_hash.encode('utf-8')[:32]
    decrypt_file(file_path, key)

    update_user_stats('downloads', current_user)

    return send_file(file_path, as_attachment=True)


@app.route('/share/<token>')
def share(token):
    link_info = share_links.get(token)

    if link_info and link_info['expiry_time'] > int(time.time()):
        file_path = link_info['filename']
        return send_file(file_path, as_attachment=True)
    else:
        return "Invalid or expired share link"


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = users.get(username)

        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password.')

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    save_user_stats()
    return redirect(url_for('login'))


if __name__ == '__main__':
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])

    app.run(debug=True)
