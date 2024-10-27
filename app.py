from flask import Flask, render_template, redirect, url_for, request, flash
from flask_socketio import SocketIO, emit
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key'
socketio = SocketIO(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # Redirect to login if not authenticated

connected_users = {}
users = {}

class User(UserMixin):
    def __init__(self, username, password):
        self.username = username
        self.password = generate_password_hash(password)

    def get_id(self):
        return self.username  # Unique identifier for Flask-Login

@login_manager.user_loader
def load_user(username):
    return users.get(username)

@app.route('/')
@login_required
def index():
    return render_template('index.html', username=current_user.username)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = users.get(username)
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('index'))
        flash('Неверное имя пользователя или пароль')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username not in users:
            users[username] = User(username, password)
            return redirect(url_for('login'))
        flash('Имя пользователя уже занято')
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@socketio.on('connect')
def handle_connect():
    if current_user.is_authenticated:
        connected_users[current_user.username] = request.sid
        emit('update_user_list', list(connected_users.keys()), broadcast=True)

@socketio.on('disconnect')
def handle_disconnect():
    if current_user.username in connected_users:
        del connected_users[current_user.username]
        emit('update_user_list', list(connected_users.keys()), broadcast=True)

@socketio.on('text_message')
def handle_text_message(message):
    emit('text_message', {'username': current_user.username, 'message': message}, broadcast=True)

@socketio.on('image_message')
def handle_image_message(data):
    emit('image_message', {'username': current_user.username, 'image': data['image']}, broadcast=True)

@socketio.on('call_request')
def handle_call_request(data):
    recipients = data['recipients']
    for recipient in recipients:
        if recipient in connected_users:
            emit('call_request', {'caller': current_user.username}, room=connected_users[recipient])

@socketio.on('accept_call')
def handle_accept_call(data):
    caller = data['caller']
    emit('call_accepted', {'caller': caller}, room=connected_users.get(caller))

if __name__ == '__main__':
    socketio.run(app, debug=True)
