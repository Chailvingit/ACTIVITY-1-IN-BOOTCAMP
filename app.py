from flask import Flask, render_template, request, redirect, url_for, session, flash, g
import sqlite3
import os
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash 
from datetime import datetime

app = Flask(__name__)

app.secret_key = os.urandom(24)

DATABASE = 'database.db'
UPLOAD_FOLDER = 'static/uploads' 
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

def get_db():
    """
    Establishes a database connection or returns the existing one.
    The connection is stored on Flask's 'g' object to be reused per request.
    """
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row 
    return g.db

def close_db(e=None):
    """
    Closes the database connection at the end of the request.
    """
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    """
    Initializes the database by creating the 'users' table if it doesn't exist.
    This table will store all user details including the image path.
    """
    with app.app_context():
        db = get_db()

        schema_sql_content = """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL, -- This will store the hashed password
            name TEXT,
            birthdate TEXT,
            address TEXT,
            image_path TEXT -- Stores path relative to 'static/' e.g., 'uploads/my_image.jpg'
        );
        """
        db.executescript(schema_sql_content)
        db.commit()


app.teardown_appcontext(close_db)


def allowed_file(filename):
    """
    Checks if the uploaded file's extension is allowed.
    """
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/')
def index():
    """
    Redirects the root URL to the login page.
    """
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Handles user login.
    - GET request: Displays the login form.
    - POST request: Processes the submitted login credentials.
    Authentication is done against the 'users' table in the database.
    """
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()


        if user and check_password_hash(user['password'], password):
            session['logged_in'] = True
            session['username'] = user['username']
            flash('Logged in successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials. Please try again.', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """
    Handles user registration.
    - GET request: Displays the registration form.
    - POST request: Processes the submitted registration data.
      All user details, including the image path, are saved to the database.
    """
    if request.method == 'POST':
        username = request.form['username']
        raw_password = request.form['password'] 
        hashed_password = generate_password_hash(raw_password)

        name = request.form.get('name')
        birthdate = request.form.get('birthdate')
        address = request.form.get('address')

        image_file = request.files.get('image')
        image_path = None 


        if image_file and image_file.filename != '' and allowed_file(image_file.filename):
            filename = secure_filename(image_file.filename)
        
            full_server_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            image_file.save(full_server_path)

            image_path = os.path.join('uploads', filename).replace('\\', '/')


            flash(f'Image "{filename}" uploaded successfully.', 'info')
        elif image_file and image_file.filename != '':
            flash('Invalid image file type. Allowed types: png, jpg, jpeg, gif.', 'danger')

        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (username, password, name, birthdate, address, image_path) VALUES (?, ?, ?, ?, ?, ?)",
                (username, hashed_password, name, birthdate, address, image_path)
            )
            db.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists. Please choose a different one.', 'danger')
            db.rollback()
        except Exception as e:

            flash(f'An error occurred during registration: {e}', 'danger')
            db.rollback()
    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    """
    A protected route that requires the user to be logged in.
    If not logged in, redirects to the login page.
    Fetches the logged-in user's complete data from the database and calculates age.
    """
    if 'logged_in' in session and session['logged_in']:
        db = get_db()
        user_data = db.execute(
            "SELECT * FROM users WHERE username = ?",
            (session['username'],)
        ).fetchone()

        if user_data:
            user_data = dict(user_data)

            
            if user_data.get('birthdate'):
                try:
                    birth_year = int(user_data['birthdate'].split('-')[0])
                    current_year = datetime.now().year
                    user_data['age'] = current_year - birth_year
                except Exception:
                    user_data['age'] = 'N/A' 
            return render_template('dashboard.html', user=user_data)
    
    flash('You need to log in first.', 'info')
    return redirect(url_for('login'))


@app.route('/logout')
def logout():
    """
    Logs out the user by clearing the session.
    """
    session.pop('logged_in', None)
    session.pop('username', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    init_db() 
    app.run(debug=True)