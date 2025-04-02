import os
from flask import Flask, render_template, request, redirect, url_for, session, abort, jsonify
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__, static_folder="/app/flask_app/Webserver-main/images", template_folder=os.path.abspath('/app/flask_app/Webserver-main'))
app.secret_key = 'your_secret_key'


# <---------------------------------------------------------DATENBANK---------------------------------------------------------------------->


def get_db_connection(use_root=False):
    return mysql.connector.connect(
        host=os.getenv('MYSQL_HOST', 'db'),
        user='root' if use_root else os.getenv('MYSQL_USER', 'flask_user'),
        password=os.getenv('MYSQL_ROOT_PASSWORD') if use_root else os.getenv('MYSQL_PASSWORD', 'flask_password'),
        database=os.getenv('MYSQL_DATABASE', 'flask_app')
    )


import time


def create_database():
    retries = 15
    while retries > 0:
        try:
            conn = get_db_connection(use_root=True)
            cursor = conn.cursor()

            cursor.execute("CREATE DATABASE IF NOT EXISTS flask_app;")
            cursor.execute("USE flask_app;")
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(50) UNIQUE NOT NULL,
                    password VARCHAR(255) NOT NULL,
                    email VARCHAR(50) NOT NULL,
                    notes VARCHAR(200) NOT NULL,
                    role ENUM('user', 'admin', 'editor') DEFAULT 'user'
                );
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS registration_requests (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(50) UNIQUE NOT NULL,
                    password VARCHAR(255) NOT NULL,
                    email VARCHAR(50) NOT NULL
                );
            """)
            cursor.execute("""
                INSERT INTO users (username, password, email, role) 
                VALUES ('Admin', 'pbkdf2:sha256:1000000$z6xQxoW6plIVe6fV$a009a43c68c63247682d0e493ced3c7d978f2e7dd9c0fbf62b12ce0371e0a019', 'admin@gamedivers.de', 'admin')
                ON DUPLICATE KEY UPDATE 
                    password = VALUES(password),
                    email = VALUES(email),
                    role = VALUES(role);
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS articles (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    title VARCHAR(255) NOT NULL,
                    text TEXT NOT NULL,
                    category VARCHAR(50),
                    image LONGBLOB,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS article_images (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    article_id INT,
                    image LONGBLOB,
                    FOREIGN KEY (article_id) REFERENCES articles(id) ON DELETE CASCADE
                );
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS article_likes (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT,
                    article_id INT,
                    UNIQUE(user_id, article_id)
                );
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS article_comments (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT NOT NULL,
                    article_id INT NOT NULL,
                    comment TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id),
                    FOREIGN KEY (article_id) REFERENCES articles(id)
                );
            """)

            conn.commit()
            cursor.close()
            conn.close()
            print("✅ Datenbank erfolgreich erstellt!")
            break  # Schleife verlassen, wenn erfolgreich

        except mysql.connector.Error as err:
            print(f"❌ Fehler bei der Datenbankerstellung: {err}")
            retries -= 1
            print(f"🔄 Neuer Versuch in 15 Sekunden... ({15 - retries}/15)")
            time.sleep(15)

    if retries == 0:
        print("❌ Konnte die Datenbank nach mehreren Versuchen nicht erstellen!")


def initialize_database():
    """Führt die ini.sql aus, um die Datenbank zu initialisieren"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        with open("/app/flask_app/init.sql", "r") as f:
            sql_commands = f.read()


        for command in sql_commands.split(";"):
            if command.strip():
                cursor.execute(command)

        conn.commit()
        cursor.close()
        conn.close()
        print("✅ Datenbank erfolgreich aus ini.sql initialisiert!")

    except Exception as e:
        print(f"❌ Fehler beim Laden der ini.sql: {e}")


from flask import send_from_directory

def migrate_add_avatar_path_column():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Prüfen, ob avatar_path-Spalte schon existiert
        cursor.execute("SHOW COLUMNS FROM users LIKE 'avatar_path';")
        column_exists = cursor.fetchone()

        if not column_exists:
            cursor.execute("ALTER TABLE users ADD COLUMN avatar_path VARCHAR(255);")
            conn.commit()
            print("✅ Spalte 'avatar_path' erfolgreich hinzugefügt.")
        else:
            print("ℹ️ Spalte 'avatar_path' existiert bereits.")

        cursor.close()
        conn.close()

    except Exception as e:
        print(f"❌ Fehler bei Migration: {e}")


# <-------------------------------------------------------APP.ROUTEs--------------------------------------------------------------------->


@app.route('/favicon.ico')
def favicon():
    return send_from_directory('flask_app/Webserver-main', 'favicon.ico', mimetype='image/vnd.microsoft.icon')


@app.route('/')
def index():
    return render_template('index.html', role=session.get('role', 'guest'))


# <--------------------------------------------Routes-für-HTML-Dateien-setzen------------------------------------------------------------>


@app.route('/adminpanel')
def adminpanel():
    if session.get('logged_in') and session.get('role') == 'admin':
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT id, username FROM registration_requests")
        registration_requests = cursor.fetchall()

        cursor.execute("SELECT id, username, email, role, notes FROM users")
        users = cursor.fetchall()

        cursor.close()
        conn.close()

        return render_template('admin.html', users=users, registration_requests=registration_requests)

    return redirect(url_for('index'))


@app.route('/datenschutz')
def datenschutz():
    if session.get('logged_in'):
        return render_template('datenschutz.html', user=session['user'], role=session.get('role', 'user'))
    return redirect(url_for('index'))


@app.route('/impressum')
def impressum():
    if session.get('logged_in'):
        return render_template('impressum.html', user=session['user'], role=session.get('role', 'user'))
    return redirect(url_for('index'))


@app.route('/profile')
def profile():
    if session.get('logged_in'):
        username = session['user']
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute('SELECT id, username, email, role, avatar_path FROM users WHERE username = %s', (username,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if user:
            return render_template('profile.html', user=user, role=user['role'])

    return redirect(url_for('index'))



@app.route('/registration')
def registration():
    if session.get('logged_in'):
        return render_template('registration.html', user=session['user'], role=session.get('role', 'user'))
    return redirect(url_for('index'))


@app.route('/underdevelopement')
def underdevelopement():
    if session.get('logged_in'):
        return render_template('under-developement.html', user=session['user'], role=session.get('role', 'user'))
    return redirect(url_for('index'))


@app.route('/welcomeuser')
def welcomeuser():
    if session.get('logged_in'):
        return render_template('welcome-user.html', user=session['user'], role=session.get('role', 'user'))
    return redirect(url_for('index'))


@app.route('/welcome')
def welcome():
    if session.get('logged_in'):
        return render_template('welcome.html', user=session['user'], role=session.get('role', 'user'))
    return redirect(url_for('index'))


@app.route('/helldivers')
def helldivers():
    if session.get('logged_in'):
        return render_template('helldivers.html')
    return redirect(url_for('index'))


@app.route('/editor')
def editor():
    if session.get('logged_in'):
        return render_template('editor.html')
    return redirect(url_for('index'))

# <---------------------------------------Routes-für-Login/Logout-und-Registrierung--------------------------------------------------------->


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None  # Standardmäßig keine Fehlermeldung

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if user and user['password'] and check_password_hash(user['password'], password):
            session['logged_in'] = True 
            session['user'] = username
            session['user_id'] = user['id']
            session['role'] = user['role']
            return redirect(url_for('welcomeuser'))
        else:
            error = "⚠ Benutzername oder Passwort ist falsch!"

    return render_template('index.html', error=error)


@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    success = None

    if request.method == 'POST':
        username = request.form['username']
        email = request.form.get('email')
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Prüfen, ob Benutzername bereits existiert
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        existing_user = cursor.fetchone()

        if existing_user:
            error = "⚠ Benutzername bereits vergeben!"
        else:
            # Registrierung als ausstehende Anfrage speichern
            hashed_password = generate_password_hash(password)
            cursor.execute("INSERT INTO registration_requests (username, email, password) VALUES (%s, %s, %s)", (username, email, hashed_password))
            conn.commit()
            success = "✅ Registrierung erfolgreich! Ein Admin muss die Anfrage bestätigen."

        cursor.close()
        conn.close()

    return render_template('registration.html', error=error, success=success)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


# <-------------------------------------------------Routes-für-Adminfunktionen----------------------------------------------------->


@app.route('/admin_approve/<int:request_id>')
def admin_approve(request_id):
    if 'role' in session and session['role'] == 'admin':
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM registration_requests WHERE id = %s", (request_id,))
        request_data = cursor.fetchone()

        if request_data:
            notes = request_data.get('notes', '')
            cursor.execute("INSERT INTO users (username, password, email, notes, role) VALUES (%s, %s, %s, %s, 'user')",
                           (request_data['username'], request_data['password'], request_data['email'], notes))
            cursor.execute("DELETE FROM registration_requests WHERE id = %s", (request_id,))
            conn.commit()

        cursor.close()
        conn.close()

    return redirect(url_for('adminpanel'))



@app.route('/admin_reject/<int:request_id>')
def admin_reject(request_id):
    if 'role' in session and session['role'] == 'admin':
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM registration_requests WHERE id = %s", (request_id,))
        conn.commit()
        cursor.close()
        conn.close()

    return redirect(url_for('adminpanel'))


@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if session.get('logged_in') and session.get('role') == 'admin':
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        if request.method == 'POST':  
            new_username = request.form['username']
            new_password = request.form['password']
            new_email = request.form['email']
            role = request.form['role']
            new_notes = request.form['notes']

            hashed_password = generate_password_hash(new_password)

            cursor.execute('INSERT INTO users (username, password, email, notes, role) VALUES (%s, %s, %s, %s, %s)', 
                           (new_username, hashed_password, new_email, new_notes, role))
            conn.commit()

        cursor.execute('SELECT id, username, role, notes FROM users')
        users = cursor.fetchall()
        for user in users:
            user['notes'] = user.get('notes', 'Keine Notiz')
        cursor.close()
        conn.close()

        return render_template('admin.html', users=users)

    return redirect(url_for('index'))


# <------------------------------------------------Routes-für-User-aktionen------------------------------------------------------------->


@app.route('/delete_account', methods=['POST'])
def delete_account():
    if session.get('logged_in'):
        user_id = session.get('user_id')

        # Benutzer aus der Datenbank löschen
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM users WHERE id = %s', (user_id,))
        conn.commit()
        cursor.close()
        conn.close()

        # Benutzer ausloggen
        session.clear()
        return redirect(url_for('index'))
    
    return redirect(url_for('index'))


@app.route('/delete_user/<int:user_id>')
def delete_user(user_id):
    if session.get('logged_in') and session.get('role') == 'admin':
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM users WHERE id = %s', (user_id,))
        conn.commit()
        cursor.close()
        conn.close()
    return redirect(url_for('admin'))


@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    if session.get('logged_in') and session.get('role') == 'admin':
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))
        user = cursor.fetchone()

        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            email = request.form['email']
            notes = request.form['notes']
            role = request.form['role']

            if password:
                cursor.execute('UPDATE users SET username = %s, password = %s, email = %s, notes = %s, role = %s WHERE id = %s',
                               (username, password, email, notes, role, user_id))
            else:
                cursor.execute('UPDATE users SET username = %s, email = %s, notes = %s, role = %s WHERE id = %s',
                               (username, email, notes, role, user_id))

            conn.commit()
            cursor.close()
            conn.close()
            return redirect(url_for('admin'))

        cursor.close()
        conn.close()
        return render_template('edit_user.html', user=user)
    
    return redirect(url_for('index'))


@app.route('/upload_avatar', methods=['POST'])
def upload_avatar():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    user_id = session['user_id']
    file = request.files.get('avatar')

    if not file or file.filename == '':
        return redirect(url_for('profile'))

    allowed_extensions = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
    ext = file.filename.rsplit('.', 1)[-1].lower()

    if ext not in allowed_extensions:
        return redirect(url_for('profile'))

    filename = f"user_{user_id}.{ext}"
    upload_folder = os.path.join('static', 'avatars')
    os.makedirs(upload_folder, exist_ok=True)

    filepath = os.path.join(upload_folder, filename)
    file.save(filepath)

    # Avatar-Pfad in der DB speichern
    avatar_url = f"/static/avatars/{filename}"

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET avatar_path = %s WHERE id = %s", (avatar_url, user_id))
    conn.commit()
    cursor.close()
    conn.close()

    return redirect(url_for('profile'))


# <------------------------------------Routes-für-Artikel-funktionen---------------------------------------------->


@app.route('/edit_article', methods=['POST'])
def edit_article():
    if not session.get('logged_in') or session.get('role') not in ['admin', 'editor']:
        return jsonify({'success': False, 'message': 'Nicht autorisiert'}), 403

    data = request.get_json()
    article_id = data.get('id')
    title = data.get('title')
    text = data.get('text')

    if not article_id or not title or not text:
        return jsonify({'success': False, 'message': 'Ungültige Daten'}), 400

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE articles
            SET title = %s, text = %s
            WHERE id = %s
        """, (title, text, article_id))

        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({'success': True})

    except Exception as e:
        print("Fehler beim Bearbeiten:", e)
        return jsonify({'success': False, 'message': 'Serverfehler'}), 500


@app.route('/get_articles')
def get_articles():
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT id, title, text, category FROM articles ORDER BY created_at DESC")
        articles = cursor.fetchall()

        for article in articles:
            cursor.execute("SELECT image FROM article_images WHERE article_id = %s", (article['id'],))
            images = cursor.fetchall()
            image_urls = []
            for img in images:
                base64_image = base64.b64encode(img['image']).decode('utf-8')
                image_urls.append(f"data:image/jpeg;base64,{base64_image}")
            article['image_urls'] = image_urls

        cursor.close()
        conn.close()

        return jsonify(articles)
    except Exception as e:
        print("Fehler beim Abrufen der Artikel:", e)
        return jsonify([]), 500

import base64

@app.route('/create_article', methods=['POST'])
def create_article():
    if not session.get('logged_in') or session.get('role') not in ['admin', 'editor']:
        return jsonify({'success': False, 'message': 'Nicht autorisiert'}), 403

    title = request.form.get('title')
    text = request.form.get('text')
    category = request.form.get('category')
    images = request.files.getlist('images')

    if not title or not text or not category:
        return jsonify({'success': False, 'message': 'Fehlende Felder'}), 400

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Artikel speichern
        cursor.execute("""
            INSERT INTO articles (title, text, category)
            VALUES (%s, %s, %s)
        """, (title, text, category))
        article_id = cursor.lastrowid

        # Bilder speichern
        for image_file in images:
            if image_file:
                image_data = image_file.read()
                cursor.execute("""
                    INSERT INTO article_images (article_id, image)
                    VALUES (%s, %s)
                """, (article_id, image_data))

        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({'success': True})
    except Exception as e:
        print("Fehler beim Speichern des Artikels:", e)
        return jsonify({'success': False, 'message': 'Serverfehler'}), 500


# <--------------------------------------Routes-für-Kommentare-und-Likes------------------------------------------->


@app.route('/like_article', methods=['POST'])
def like_article():
    if not session.get('logged_in'):
        return jsonify({'success': False, 'message': 'Nicht eingeloggt'}), 403
    data = request.get_json()
    user_id = session['user_id']
    article_id = data.get('article_id')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM article_likes WHERE user_id = %s AND article_id = %s", (user_id, article_id))
    exists = cursor.fetchone()

    if exists:
        cursor.execute("DELETE FROM article_likes WHERE user_id = %s AND article_id = %s", (user_id, article_id))
        action = 'unliked'
    else:
        cursor.execute("INSERT INTO article_likes (user_id, article_id) VALUES (%s, %s)", (user_id, article_id))
        action = 'liked'

    conn.commit()
    cursor.close()
    conn.close()
    return jsonify({'success': True, 'action': action})


@app.route('/comment_article', methods=['POST'])
def comment_article():
    if not session.get('logged_in'):
        return jsonify({'success': False}), 403

    data = request.get_json()
    user_id = session['user_id']
    article_id = data.get('article_id')
    comment = data.get('comment')

    if not comment:
        return jsonify({'success': False, 'message': 'Kein Kommentar erhalten'}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO article_comments (user_id, article_id, comment) VALUES (%s, %s, %s)", (user_id, article_id, comment))
    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({'success': True})


@app.route('/get_comments')
def get_comments():
    article_id = request.args.get('article_id', type=int)
    if not article_id:
        return jsonify([])

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT c.comment, c.created_at, u.username
        FROM article_comments c
        JOIN users u ON c.user_id = u.id
        WHERE c.article_id = %s
        ORDER BY c.created_at ASC
    """, (article_id,))

    comments = cursor.fetchall()

    cursor.close()
    conn.close()

    return jsonify(comments)


@app.route('/delete_comment/<int:comment_id>', methods=['DELETE'])
def delete_comment(comment_id):
    if not session.get('logged_in'):
        return jsonify({'success': False}), 403

    user_id = session['user_id']
    is_admin = session.get('role') == 'admin'

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT user_id FROM article_comments WHERE id = %s", (comment_id,))
    comment = cursor.fetchone()

    if not comment:
        cursor.close()
        conn.close()
        return jsonify({'success': False, 'message': 'Nicht gefunden'}), 404

    if comment['user_id'] != user_id and not is_admin:
        cursor.close()
        conn.close()
        return jsonify({'success': False, 'message': 'Nicht erlaubt'}), 403

    cursor.execute("DELETE FROM article_comments WHERE id = %s", (comment_id,))
    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({'success': True})


if __name__ == '__main__':
    create_database()
    initialize_database()
    migrate_add_avatar_path_column()  # <-- das hier fehlt noch
    app.run(host='0.0.0.0', port=5000, debug=True)
