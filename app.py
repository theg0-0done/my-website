from werkzeug.security import check_password_hash
from flask import Flask, flash, render_template, request, redirect, url_for, session, jsonify
import sqlite3
import secrets
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)

# Set a secret key
app.secret_key = secrets.token_hex(16)

# connect to database


def get_db():
    """
    Establishes a connection to the project.db SQLite database and returns the connection object.
    """
    conn = sqlite3.connect("project.db")
    conn.row_factory = sqlite3.Row
    return conn

# Route for the home page


@app.route("/index")
def index():
    return render_template("index.html")

# Errors route


@app.route("/error")
def error():
    return render_template("error.html")


# Route for the login page
@app.route("/")
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        # Validation
        if not username:
            return render_template("error.html", message="Must provide username.")
        elif not password:
            return render_template("error.html", message="Must provide password.")

        # Database query to fetch user details by username
        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        conn.close()

        # Check if user exists and password is correct
        if user and check_password_hash(user["password"], password):
            session["user_id"] = user["id"]
            flash(f"You're logged in as '{username}'!", "success")
            return redirect(url_for("index"))
        else:
            return render_template("error.html", message="Invalid username or password.")

    # Render the login form for GET requests
    return render_template("login.html")

# Route for register


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        # Validation
        if not username:
            return render_template("error.html", message="Username is required.")
        elif not password:
            return render_template("error.html", message="Password is required.")
        elif not confirm_password:
            return render_template("error.html", message="Password Confirmation is required.")
        elif password != confirm_password:
            return render_template("error.html", message="Passwords must match.")

        # Insert user into the database
        hashed_password = generate_password_hash(password)
        try:
            conn = get_db()
            conn.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, hashed_password)
            )
            conn.commit()
            conn.close()
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            return render_template("error.html", message="Username already exists.")

    # Render register page if GET request
    return render_template("register.html")


# Route to change password
@app.route("/change_password", methods=["GET", "POST"])
def change_password():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")

        # Validation
        if not username or not password or not new_password or not confirm_password:
            return render_template("error.html", message="All fields are required.")
        elif password == new_password:
            return render_template("error.html", message="New password must not match the current password.")
        elif new_password != confirm_password:
            return render_template("error.html", message="Passwords must match.")

        conn = get_db()
        user = conn.execute(
            "SELECT password FROM users WHERE username = ?", (username,)
        ).fetchone()

        if not user or not check_password_hash(user["password"], password):
            return render_template("error.html", message="Invalid current password.")

        hashed_new_password = generate_password_hash(new_password)
        result = conn.execute(
            "UPDATE users SET password = ? WHERE username = ?",
            (hashed_new_password, username)
        )
        conn.commit()
        conn.close()

        if result.rowcount == 0:
            return render_template("error.html", message="Password change failed.")

        # Flash success message
        flash("Password changed successfully!", "success")
        return redirect(url_for("index"))

    return render_template("change_password.html")


# Route to change password
@app.route("/personal", methods=["GET", "POST"])
def personal():
    if request.method == "POST":
        if request.is_json:
            data = request.get_json()

            # Extract task data from the request
            task_name = data['task_name']
            task_type = data['task_type']
            deadline = data['deadline']
            description = data['description']
            done = data['done']

            # Get the user_id from the session
            user_id = session.get('user_id')
            if not user_id:
                return jsonify({"status": "error", "message": "User not logged in"})

            # Save the task to the database
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute('''INSERT INTO tasks (user_id, done, task_name, task_type, deadline, description, type)
                              VALUES (?, ?, ?, ?, ?, ?, ?)''',
                           (user_id, done, task_name, task_type, deadline, description, 'personal'))
            conn.commit()

            return jsonify({"status": "success", "message": "Task saved successfully"})

    # Fetch tasks for the logged-in user
    user_id = session.get('user_id')
    if user_id:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM tasks WHERE user_id = ? AND type = 'personal'", (user_id,))
        tasks = cursor.fetchall()
        return render_template("personal.html", tasks=tasks)

    return render_template("personal.html")


@app.route("/work", methods=["GET", "POST"])
def work():
    if request.method == "POST":
        if request.is_json:
            data = request.get_json()

            task_name = data['task_name']
            task_type = data['task_type']
            deadline = data['deadline']
            description = data['description']
            done = data['done']

            user_id = session.get('user_id')
            if not user_id:
                return jsonify({"status": "error", "message": "User not logged in"})

            conn = get_db()
            cursor = conn.cursor()
            cursor.execute('''INSERT INTO tasks (user_id, done, task_name, task_type, deadline, description, type)
                              VALUES (?, ?, ?, ?, ?, ?, ?)''',
                           (user_id, done, task_name, task_type, deadline, description, 'work'))
            conn.commit()

            return jsonify({"status": "success", "message": "Task saved successfully"})

    user_id = session.get('user_id')
    if user_id:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM tasks WHERE user_id = ? AND type = 'work'", (user_id,))
        tasks = cursor.fetchall()
        return render_template("work.html", tasks=tasks)

    return render_template("work.html")


@app.route("/study", methods=["GET", "POST"])
def study():
    if request.method == "POST":
        if request.is_json:
            data = request.get_json()

            task_name = data['task_name']
            task_type = data['task_type']
            deadline = data['deadline']
            description = data['description']
            done = data['done']

            user_id = session.get('user_id')
            if not user_id:
                return jsonify({"status": "error", "message": "User not logged in"})

            conn = get_db()
            cursor = conn.cursor()
            cursor.execute('''INSERT INTO tasks (user_id, done, task_name, task_type, deadline, description, type)
                              VALUES (?, ?, ?, ?, ?, ?, ?)''',
                           (user_id, done, task_name, task_type, deadline, description, 'study'))
            conn.commit()

            return jsonify({"status": "success", "message": "Task saved successfully"})

    user_id = session.get('user_id')
    if user_id:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM tasks WHERE user_id = ? AND type = 'study'", (user_id,))
        tasks = cursor.fetchall()
        return render_template("study.html", tasks=tasks)

    return render_template("study.html")


@app.route("/else", methods=["GET", "POST"])
def alse():
    if request.method == "POST":
        if request.is_json:
            data = request.get_json()

            task_name = data['task_name']
            task_type = data['task_type']
            deadline = data['deadline']
            description = data['description']
            done = data['done']

            user_id = session.get('user_id')

            if not user_id:
                return jsonify({"status": "error", "message": "User not logged in"})

            conn = get_db()
            cursor = conn.cursor()
            cursor.execute('''INSERT INTO tasks (user_id, done, task_name, task_type, deadline, description, type)
                              VALUES (?, ?, ?, ?, ?, ?, ?)''',
                           (user_id, done, task_name, task_type, deadline, description, 'else'))
            conn.commit()

            return jsonify({"status": "success", "message": "Task saved successfully"})

    user_id = session.get('user_id')
    if user_id:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM tasks WHERE user_id = ? AND type = 'else'", (user_id,))
        tasks = cursor.fetchall()
        return render_template("else.html", tasks=tasks)

    return render_template("else.html")


@app.route('/update_task_status', methods=['POST'])
def update_task_status():
    data = request.json
    task_id = data.get('id')  # Get `id` from the request
    done = data.get('done')  # Get `done` state

    if task_id is None or done is None:
        return jsonify({'error': 'Invalid data'}), 400

    # Update the task in the database
    try:
        db = get_db()
        db.execute("UPDATE tasks SET done = ? WHERE id = ?", (int(done), task_id))
        db.commit()
        return jsonify({'message': 'Task updated successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route("/logout")
def logout():
    session.clear()  # Clear the session
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True)
