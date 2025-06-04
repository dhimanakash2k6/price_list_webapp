import os
import json
import re
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
import mysql.connector
from flask_wtf.csrf import CSRFProtect ,validate_csrf
from flask_wtf import csrf
from flask_mail import Mail, Message
import pandas as pd
from flask_bcrypt import Bcrypt
from flask import make_response
from fpdf import FPDF
from datetime import datetime
from functools import wraps
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email
from forms import SignupForm


app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'your-local-secret-key')  # Use a secure key
csrf = CSRFProtect(app)
bcrypt = Bcrypt(app)

# Email configuration (optional, disable if not needed)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME', 'dhimanakashmls@gmail.com')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD', 'gahk utos lkvo tlwy')  # Fixed missing quote
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_USERNAME', 'dhimanakashmls@gmail.com')
mail = Mail(app)

# MySQL database configuration
db_config = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'user': os.getenv('DB_USER', 'root'),
    'password': os.getenv('DB_PASSWORD', 'MLS@5002hd'),
    'database': os.getenv('DB_NAME', 'price_list')
}

# Function to get MySQL connection
def get_db_connection():
    return mysql.connector.connect(**db_config)

# Validate part ID format
def validate_part_id(part_id):
    return bool(re.match(r'^P\d+$', part_id))

# Utility to fetch model names
def get_sheet_names():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT name FROM models')
    models = [row[0] for row in cursor.fetchall()]
    cursor.close()
    conn.close()
    return models

def permission_required(permission_key):
    def decorator(view_func):
        @wraps(view_func)
        def wrapped_view(*args, **kwargs):
            if 'username' not in session or not session.get('permissions', {}).get(permission_key, False):
                flash("Access denied: You don't have permission to access this page.", "danger")
                return redirect(url_for('index'))  # or wherever you want to send the user
            return view_func(*args, **kwargs)
        return wrapped_view
    return decorator

def log_action(username, action):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO audit_logs (username, action) VALUES (%s, %s)",
            (username, action)
        )
        conn.commit()
        print(f"[Audit Log] {username}: {action}")  # 👈 helpful debug print
    except Exception as e:
        print(f"[Audit Log Error] {e}")  # 👈 print error if logging fails
    finally:
        conn.close()



@app.route("/")
def index():
    models = get_sheet_names()
    if 'username' in session:
        return render_template("home.html", message=f"Welcome, {session['username']}!", models=models, logged_in=True)
    return render_template("home.html", models=models, logged_in=False, message="Welcome to the Price List WebApp! Please log in to access more features.")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        print(f"Attempting login for username: {username}, password: {password}")

        try:
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)

            # Fetch user details
            cursor.execute('SELECT * FROM users WHERE username = %s AND is_approved = TRUE', (username,))
            user = cursor.fetchone()
            print(f"User fetched: {user}")

            if user:
                is_password_valid = False

                # Verify password
                if user['password'].startswith('$2b$'):
                    is_password_valid = bcrypt.check_password_hash(user['password'], password)
                else:
                    is_password_valid = (user['password'] == password)

                if is_password_valid:
                    session['username'] = username
                    session['role'] = user['role']    

                    # Load permissions only for non-admins
                    session['permissions'] = {}

                    if user['role'] != 'admin':
                        user_id = user['id']

                        cursor.execute("""
                            SELECT can_view_models, can_view_parts, can_view_prices
                            FROM user_permissions
                            WHERE user_id = %s
                        """, (user_id,))
                        permissions = cursor.fetchone()

                        if permissions:
                            session['permissions'] = {
                                'can_view_models': bool(permissions['can_view_models']),
                                'can_view_parts': bool(permissions['can_view_parts']),
                                'can_view_prices': bool(permissions['can_view_prices'])
                            }

                    flash(f'Welcome, {username}!', 'success')
                    print(f"Login successful: {username}, role: {user['role']}")

                     # ✅ Log the login action
                    log_action(username, "Logged in")

                    if user['role'] == 'admin':
                        return redirect(url_for('admin_dashboard'))
                    elif user['username'].startswith("account_"):
                        return redirect(url_for('inventory_dashboard'))
                    else:
                        return redirect(url_for('post_login'))
                    


            flash('Invalid credentials or unapproved user.', 'danger')
            print(f"Login failed for {username}: Invalid credentials or unapproved.")

        except mysql.connector.Error as e:
            flash(f'Error logging in: {str(e)}', 'danger')
            print(f"MySQL error: {e}")

        finally:
            conn.close()

    return render_template('login.html')



@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        account_name = form.account_name.data
        password = form.password.data
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        account_name = request.form['account_name']
        password = request.form['password']
        print(f"Signup attempt: {username}, {email}, {account_name}")
        try:
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)
            cursor.execute('SELECT * FROM users WHERE username = %s OR email = %s', (username, email))
            existing_user = cursor.fetchone()
            cursor.execute('SELECT * FROM signup_requests WHERE username = %s OR email = %s', (username, email))
            existing_request = cursor.fetchone()
            if existing_user or existing_request:
                flash('Username or email already exists.', 'danger')
                conn.close()
                return redirect(url_for('signup'))
            cursor.execute(
                'INSERT INTO signup_requests (username, email, account_name, password, status) VALUES (%s, %s, %s, %s, %s)',
                (username, email, account_name, password, 'pending')
            )
            conn.commit()
            try:
                msg = Message('New Signup Request', recipients=[app.config['MAIL_USERNAME']])
                msg.body = f'New signup request:\nUsername: {username}\nEmail: {email}\nAccount: {account_name}'
                mail.send(msg)
                flash('Signup request sent. Please wait for approval.', 'success')
            except Exception as e:
                flash(f'Email notification failed: {str(e)}', 'warning')
                print(f"Email error: {str(e)}")
            conn.close()
            return redirect(url_for('login'))
        except mysql.connector.Error as e:
            flash(f'Database error: {str(e)}', 'danger')
            print(f"Signup database error: {str(e)}")
            conn.close()
            return redirect(url_for('signup'))
    return render_template('signup.html', form=form)

@app.route("/logout")
def logout():
    username = session.get('username')  # Get it before popping
    if username:
        log_action(username, "Logged out")

    session.pop('username', None)
    session.pop('role', None)
    session.pop('permissions', None)  # Optional: remove permissions too

    return redirect(url_for('index'))


@app.route("/get_models")
def get_models():
    models = get_sheet_names()
    return jsonify({"models": models})

@app.route("/get_customers", methods=["POST"])
@csrf.exempt
def get_customers():
    model = request.form.get("model")
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM models WHERE name = %s', (model,))
    model_id = cursor.fetchone()
    if not model_id:
        conn.close()
        return jsonify({"customers": []})
    model_id = model_id[0]
    cursor.execute('''
        SELECT DISTINCT customers.name
        FROM customer_prices
        JOIN parts ON customer_prices.part_id = parts.id
        JOIN customers ON customer_prices.customer_id = customers.id
        WHERE parts.model_id = %s
    ''', (model_id,))
    customers = [row[0] for row in cursor.fetchall()]
    conn.close()
    return jsonify({"customers": customers})

@app.route("/get_price_list", methods=["POST"])
@csrf.exempt
def get_price_list():
    model = request.form.get("model")
    customer = request.form.get("customer")
    filter_part = request.form.get("filter_part")
    if customer and customer != "Retail Price" and 'username' not in session:
        return jsonify({"price_list": "Please login to view customer prices."})
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM models WHERE name = %s', (model,))
    model_id = cursor.fetchone()
    if not model_id:
        conn.close()
        return jsonify({"price_list": f"No parts found for model '{model}'."})
    model_id = model_id[0]
    query = '''
        SELECT parts.part_id, parts.part_name, parts.retail_price,
        customer_prices.price as customer_price
        FROM parts
        LEFT JOIN customer_prices ON parts.id = customer_prices.part_id
        LEFT JOIN customers ON customer_prices.customer_id = customers.id
        AND customers.name = %s
        WHERE parts.model_id = %s
    '''
    params = (customer if customer and customer != "Retail Price" else None, model_id)
    if filter_part:
        if " - " in filter_part:
            filter_part = filter_part.split(" - ")[0]
        query += ' AND (parts.part_id LIKE %s OR parts.part_name LIKE %s)'
        params += ('%' + filter_part + '%', '%' + filter_part + '%')
    cursor.execute(query, params)
    rows = cursor.fetchall()
    html = ["<table class='table table-striped'><tr><th>Part ID</th><th>Part Name</th><th>Retail Price</th>"]
    if customer and customer != "Retail Price" and 'username' in session:
        html.append("<th>Customer Price</th>")
    html.append("</tr>")
    for row in rows:
        html.append("<tr>")
        html.append(f"<td>{row[0]}</td>")
        html.append(f"<td>{row[1]}</td>")
        html.append(f"<td>{row[2]}</td>")
        if customer and customer != "Retail Price" and 'username' in session:
            html.append(f"<td>{row[3] if row[3] else ''}</td>")
        html.append("</tr>")
    html.append("</table>")
    conn.close()
    return jsonify({"price_list": "".join(html)})

@app.route("/add_customer", methods=["POST"])
@csrf.exempt
def add_customer():
    if 'username' not in session or session.get('role') != 'admin':
        return jsonify({"message": "Unauthorized. Admins only.", "success": False})
    model = request.form.get("model")
    customer = request.form.get("customer")
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM customers WHERE name = %s', (customer,))
    if cursor.fetchone():
        conn.close()
        return jsonify({"message": f"Customer '{customer}' already exists.", "success": False})
    cursor.execute('SELECT id FROM models WHERE name = %s', (model,))
    model_id = cursor.fetchone()
    if not model_id:
        conn.close()
        return jsonify({"message": f"Model '{model}' not found.", "success": False})
    model_id = model_id[0]
    cursor.execute('SELECT id FROM parts WHERE model_id = %s LIMIT 1', (model_id,))
    part_exists = cursor.fetchone()
    if not part_exists:
        conn.close()
        return jsonify({"message": "no_parts", "model": model, "success": False})
    cursor.execute('INSERT INTO customers (name) VALUES (%s)', (customer,))
    customer_id = cursor.lastrowid
    cursor.execute('SELECT id, retail_price FROM parts WHERE model_id = %s', (model_id,))
    parts = cursor.fetchall()
    for part_id, retail_price in parts:
        cursor.execute('INSERT INTO customer_prices (part_id, customer_id, price) VALUES (%s, %s, %s) ON DUPLICATE KEY UPDATE price = VALUES(price)', 
                      (part_id, customer_id, retail_price or 0.00))
    conn.commit()
    conn.close()
    return jsonify({"message": f"Customer '{customer}' added with default prices.", "success": True})

@app.route("/add_customer_prices/<customer_name>", methods=["GET", "POST"])
@csrf.exempt
def add_customer_prices(customer_name):
    if 'username' not in session or session.get('role') != 'admin':
        flash('Unauthorized. Admins only.', 'danger')
        return redirect(url_for('login'))
    model = request.form.get("model") or request.args.get("model")
    if not model:
        return redirect(url_for("add_customer_view"))
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM models WHERE name = %s', (model,))
    model_id = cursor.fetchone()
    if not model_id:
        conn.close()
        return redirect(url_for("add_customer_view"))
    model_id = model_id[0]
    cursor.execute('SELECT id FROM customers WHERE name = %s', (customer_name,))
    customer_id = cursor.fetchone()
    if not customer_id:
        conn.close()
        return redirect(url_for("add_customer_view"))
    customer_id = customer_id[0]
    cursor.execute('''
        SELECT parts.id, parts.part_id, parts.part_name, parts.retail_price,
        customer_prices.price as customer_price
        FROM parts
        LEFT JOIN customer_prices ON parts.id = customer_prices.part_id
        AND customer_prices.customer_id = %s
        WHERE parts.model_id = %s
    ''', (customer_id, model_id))
    parts_data = cursor.fetchall()
    headers = ["Part ID", "Part Name", "Retail Price", customer_name]
    parts = [[row[1], row[2], str(row[3]), str(row[4] if row[4] is not None else '')] for row in parts_data]
    df = pd.DataFrame(parts, columns=headers)
    if request.method == "POST":
        prices = request.form.getlist("prices[]")
        for i, price in enumerate(prices):
            if price and price.replace('.', '').isdigit():
                part_id = parts_data[i][0]
                cursor.execute('INSERT INTO customer_prices (part_id, customer_id, price) VALUES (%s, %s, %s) ON DUPLICATE KEY UPDATE price = VALUES(price)', 
                              (part_id, customer_id, float(price)))
        conn.commit()
        conn.close()
        return render_template("add_customer_prices.html", model=model, customer_name=customer_name, df=df, message="Successfully updated!")
    conn.close()
    return render_template("add_customer_prices.html", model=model, customer_name=customer_name, df=df)

@app.route("/update_prices", methods=["POST"])
@csrf.exempt
def update_prices():
    if 'username' not in session or session.get('role') != 'admin':
        return jsonify({"message": "Unauthorized. Admins only.", "success": False})
    model = request.form.get("model")
    customer = request.form.get("customer")
    prices = request.form.getlist("prices[]")
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM models WHERE name = %s', (model,))
    model_id = cursor.fetchone()
    if not model_id:
        conn.close()
        return jsonify({"message": "Model not found."})
    model_id = model_id[0]
    cursor.execute('SELECT id FROM customers WHERE name = %s', (customer,))
    customer_id = cursor.fetchone()
    if not customer_id:
        conn.close()
        return jsonify({"message": "Customer not found."})
    customer_id = customer_id[0]
    cursor.execute('SELECT id FROM parts WHERE model_id = %s', (model_id,))
    part_ids = [row[0] for row in cursor.fetchall()]
    for i, price in enumerate(prices):
        if price and price.replace('.', '').isdigit():
            part_id = part_ids[i]
            cursor.execute('INSERT INTO customer_prices (part_id, customer_id, price) VALUES (%s, %s, %s) ON DUPLICATE KEY UPDATE price = VALUES(price)', 
                          (part_id, customer_id, float(price)))
    conn.commit()
    conn.close()
    return jsonify({"message": "Prices updated."})

@app.route("/add_model", methods=["POST"])
@csrf.exempt
def add_model():
    if 'username' not in session or session.get('role') != 'admin':
        return jsonify({"message": "Unauthorized. Admins only.", "success": False})
    model = request.form.get("model")
    part_ids = request.form.getlist("part_ids[]")
    part_names = request.form.getlist("part_names[]")
    retail_prices = request.form.getlist("retail_prices[]")
    if not model or not part_ids or not all(part_ids) or not all(part_names) or not all(retail_prices):
        return jsonify({"message": "All part fields must be filled.", "success": False})

    if len(part_ids) != len(set(part_ids)):
        return jsonify({"success": False, "message": "Duplicate Part IDs are not allowed"})
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM models WHERE name = %s', (model,))
    if cursor.fetchone():
        conn.close()
        return jsonify({"message": f"Model '{model}' already exists.", "success": False})
    cursor.execute('INSERT INTO models (name) VALUES (%s)', (model,))
    model_id = cursor.lastrowid
    for part_id, part_name, price in zip(part_ids, part_names, retail_prices):
        try:
            price = float(price)
            cursor.execute('INSERT INTO parts (model_id, part_id, part_name, retail_price) VALUES (%s, %s, %s, %s)', 
                          (model_id, part_id, part_name, price))
        except ValueError:
            conn.rollback()
            conn.close()
            return jsonify({"message": "Retail price must be a valid number.", "success": False})
    conn.commit()
    conn.close()
    return jsonify({"message": f"Model '{model}' added with parts.", "success": True})

@app.route("/get_part_suggestions", methods=["POST"])
@csrf.exempt
def get_part_suggestions():
    model = request.form.get("model")
    term = request.form.get("term")
    if not model or not term:
        return jsonify({"suggestions": []})
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM models WHERE name = %s', (model,))
    model_id = cursor.fetchone()
    if not model_id:
        conn.close()
        return jsonify({"suggestions": []})
    model_id = model_id[0]
    cursor.execute('SELECT CONCAT(part_id, " - ", part_name) FROM parts WHERE model_id = %s AND (part_id LIKE %s OR part_name LIKE %s)', 
                  (model_id, '%' + term + '%', '%' + term + '%'))
    suggestions = [row[0] for row in cursor.fetchall()]
    conn.close()
    return jsonify({"suggestions": suggestions})

@app.route("/add_spare_parts/<model>", methods=["GET", "POST"])
@csrf.exempt
def add_spare_parts(model):
    if 'username' not in session or session.get('role') != 'admin':
        flash('Unauthorized. Admins only.', 'danger')
        return redirect(url_for('login'))
    if request.method == "POST":
        part_id = request.form.get("part_id")
        part_name = request.form.get("part_name")
        retail_price = request.form.get("retail_price")
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM models WHERE name = %s', (model,))
        model_id = cursor.fetchone()
        if not model_id:
            conn.close()
            return jsonify({"success": False, "message": "Model not found"})
        model_id = model_id[0]
        cursor.execute('SELECT * FROM parts WHERE part_id = %s AND model_id = %s', (part_id, model_id))
        if cursor.fetchone():
            conn.close()
            return jsonify({"success": False, "message": "Part ID already exists for this model"})
        try:
            retail_price = float(retail_price)
        except ValueError:
            conn.close()
            return jsonify({"success": False, "message": "Retail price must be a valid number"})
        cursor.execute('INSERT INTO parts (model_id, part_id, part_name, retail_price) VALUES (%s, %s, %s, %s)', 
                      (model_id, part_id, part_name, retail_price))
        conn.commit()
        conn.close()
        return jsonify({"success": True, "message": "Part added successfully!"})
    return render_template("add_spare_parts.html", model=model)

@app.route("/edit_spare_part/<int:part_id>", methods=["POST"])
@csrf.exempt
def edit_spare_part(part_id):
    if 'username' not in session or session.get('role') != 'admin':
        return jsonify({"message": "Unauthorized. Admins only.", "success": False})
    part_name = request.form.get("part_name")
    retail_price = request.form.get("retail_price")
    try:
        retail_price = float(retail_price)
    except ValueError:
        return jsonify({"success": False, "message": "Retail price must be a valid number"})
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('UPDATE parts SET part_name = %s, retail_price = %s WHERE id = %s', 
                  (part_name, retail_price, part_id))
    conn.commit()
    conn.close()
    return jsonify({"success": True, "message": "Part updated successfully!"})

@app.route("/get_spare_parts/<model>")
def get_spare_parts(model):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM models WHERE name = %s', (model,))
    model_id = cursor.fetchone()
    if not model_id:
        conn.close()
        return jsonify({"parts": []})
    model_id = model_id[0]
    cursor.execute('SELECT id, part_id, part_name, retail_price FROM parts WHERE model_id = %s', (model_id,))
    parts = [{"id": row[0], "part_id": row[1], "part_name": row[2], "retail_price": row[3]} for row in cursor.fetchall()]
    conn.close()
    return jsonify({"parts": parts})

@app.route('/price_list')
def price_list():
    models = get_sheet_names()
    if 'username' in session:
        return render_template('price_list.html', models=models, logged_in=True)
    return render_template('price_list.html', models=models, logged_in=False)

@app.route('/price_list_view')
def price_list_view():
    models = get_sheet_names()
    if 'username' in session:
        return render_template('price_list_view.html', models=models, logged_in=True)
    return render_template('price_list_view.html', models=models, logged_in=False)

@app.route("/add_customer_view")
def add_customer_view():
    if 'username' not in session or session.get('role') != 'admin':
        flash('Unauthorized. Admins only.', 'danger')
        return redirect(url_for('login'))
    return render_template("add_customer.html")

@app.route("/add_model_view")
def add_model_view():
    if 'username' not in session or session.get('role') != 'admin':
        flash('Unauthorized. Admins only.', 'danger')
        return redirect(url_for('login'))
    return render_template("add_model.html")

@app.route('/admin_dashboard')
def admin_dashboard():
    if 'username' not in session or session.get('role') != 'admin':
        flash("Unauthorized. Admins only.", "danger")
        return redirect(url_for('login'))
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute('SELECT * FROM signup_requests WHERE status = "pending"')
        signup_requests = cursor.fetchall()
        cursor.execute('SELECT * FROM users WHERE username != "admin"')
        approved_users = cursor.fetchall()
        print(f"Signup requests fetched: {signup_requests}")
        print(f"Approved users (except admin): {approved_users}")
        conn.close()
        return render_template('admin_dashboard.html', signup_requests=signup_requests, approved_users=approved_users)
    except mysql.connector.Error as e:
        flash(f'Error fetching data: {str(e)}', 'danger')
        return redirect(url_for('index'))



@app.route("/approve_signup/<int:request_id>", methods=["POST"])
def approve_signup(request_id):
    if 'username' not in session or session.get('role') != 'admin':
        return jsonify({"success": False, "message": "Unauthorized"})
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute('SELECT * FROM signup_requests WHERE id = %s', (request_id,))
        request_data = cursor.fetchone()
        if request_data:
            hashed_password = bcrypt.generate_password_hash(request_data['password']).decode('utf-8')
            cursor.execute('INSERT INTO users (username, email, account_name, password, role, is_approved) VALUES (%s, %s, %s, %s, %s, TRUE)',
                          (request_data['username'], request_data['email'], request_data['account_name'], hashed_password, 'user'))
            cursor.execute('DELETE FROM signup_requests WHERE id = %s', (request_id,))
            try:
                msg = Message('Account Approved', recipients=[request_data['email']])
                msg.body = f'Your account {request_data["username"]} has been approved. You can now login and access all features.'
                mail.send(msg)
                flash('User approved and email sent.', 'success')
            except Exception as e:
                print(f"Email error: {str(e)}")
                flash('User approved, but email failed to send.', 'warning')
            conn.commit()
        else:
            flash(f'Request {request_id} not found.', 'danger')
    except mysql.connector.Error as e:
        conn.rollback()
        flash(f'Error approving request: {str(e)}', 'danger')
    finally:
        cursor.close()
        conn.close()
    return redirect(url_for('admin_dashboard'))  # Changed to redirect for consistency

@app.route("/reject_request/<int:request_id>", methods=["POST"])
def reject_request(request_id):
    if 'username' not in session or session.get('role') != 'admin':
        flash('Unauthorized. Admins only.', 'danger')
        return redirect(url_for('login'))
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute('SELECT username, email FROM signup_requests WHERE id = %s', (request_id,))
        request_data = cursor.fetchone()
        if not request_data:
            flash(f'Request {request_id} not found.', 'danger')
            conn.close()
            return redirect(url_for('admin_dashboard'))
        cursor.execute('DELETE FROM signup_requests WHERE id = %s', (request_id,))
        rows_affected = cursor.rowcount
        if rows_affected == 0:
            flash(f'Failed to reject request {request_id}.', 'danger')
        else:
            try:
                msg = Message('Account Request Rejected', recipients=[request_data['email']])
                msg.body = f'Hello {request_data["username"]},\n\nYour account request has been rejected.\n\nBest regards,\nPrice List WebApp Team'
                mail.send(msg)
                flash('Request rejected and email sent.', 'success')
            except Exception as e:
                print(f"Email error: {str(e)}")
                flash('Request rejected, but email failed to send.', 'warning')
        conn.commit()
    except mysql.connector.Error as e:
        conn.rollback()
        flash(f'Error rejecting request: {str(e)}', 'danger')
    finally:
        cursor.close()
        conn.close()
    return redirect(url_for('admin_dashboard'))

@app.route('/delete_all_users_except_admin', methods=['POST'])
@csrf.exempt
def delete_all_users_except_admin():
    if 'username' not in session or session.get('role') != 'admin':
        flash('Unauthorized. Admins only.', 'danger')
        return redirect(url_for('login'))
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM users WHERE username != "admin"')
        rows_affected = cursor.rowcount
        conn.commit()
        flash(f'Successfully deleted {rows_affected} users (admin retained).', 'success')
    except mysql.connector.Error as e:
        flash(f'Error deleting users: {str(e)}', 'danger')
    finally:
        conn.close()
    return redirect(url_for('admin_dashboard'))

@app.route('/delete_user/<username>', methods=['POST'])
@csrf.exempt
def delete_user(username):
    if 'username' not in session or session.get('role') != 'admin':
        flash('Unauthorized. Admins only.', 'danger')
        return redirect(url_for('login'))
    if username == 'admin':
        flash('Cannot delete the admin user.', 'danger')
        return redirect(url_for('admin_dashboard'))
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM users WHERE username = %s', (username,))
        rows_affected = cursor.rowcount
        conn.commit()
        if rows_affected > 0:
            flash(f'User {username} deleted successfully.', 'success')
        else:
            flash(f'User {username} not found.', 'danger')
    except mysql.connector.Error as e:
        flash(f'Error deleting user: {str(e)}', 'danger')
    finally:
        conn.close()
    return redirect(url_for('admin_dashboard'))

@app.route("/get_all_models", methods=["GET"])
def get_all_models():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM models")
    models = cursor.fetchall()
    conn.close()
    return jsonify(models)

@app.route("/admin_add_model", methods=["POST"])
@csrf.exempt
def admin_add_model():
    if 'username' not in session or session.get('role') != 'admin':
        return jsonify({"success": False, "message": "Unauthorized"})
    model_name = request.form.get("model_name")
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO models (name) VALUES (%s)", (model_name,))
        conn.commit()
        return jsonify({"success": True, "message": f"Model '{model_name}' added successfully."})
    except mysql.connector.Error as err:
        conn.rollback()
        return jsonify({"success": False, "message": f"Error: {str(err)}"})
    finally:
        conn.close()

@app.route("/admin_edit_model/<int:model_id>", methods=["POST"])
@csrf.exempt
def admin_edit_model(model_id):
    if 'username' not in session or session.get('role') != 'admin':
        return jsonify({"success": False, "message": "Unauthorized"})
    new_name = request.form.get("model_name")
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("UPDATE models SET name = %s WHERE id = %s", (new_name, model_id))
        conn.commit()
        return jsonify({"success": True, "message": f"Model updated to '{new_name}'."})
    except mysql.connector.Error as err:
        conn.rollback()
        return jsonify({"success": False, "message": f"Error: {str(err)}"})
    finally:
        conn.close()

@app.route("/admin_delete_model/<int:model_id>", methods=["POST"])
@csrf.exempt
def admin_delete_model(model_id):
    if 'username' not in session or session.get('role') != 'admin':
        return jsonify({"success": False, "message": "Unauthorized"})
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM parts WHERE model_id = %s", (model_id,))
        cursor.execute("DELETE FROM models WHERE id = %s", (model_id,))
        conn.commit()
        return jsonify({"success": True, "message": "Model deleted successfully."})
    except mysql.connector.Error as err:
        conn.rollback()
        return jsonify({"success": False, "message": f"Error: {str(err)}"})
    finally:
        conn.close()

@app.route("/get_all_customers", methods=["GET"])
def get_all_customers():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM customers")
    customers = cursor.fetchall()
    conn.close()
    return jsonify(customers)

@app.route("/admin_add_customer", methods=["POST"])
@csrf.exempt
def admin_add_customer():
    if 'username' not in session or session.get('role') != 'admin':
        return jsonify({"success": False, "message": "Unauthorized"})
    customer_name = request.form.get("customer_name")
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO customers (name) VALUES (%s)", (customer_name,))
        conn.commit()
        return jsonify({"success": True, "message": f"Customer '{customer_name}' added successfully."})
    except mysql.connector.Error as err:
        conn.rollback()
        return jsonify({"success": False, "message": f"Error: {str(err)}"})
    finally:
        conn.close()

@app.route("/admin_edit_customer/<int:customer_id>", methods=["POST"])
@csrf.exempt
def admin_edit_customer(customer_id):
    if 'username' not in session or session.get('role') != 'admin':
        return jsonify({"success": False, "message": "Unauthorized"})
    new_name = request.form.get("customer_name")
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("UPDATE customers SET name = %s WHERE id = %s", (new_name, customer_id))
        conn.commit()
        return jsonify({"success": True, "message": f"Customer updated to '{new_name}'."})
    except mysql.connector.Error as err:
        conn.rollback()
        return jsonify({"success": False, "message": f"Error: {str(err)}"})
    finally:
        conn.close()

@app.route("/admin_delete_customer/<int:customer_id>", methods=["POST"])
@csrf.exempt
def admin_delete_customer(customer_id):
    if 'username' not in session or session.get('role') != 'admin':
        return jsonify({"success": False, "message": "Unauthorized"})
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM customer_prices WHERE customer_id = %s", (customer_id,))
        cursor.execute("DELETE FROM customers WHERE id = %s", (customer_id,))
        conn.commit()
        return jsonify({"success": True, "message": "Customer deleted successfully."})
    except mysql.connector.Error as err:
        conn.rollback()
        return jsonify({"success": False, "message": f"Error: {str(err)}"})
    finally:
        conn.close()

@app.route("/get_all_parts", methods=["GET"])
def get_all_parts():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT p.*, m.name AS model_name
        FROM parts p
        JOIN models m ON p.model_id = m.id
    """)
    parts = cursor.fetchall()
    conn.close()
    return jsonify(parts)

@app.route("/admin_add_part", methods=["POST"])
@csrf.exempt
def admin_add_part():
    if 'username' not in session or session.get('role') != 'admin':
        return jsonify({"success": False, "message": "Unauthorized"})
    model_id = request.form.get("model_id")
    part_id = request.form.get("part_id")
    part_name = request.form.get("part_name")
    retail_price = request.form.get("retail_price")
    try:
        retail_price = float(retail_price)
    except ValueError:
        return jsonify({"success": False, "message": "Retail price must be a valid number"})
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO parts (model_id, part_id, part_name, retail_price)
            VALUES (%s, %s, %s, %s)
        """, (model_id, part_id, part_name, retail_price))
        conn.commit()
        return jsonify({"success": True, "message": f"Part '{part_id}' added successfully."})
    except mysql.connector.Error as err:
        conn.rollback()
        return jsonify({"success": False, "message": f"Error: {str(err)}"})
    finally:
        conn.close()

@app.route("/admin_edit_part/<int:part_id>", methods=["POST"])
@csrf.exempt
def admin_edit_part(part_id):
    if 'username' not in session or session.get('role') != 'admin':
        return jsonify({"success": False, "message": "Unauthorized"})
    model_id = request.form.get("model_id")
    new_part_id = request.form.get("part_id")
    part_name = request.form.get("part_name")
    retail_price = request.form.get("retail_price")
    try:
        retail_price = float(retail_price)
    except ValueError:
        return jsonify({"success": False, "message": "Retail price must be a valid number"})
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            UPDATE parts
            SET model_id = %s, part_id = %s, part_name = %s, retail_price = %s
            WHERE id = %s
        """, (model_id, new_part_id, part_name, retail_price, part_id))
        conn.commit()
        return jsonify({"success": True, "message": "Part updated successfully."})
    except mysql.connector.Error as err:
        conn.rollback()
        return jsonify({"success": False, "message": f"Error: {str(e)}"})
    finally:
        conn.close()

@app.route("/admin_delete_part/<int:part_id>", methods=["POST"])
@csrf.exempt
def admin_delete_part(part_id):
    if 'username' not in session or session.get('role') != 'admin':
        return jsonify({"success": False, "message": "Unauthorized"})
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM customer_prices WHERE part_id = %s", (part_id,))
        cursor.execute("DELETE FROM parts WHERE id = %s", (part_id,))
        conn.commit()
        return jsonify({"success": True, "message": "Part deleted successfully."})
    except mysql.connector.Error as err:
        conn.rollback()
        return jsonify({"success": False, "message": f"Error: {str(err)}"})
    finally:
        conn.close()

@app.route("/admin_delete_customer_price/<int:price_id>", methods=["POST"])
@csrf.exempt
def admin_delete_customer_price(price_id):
    if 'username' not in session or session.get('role') != 'admin':
        return jsonify({"success": False, "message": "Unauthorized"})
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM customer_prices WHERE id = %s", (price_id,))
        conn.commit()
        return jsonify({"success": True, "message": "Customer price deleted successfully."})
    except mysql.connector.Error as err:
        conn.rollback()
        return jsonify({"success": False, "message": f"Error: {str(err)}"})
    finally:
        conn.close()


@app.route("/get_all_customer_prices", methods=["GET"])
def get_all_customer_prices():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT cp.*, p.part_id, p.part_name, m.name AS model_name, c.name AS customer_name
        FROM customer_prices cp
        JOIN parts p ON cp.part_id = p.id
        JOIN models m ON p.model_id = m.id
        JOIN customers c ON cp.customer_id = c.id
    """)
    customer_prices = cursor.fetchall()
    conn.close()
    return jsonify(customer_prices)

@app.route("/get_customer_prices_by_model/<int:model_id>", methods=["GET"])
def get_customer_prices_by_model(model_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT p.id, p.part_id, p.part_name, p.retail_price
        FROM parts p
        WHERE p.model_id = %s
    """, (model_id,))
    parts = cursor.fetchall()
    cursor.execute("""
        SELECT DISTINCT c.id, c.name
        FROM customers c
        JOIN customer_prices cp ON c.id = cp.customer_id
        JOIN parts p ON cp.part_id = p.id
        WHERE p.model_id = %s
    """, (model_id,))
    customers = cursor.fetchall()
    cursor.execute("""
        SELECT cp.id, cp.part_id, cp.customer_id, cp.price, p.part_id AS part_id_name, p.part_name, c.name AS customer_name
        FROM customer_prices cp
        JOIN parts p ON cp.part_id = p.id
        JOIN customers c ON cp.customer_id = c.id
        WHERE p.model_id = %s
    """, (model_id,))
    customer_prices = cursor.fetchall()
    result = []
    for part in parts:
        part_data = {
            "part_id": part["id"],
            "part_id_name": part["part_id"],
            "part_name": part["part_name"],
            "retail_price": part["retail_price"],
            "prices": {}
        }
        for customer in customers:
            part_data["prices"][customer["name"]] = {
                "price_id": None,
                "price": None
            }
        for price in customer_prices:
            if price["part_id"] == part["id"]:
                part_data["prices"][price["customer_name"]] = {
                    "price_id": price["id"],
                    "price": price["price"]
                }
        result.append(part_data)
    conn.close()
    return jsonify({"parts": result, "customers": customers})

@app.route("/admin_edit_customer_price/<int:price_id>", methods=["POST"])
@csrf.exempt
def admin_edit_customer_price(price_id):
    if 'username' not in session or session.get('role') != 'admin':
        return jsonify({"success": False, "message": "Unauthorized"})
    new_price = request.form.get("price")
    try:
        new_price = float(new_price)
    except ValueError:
        return jsonify({"success": False, "message": "Price must be a valid number"})
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("UPDATE customer_prices SET price = %s WHERE id = %s", (new_price, price_id))
        conn.commit()
        return jsonify({"success": True, "message": "Customer price updated successfully"})
    except mysql.connector.Error as err:
        conn.rollback()
        return jsonify({"success": False, "message": f"Error: {str(err)}"})
    finally:
        conn.close()

@app.route("/admin_add_customer_price", methods=["POST"])
@csrf.exempt
def admin_add_customer_price():
    if 'username' not in session or session.get('role') != 'admin':
        return jsonify({"success": False, "message": "Unauthorized"})
    customer_id = request.form.get("customer_id")
    part_id = request.form.get("part_id")
    price = request.form.get("price")
    try:
        price = float(price)
    except ValueError:
        return jsonify({"success": False, "message": "Price must be a valid number"})
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO customer_prices (customer_id, part_id, price)
            VALUES (%s, %s, %s)
            ON DUPLICATE KEY UPDATE price = %s
        """, (customer_id, part_id, price, price))
        conn.commit()
        return jsonify({"success": True, "message": "Customer price added successfully"})
    except mysql.connector.Error as err:
        conn.rollback()
        return jsonify({"success": False, "message": f"Error: {str(err)}"})
    finally:
        conn.close()

@app.route("/get_customer_price/<int:customer_id>/<int:part_id>", methods=["GET"])
def get_customer_price(customer_id, part_id):
    if 'username' not in session or session.get('role') != 'admin':
        return jsonify({"success": False, "message": "Unauthorized"})
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT price FROM customer_prices WHERE customer_id = %s AND part_id = %s",
            (customer_id, part_id)
        )
        price = cursor.fetchone()
        conn.close()
        return jsonify({"price": price["price"] if price else None})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})

@app.route("/admin_add_bulk_customer_prices", methods=["POST"])
@csrf.exempt
def admin_add_bulk_customer_prices():
    if 'username' not in session or session.get('role') != 'admin':
        return jsonify({"success": False, "message": "Unauthorized"})
    try:
        data = request.form
        customer_id = data["customer_id"]
        prices = json.loads(data["prices"])
        conn = get_db_connection()
        cursor = conn.cursor()
        for price_data in prices:
            part_id = price_data["part_id"]
            price = price_data["price"]
            cursor.execute(
                "SELECT id FROM customer_prices WHERE customer_id = %s AND part_id = %s",
                (customer_id, part_id)
            )
            existing_price = cursor.fetchone()
            if existing_price:
                cursor.execute(
                    "UPDATE customer_prices SET price = %s WHERE customer_id = %s AND part_id = %s",
                    (price, customer_id, part_id)
                )
            else:
                cursor.execute(
                    "INSERT INTO customer_prices (customer_id, part_id, price) VALUES (%s, %s, %s)",
                    (customer_id, part_id, price)
                )
        conn.commit()
        conn.close()
        return jsonify({"success": True, "message": "Customer prices saved successfully"})
    except Exception as e:
        conn.rollback()
        conn.close()
        return jsonify({"success": False, "message": str(e)})


@app.route("/download_price_list/<customer_name>/<model_name>")
def download_price_list(customer_name, model_name):
    if 'username' not in session:
        return redirect(url_for("login"))

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT id FROM models WHERE name = %s", (model_name,))
    model = cursor.fetchone()
    if not model:
        conn.close()
        return "Model not found", 404
    model_id = model[0]

    if customer_name == "Retail Price":
        cursor.execute("""
            SELECT part_id, part_name, retail_price
            FROM parts
            WHERE model_id = %s
        """, (model_id,))
        rows = cursor.fetchall()
    else:
        cursor.execute("SELECT id FROM customers WHERE name = %s", (customer_name,))
        customer = cursor.fetchone()
        if not customer:
            conn.close()
            return "Customer not found", 404
        customer_id = customer[0]

        cursor.execute("""
            SELECT p.part_id, p.part_name, p.retail_price, cp.price
            FROM parts p
            LEFT JOIN customer_prices cp ON cp.part_id = p.id AND cp.customer_id = %s
            WHERE p.model_id = %s
        """, (customer_id, model_id))
        rows = cursor.fetchall()

    conn.close()

    # --- PDF generation ---
    pdf = FPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.set_font("Arial", "B", 16)
    pdf.set_text_color(0, 0, 128)
    pdf.cell(0, 10, f"{customer_name} Price List - {model_name}", ln=True, align="C")
    pdf.set_font("Arial", "", 10)
    pdf.set_text_color(100)
    pdf.cell(0, 10, f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align="R")
    pdf.ln(5)

    pdf.set_font("Arial", "B", 12)
    pdf.set_fill_color(0, 102, 204)
    pdf.set_text_color(255, 255, 255)

    if customer_name == "Retail Price":
        pdf.cell(50, 10, "Part ID", 1, 0, "C", True)
        pdf.cell(90, 10, "Part Name", 1, 0, "C", True)
        pdf.cell(40, 10, "Retail Price", 1, 1, "C", True)
    else:
        pdf.cell(40, 10, "Part ID", 1, 0, "C", True)
        pdf.cell(80, 10, "Part Name", 1, 0, "C", True)
        pdf.cell(35, 10, "Retail Price", 1, 0, "C", True)
        pdf.cell(35, 10, f"{customer_name} Price", 1, 1, "C", True)

    pdf.set_font("Arial", "", 11)
    pdf.set_text_color(0)
    fill = False

    for row in rows:
        pdf.set_fill_color(245, 245, 245)
        if customer_name == "Retail Price":
            part_id, part_name, retail_price = row
            pdf.cell(50, 10, str(part_id), 1, 0, "C", fill)
            pdf.cell(90, 10, str(part_name), 1, 0, "L", fill)
            pdf.cell(40, 10, f"{retail_price:.2f}", 1, 1, "R", fill)
        else:
            part_id, part_name, retail_price, customer_price = row
            pdf.cell(40, 10, str(part_id), 1, 0, "C", fill)
            pdf.cell(80, 10, str(part_name), 1, 0, "L", fill)
            pdf.cell(35, 10, f"{retail_price:.2f}", 1, 0, "R", fill)
            price_display = f"{customer_price:.2f}" if customer_price is not None else "-"
            pdf.cell(35, 10, price_display, 1, 1, "R", fill)
        fill = not fill

    response = make_response(pdf.output(dest='S').encode('latin1'))
    filename = f"{customer_name.replace(' ', '_')}_{model_name.replace(' ', '_')}_price_list.pdf"
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename={filename}'
    return response

@app.route("/manage_permissions/<username>", methods=["GET", "POST"])
def manage_permissions(username):
    if 'username' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor()

    # Get user details
    cursor.execute("SELECT id, role FROM users WHERE username = %s", (username,))
    user = cursor.fetchone()
    if not user:
        conn.close()
        return "User not found", 404

    user_id, role = user

    if request.method == "POST":
        # Get permission values from the form
        view_models = 'view_models' in request.form
        view_parts = 'view_parts' in request.form
        view_prices = 'view_prices' in request.form

        # Update or insert permissions
        cursor.execute("SELECT id FROM user_permissions WHERE user_id = %s", (user_id,))
        if cursor.fetchone():
            cursor.execute("""
                UPDATE user_permissions
                SET can_view_models = %s, can_view_parts = %s, can_view_prices = %s
                WHERE user_id = %s
            """, (view_models, view_parts, view_prices, user_id))
        else:
            cursor.execute("""
                INSERT INTO user_permissions (user_id, can_view_models, can_view_parts, can_view_prices)
                VALUES (%s, %s, %s, %s)
            """, (user_id, view_models, view_parts, view_prices))

        conn.commit()
        conn.close()
        flash("Permissions updated successfully.", "success")
        return redirect(url_for("admin_dashboard"))

    # GET request: fetch existing permissions if available
    cursor.execute("""
        SELECT can_view_models, can_view_parts, can_view_prices
        FROM user_permissions
        WHERE user_id = %s
    """, (user_id,))
    permissions = cursor.fetchone()
    conn.close()

    if permissions:
        view_models, view_parts, view_prices = permissions
    else:
        view_models = view_parts = view_prices = False

    return render_template("manage_permissions.html",
                           username=username,
                           role=role,
                           view_models=view_models,
                           view_parts=view_parts,
                           view_prices=view_prices)

@app.route('/view_logs')
def view_logs():
    if 'username' not in session or session.get('role') != 'admin':
        flash("You must be an admin to view logs.", "warning")
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM audit_logs ORDER BY timestamp DESC")
    logs = cursor.fetchall()
    conn.close()

    return render_template('view_logs.html', logs=logs)

@app.route('/post_login')
def post_login():
    # This ensures session is available before redirecting
    return redirect(url_for('index'))

@app.route('/inventory')
def inventory_redirect():
    return redirect(url_for('inventory_dashboard'))


    # Optional: Only allow users with certain roles
    if session['role'] != 'admin' and not session['username'].startswith("Account_"):
        flash("Unauthorized access to inventory dashboard.", "danger")
        return redirect(url_for('index'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM inventory")
    inventory_items = cursor.fetchall()
    conn.close()

    return render_template("inventory_dashboard.html", inventory=inventory_items)

@app.route('/inventory_dashboard')
def inventory_dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))

    selected_model = request.args.get('model')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Get all model names for dropdown
    cursor.execute("SELECT name FROM models")
    models = [row['name'] for row in cursor.fetchall()]

    # Build part query with optional model filter
    part_query = """
        SELECT p.id, p.part_id, p.part_name, m.name AS model_name, p.threshold_quantity,
               IFNULL(SUM(CASE WHEN mv.movement_type = 'in' THEN mv.quantity ELSE 0 END), 0) AS total_in,
               IFNULL(SUM(CASE WHEN mv.movement_type = 'out' THEN mv.quantity ELSE 0 END), 0) AS total_out
        FROM parts p
        JOIN models m ON p.model_id = m.id
        LEFT JOIN part_movements mv ON p.id = mv.part_id
    """
    query_params = []

    if selected_model:
        part_query += " WHERE m.name = %s"
        query_params.append(selected_model)

    part_query += " GROUP BY p.id"

    cursor.execute(part_query, query_params)
    parts = cursor.fetchall()
    conn.close()

    for part in parts:
        part['available_quantity'] = part['total_in'] - part['total_out']
        part['min_quantity'] = part['threshold_quantity']

    return render_template(
        'inventory_dashboard.html',
        models=models,
        selected_model=selected_model,
        inventory=parts
    )

@app.route('/get_inventory_models')
def get_inventory_models():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM models ORDER BY name")
    models = [row[0] for row in cursor.fetchall()]
    conn.close()
    return jsonify(models=models)



@app.route('/update_stock_manual', methods=['POST'])
@csrf.exempt
def update_stock_manual():
    if 'username' not in session or session['role'] != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    part_id = request.form['part_id']
    new_quantity = int(request.form['new_quantity'])

    conn = get_db_connection()
    cursor = conn.cursor()

    # First, remove existing movements
    cursor.execute("DELETE FROM part_movements WHERE part_id = %s", (part_id,))
    # Insert a new "in" movement with the updated quantity
    cursor.execute("INSERT INTO part_movements (part_id, movement_type, quantity) VALUES (%s, 'in', %s)",
                   (part_id, new_quantity))

    conn.commit()
    conn.close()

    return jsonify({'success': True, 'message': 'Stock updated'})


@app.route('/view_part_log/<int:part_id>')
def view_part_log(part_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Get part details
    cursor.execute("SELECT part_id, part_name, model_name FROM parts WHERE id = %s", (part_id,))
    part = cursor.fetchone()

    if not part:
        conn.close()
        return "Part not found", 404

    # Get movement logs
    cursor.execute("""
        SELECT movement_type, quantity, timestamp
        FROM part_movements
        WHERE part_id = %s
        ORDER BY timestamp DESC
    """, (part_id,))
    logs = cursor.fetchall()
    conn.close()

    return render_template('part_logs.html', part=part, logs=logs)


@app.route('/inventory/incoming/<int:part_id>', methods=['POST'])
@csrf.exempt
def inventory_incoming(part_id):
    if 'username' not in session:
        return "Unauthorized", 401

    quantity = request.form.get('quantity')
    if not quantity or not quantity.isdigit():
        return "Invalid quantity", 400

    quantity = int(quantity)

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO part_movements (part_id, quantity, movement_type) VALUES (%s, %s, 'in')",
                   (part_id, quantity))
    conn.commit()
    conn.close()

    return '', 204  # Success without content



@app.route('/inventory/outgoing/<int:part_id>', methods=['POST'])
@csrf.exempt
def inventory_outgoing(part_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    quantity = request.form.get('quantity')
    if not quantity or not quantity.isdigit():
        return "Invalid quantity", 400

    quantity = int(quantity)

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO part_movements (part_id, quantity, movement_type) VALUES (%s, %s, 'out')", (part_id, quantity))
    conn.commit()
    conn.close()
    return '', 204


@app.route('/update_threshold', methods=['POST'])
@csrf.exempt
def update_threshold():
    if 'username' not in session:
        return redirect(url_for('login'))

    part_id = request.form['part_id']
    threshold = request.form['threshold']

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE parts SET threshold_quantity = %s WHERE id = %s", (threshold, part_id))
    conn.commit()
    conn.close()

    flash("Threshold updated.", "success")
    return redirect(url_for('inventory_dashboard'))


# Remove serverless handler for local execution
if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)