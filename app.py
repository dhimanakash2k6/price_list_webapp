import os
import json
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
import mysql.connector
import pandas as pd
from flask_mail import Mail, Message  # For email functionality

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change this to a secure random key in production

# Email configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'dhimanakashmls@gmail.com'  # Replace with your email
app.config['MAIL_PASSWORD'] = 'yxsdectmvramfbro'     # Replace with your app-specific password
app.config['MAIL_DEFAULT_SENDER'] = 'dhimanakashmls@gmail.com'
mail = Mail(app)

# MySQL setup
db_config = {
    'host': '127.0.0.1',
    'user': 'root',
    'password': 'MLS@5002hd',
    'database': 'price_list'
}

def get_db_connection():
    return mysql.connector.connect(**db_config)

def get_sheet_names():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT name FROM models')
    models = [row[0] for row in cursor.fetchall()]
    conn.close()
    return models

@app.route("/")
def index():
    models = get_sheet_names()
    if 'username' in session:
        return render_template("home.html", message=f"Welcome, {session['username']}!", models=models, logged_in=True)
    return render_template("home.html", models=models, logged_in=False)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        try:
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)
            cursor.execute('SELECT * FROM users WHERE username = %s AND password = %s', (username, password))
            user = cursor.fetchone()
            if user:
                session['username'] = username
                session['role'] = user['role']
                flash(f'Welcome, {username}!', 'success')
                print(f"Login successful: {username}, role: {user['role']}")
                if user['role'] == 'admin':
                    return redirect(url_for('admin_dashboard'))
                return """
                <script>
                    window.open('/home', '_blank', 'width=800,height=600');
                    window.location.href = '/login';
                </script>
                """
            else:
                flash('Invalid credentials.', 'danger')
        except mysql.connector.Error as e:
            flash(f'Error logging in: {str(e)}', 'danger')
        finally:
            conn.close()
    return render_template('login.html')

@app.route('/home')
def home():
    if 'username' not in session:
        return redirect(url_for('login'))
    print(f"Rendering home for {session['username']}, role: {session['role']}")
    try:
        rendered = render_template('index.html')
        print(f"Rendered HTML: {rendered[:200]}...")
        return rendered
    except Exception as e:
        flash(f'Error loading home page: {str(e)}', 'danger')
        return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        account_name = request.form['account_name']
        password = request.form['password']
        print(f"Signup attempt: {username}, {email}, {account_name}, {password}")
        try:
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)
            cursor.execute('SELECT * FROM users WHERE username = %s OR email = %s', (username, email))
            existing_user = cursor.fetchone()
            cursor.execute('SELECT * FROM signup_requests WHERE username = %s OR email = %s', (username, email))
            existing_request = cursor.fetchone()
            print(f"Existing user: {existing_user}")
            print(f"Existing request: {existing_request}")
            if existing_user is not None or existing_request is not None:
                flash('Username or email already exists.', 'danger')
                conn.close()
                return redirect(url_for('signup'))
            cursor.execute(
                'INSERT INTO signup_requests (username, email, account_name, password, status) VALUES (%s, %s, %s, %s, %s)',
                (username, email, account_name, password, 'pending')
            )
            print(f"Rows inserted: {cursor.rowcount}")
            conn.commit()
            print("Database committed")
            try:
                msg = Message('New Signup Request', recipients=['your-email@gmail.com'])
                msg.body = f'New signup request:\nUsername: {username}\nEmail: {email}\nAccount: {account_name}'
                mail.send(msg)
                flash('Signup request sent. Please wait for approval.', 'success')
            except Exception as e:
                flash(f'Email notification failed: {str(e)}', 'warning')
            conn.close()
            return redirect(url_for('login'))
        except mysql.connector.Error as e:
            flash(f'Database error: {str(e)}', 'danger')
            print(f"Database error: {str(e)}")
            conn.close()
            return redirect(url_for('signup'))
    return render_template('signup.html')

@app.route("/logout")
def logout():
    session.pop('username', None)
    session.pop('role', None)
    return redirect(url_for('index'))

@app.route("/get_models")
def get_models():
    models = get_sheet_names()
    return jsonify({"models": models})

@app.route("/get_customers", methods=["POST"])
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
def add_customer():
    if 'username' not in session:
        return jsonify({"message": "Please log in.", "success": False})
    model = request.form.get("model")
    customer = request.form.get("customer")
    conn = get_db_connection()
    cursor = conn.cursor()

    # Check if customer already exists
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

    # Check if the model has parts
    cursor.execute('SELECT id FROM parts WHERE model_id = %s LIMIT 1', (model_id,))
    part_exists = cursor.fetchone()
    conn.close()
    if not part_exists:
        return jsonify({"message": "no_parts", "model": model, "success": False})

    # Add customer
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('INSERT INTO customers (name) VALUES (%s)', (customer,))
    customer_id = cursor.lastrowid

    cursor.execute('SELECT id, retail_price FROM parts WHERE model_id = %s', (model_id,))
    parts = cursor.fetchall()
    for part_id, retail_price in parts:
        cursor.execute('INSERT INTO customer_prices (part_id, customer_id, price) VALUES (%s, %s, %s) ON DUPLICATE KEY UPDATE price = VALUES(price)', (part_id, customer_id, retail_price or 0.00))
    conn.commit()
    conn.close()
    return jsonify({"message": f"Customer '{customer}' added with default prices.", "success": True})

@app.route("/add_customer_prices/<customer_name>", methods=["GET", "POST"])
def add_customer_prices(customer_name):
    if 'username' not in session:
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
                cursor.execute('INSERT INTO customer_prices (part_id, customer_id, price) VALUES (%s, %s, %s) ON DUPLICATE KEY UPDATE price = VALUES(price)', (part_id, customer_id, float(price)))
        conn.commit()
        conn.close()
        return render_template("add_customer_prices.html", model=model, customer_name=customer_name, df=df, message="Successfully updated!")

    conn.close()
    return render_template("add_customer_prices.html", model=model, customer_name=customer_name, df=df)

@app.route("/update_prices", methods=["POST"])
def update_prices():
    if 'username' not in session:
        return jsonify({"message": "Please log in.", "success": False})
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
            cursor.execute('INSERT INTO customer_prices (part_id, customer_id, price) VALUES (%s, %s, %s) ON DUPLICATE KEY UPDATE price = VALUES(price)', (part_id, customer_id, float(price)))
    conn.commit()
    conn.close()
    return jsonify({"message": "Prices updated."})

@app.route("/add_model", methods=["POST"])
def add_model():
    if 'username' not in session:
        return jsonify({"message": "Please log in.", "success": False})
    model = request.form.get("model")
    part_ids = request.form.getlist("part_ids[]")
    part_names = request.form.getlist("part_names[]")
    retail_prices = request.form.getlist("retail_prices[]")
    conn = get_db_connection()
    cursor = conn.cursor()

    # Check if model already exists
    cursor.execute('SELECT id FROM models WHERE name = %s', (model,))
    if cursor.fetchone():
        conn.close()
        return jsonify({"message": f"Model '{model}' already exists.", "success": False})

    # Validate parts data
    if not part_ids or not all(part_ids) or not all(part_names) or not all(retail_prices):
        conn.close()
        return jsonify({"message": "All part fields must be filled.", "success": False})

    # Insert the model
    cursor.execute('INSERT INTO models (name) VALUES (%s)', (model,))
    model_id = cursor.lastrowid

    # Insert parts
    for part_id, part_name, price in zip(part_ids, part_names, retail_prices):
        try:
            price = float(price)
            cursor.execute('INSERT INTO parts (model_id, part_id, part_name, retail_price) VALUES (%s, %s, %s, %s)', (model_id, part_id, part_name, price))
        except ValueError:
            conn.rollback()
            conn.close()
            return jsonify({"message": "Retail price must be a valid number.", "success": False})

    conn.commit()
    conn.close()
    return jsonify({"message": f"Model '{model}' added with parts.", "success": True})

@app.route("/get_part_suggestions", methods=["POST"])
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
    cursor.execute('SELECT CONCAT(part_id, " - ", part_name) FROM parts WHERE model_id = %s AND (part_id LIKE %s OR part_name LIKE %s)', (model_id, '%' + term + '%', '%' + term + '%'))
    suggestions = [row[0] for row in cursor.fetchall()]
    conn.close()
    return jsonify({"suggestions": suggestions})

@app.route("/add_spare_parts/<model>", methods=["GET", "POST"])
def add_spare_parts(model):
    if 'username' not in session:
        return redirect(url_for('login'))
    if request.method == "POST":
        part_id = request.form.get("part_id")
        part_name = request.form.get("part_name")
        retail_price = request.form.get("retail_price")
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM models WHERE name = %s', (model,))
        model_id = cursor.fetchone()[0]
        cursor.execute('INSERT INTO parts (model_id, part_id, part_name, retail_price) VALUES (%s, %s, %s, %s)', (model_id, part_id, part_name, float(retail_price)))
        conn.commit()
        conn.close()
        return jsonify({"success": True, "message": "Part added successfully!"})
    return render_template("add_spare_parts.html", model=model)

@app.route("/edit_spare_part/<int:part_id>", methods=["POST"])
def edit_spare_part(part_id):
    if 'username' not in session:
        return jsonify({"message": "Please log in.", "success": False})
    part_name = request.form.get("part_name")
    retail_price = request.form.get("retail_price")
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('UPDATE parts SET part_name = %s, retail_price = %s WHERE id = %s', (part_name, float(retail_price), part_id))
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

@app.route('/price_list_view')
def price_list_view():
    models = get_sheet_names()
    if 'username' in session:
        return render_template('price_list_view.html', models=models, logged_in=True)
    return render_template('price_list_view.html', models=models, logged_in=False)

@app.route("/add_customer_view")
def add_customer_view():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template("add_customer.html")

@app.route("/add_model_view")
def add_model_view():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template("add_model.html")

@app.route('/admin_dashboard')
def admin_dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    if session.get('role') != 'admin':
        flash("You do not have permission to access the admin dashboard.", "error")
        return redirect(url_for('home'))
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
        return redirect(url_for('home'))

@app.route("/approve_signup/<int:request_id>", methods=["POST"])
def approve_signup(request_id):
    if session.get('role') != 'admin':
        return jsonify({"success": False, "message": "Unauthorized"})
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM signup_requests WHERE id = %s', (request_id,))
    request_data = cursor.fetchone()
    
    if request_data:
        cursor.execute('INSERT INTO users (username, email, account_name, password, is_approved) VALUES (%s, %s, %s, %s, TRUE)',
                      (request_data[1], request_data[2], request_data[3], request_data[4]))
        cursor.execute('DELETE FROM signup_requests WHERE id = %s', (request_id,))
        
        # Send approval email
        msg = Message('Account Approved', recipients=[request_data[2]])
        msg.body = f'Your account {request_data[1]} has been approved. You can now login and access all features.'
        mail.send(msg)
        
        conn.commit()
    conn.close()
    return jsonify({"success": True, "message": "User approved"})

@app.route("/get_all_models", methods=["GET"])
def get_all_models():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM models")
    models = cursor.fetchall()
    conn.close()
    return jsonify(models)

@app.route("/admin_add_model", methods=["POST"])
def admin_add_model():
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
def admin_edit_model(model_id):
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
def admin_delete_model(model_id):
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
def admin_add_customer():
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
def admin_edit_customer(customer_id):
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
def admin_delete_customer(customer_id):
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
def admin_add_part():
    model_id = request.form.get("model_id")
    part_id = request.form.get("part_id")
    part_name = request.form.get("part_name")
    retail_price = request.form.get("retail_price")
    try:
        retail_price = float(retail_price)
    except ValueError:
        return jsonify({"success": False, "message": "Retail price must be a valid number."})
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
def admin_edit_part(part_id):
    model_id = request.form.get("model_id")
    new_part_id = request.form.get("part_id")
    part_name = request.form.get("part_name")
    retail_price = request.form.get("retail_price")
    try:
        retail_price = float(retail_price)
    except ValueError:
        return jsonify({"success": False, "message": "Retail price must be a valid number."})
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
        return jsonify({"success": False, "message": f"Error: {str(err)}"})
    finally:
        conn.close()

@app.route("/admin_delete_part/<int:part_id>", methods=["POST"])
def admin_delete_part(part_id):
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
def admin_edit_customer_price(price_id):
    new_price = request.form.get("price")
    try:
        new_price = float(new_price)
    except ValueError:
        return jsonify({"success": False, "message": "Price must be a valid number."})
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("UPDATE customer_prices SET price = %s WHERE id = %s", (new_price, price_id))
        conn.commit()
        return jsonify({"success": True, "message": "Customer price updated successfully."})
    except mysql.connector.Error as err:
        conn.rollback()
        return jsonify({"success": False, "message": f"Error: {str(err)}"})
    finally:
        conn.close()

@app.route("/admin_add_customer_price", methods=["POST"])
def admin_add_customer_price():
    customer_id = request.form.get("customer_id")
    part_id = request.form.get("part_id")
    price = request.form.get("price")
    try:
        price = float(price)
    except ValueError:
        return jsonify({"success": False, "message": "Price must be a valid number."})
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO customer_prices (customer_id, part_id, price)
            VALUES (%s, %s, %s)
            ON DUPLICATE KEY UPDATE price = %s
        """, (customer_id, part_id, price, price))
        conn.commit()
        return jsonify({"success": True, "message": "Customer price added successfully."})
    except mysql.connector.Error as err:
        conn.rollback()
        return jsonify({"success": False, "message": f"Error: {str(err)}"})
    finally:
        conn.close()

@app.route("/get_customer_price/<int:customer_id>/<int:part_id>", methods=["GET"])
def get_customer_price(customer_id, part_id):
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
def admin_add_bulk_customer_prices():
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

@app.route('/approve_request/<int:request_id>', methods=['POST'])
def approve_request(request_id):
    if 'username' not in session or session.get('role') != 'admin':
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('login'))
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute('SELECT * FROM signup_requests WHERE id = %s', (request_id,))
        request_data = cursor.fetchone()
        if not request_data:
            flash(f'Request {request_id} not found.', 'danger')
            conn.close()
            return redirect(url_for('admin_dashboard'))
        username = request_data['username']
        email = request_data['email']
        password = request_data['password']
        cursor.execute(
            'INSERT INTO users (username, email, password, role) VALUES (%s, %s, %s, %s)',
            (username, email, password, 'user')
        )
        cursor.execute('DELETE FROM signup_requests WHERE id = %s', (request_id,))
        conn.commit()
        flash(f'Request {request_id} approved! User {username} moved to approved users.', 'success')
    except mysql.connector.Error as e:
        flash(f'Error approving request: {str(e)}', 'danger')
    finally:
        conn.close()
    return redirect(url_for('admin_dashboard'))

@app.route('/reject_request/<int:request_id>', methods=['POST'])
def reject_request(request_id):
    if 'username' not in session or session['username'] != 'admin':
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('login'))
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Check if request exists
        cursor.execute('SELECT username FROM signup_requests WHERE id = %s', (request_id,))
        request_data = cursor.fetchone()
        
        if not request_data:
            flash(f'Request {request_id} not found.', 'danger')
            conn.close()
            return redirect(url_for('admin_dashboard'))
        
        # Delete the request
        cursor.execute('DELETE FROM signup_requests WHERE id = %s', (request_id,))
        rows_affected = cursor.rowcount
        
        if rows_affected == 0:
            flash(f'Failed to reject request {request_id}.', 'danger')
        else:
            if request_id == 5:  # Example condition for user deletion
                username = request_data['username']
                cursor.execute('DELETE FROM users WHERE username = %s', (username,))
                flash(f'Request {request_id} rejected, and user {username} deleted.', 'warning')
            else:
                flash(f'Request {request_id} rejected and removed.', 'success')
        
        conn.commit()
    
    except mysql.connector.Error as e:
        flash(f'Error rejecting request: {str(e)}', 'danger')
    
    finally:
        conn.close()
    
    return redirect(url_for('admin_dashboard'))

@app.route('/delete_all_users_except_admin', methods=['POST'])
def delete_all_users_except_admin():
    if 'username' not in session or session.get('role') != 'admin':
        flash('Unauthorized access.', 'danger')
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
def delete_user(username):
    if 'username' not in session or session.get('role') != 'admin':
        flash('Unauthorized access.', 'danger')
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

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)