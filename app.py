import os
import json
from flask import Flask, render_template, request, jsonify, redirect, url_for
import gspread
from oauth2client.service_account import ServiceAccountCredentials

app = Flask(__name__)

# Google Sheets configuration
scope = ["https://spreadsheets.google.com/feeds", "https://www.googleapis.com/auth/drive"]

# Load credentials from environment variable
google_creds = os.getenv("GOOGLE_CREDENTIALS")
if google_creds:
    creds_dict = json.loads(google_creds)
    creds = ServiceAccountCredentials.from_json_keyfile_dict(creds_dict, scope)
else:
    # Fallback for local development
    creds = ServiceAccountCredentials.from_json_keyfile_name('credentials.json', scope)

client = gspread.authorize(creds)
spreadsheet_id = '1zl-E2D1DZpWR9iUhqYBQdKIiOzcDbxQVfkKIrQLwfJk'  # Replace with your Google Sheet ID
spreadsheet = client.open_by_key(spreadsheet_id)

def get_sheet_names():
    return [sheet.title for sheet in spreadsheet.worksheets()]

@app.route("/")
def index():
    return render_template("home.html")

@app.route("/get_models")
def get_models():
    models = get_sheet_names()
    return jsonify({"models": models})

@app.route("/get_customers", methods=["POST"])
def get_customers():
    model = request.form.get("model")
    sheet = spreadsheet.worksheet(model)
    headers = sheet.row_values(1)
    customers = [header for header in headers[3:] if header]  # Exclude Part ID, Part Name, Retail Price
    return jsonify({"customers": customers})

@app.route("/get_price_list", methods=["POST"])
def get_price_list():
    model = request.form.get("model")
    customer = request.form.get("customer")
    filter_part = request.form.get("filter_part")

    sheet = spreadsheet.worksheet(model)
    data = sheet.get_all_values()
    headers = data[0]
    part_id_idx = headers.index("Part ID")
    part_name_idx = headers.index("Part Name")
    retail_price_idx = headers.index("Retail Price")
    customer_idx = headers.index(customer) if customer and customer != "Retail Price" else -1

    filtered_data = data[1:]  # Skip header
    if filter_part:
        if " - " in filter_part:
            filter_part = filter_part.split(" - ")[0]
        filtered_data = [row for row in filtered_data if row and (filter_part in row[part_id_idx] or filter_part in row[part_name_idx])]

    if not filtered_data:
        return jsonify({"price_list": f"No parts found for model '{model}'."})

    html = ["<table><tr><th>Part ID</th><th>Part Name</th><th>Retail Price</th>"]
    if customer and customer != "Retail Price":
        html.append("<th>Customer Price</th>")
    html.append("</tr>")

    for row in filtered_data:
        if not row:
            continue
        html.append("<tr>")
        html.append(f"<td>{row[part_id_idx]}</td>")
        html.append(f"<td>{row[part_name_idx]}</td>")
        html.append(f"<td>{float(row[retail_price_idx]) if row[retail_price_idx] else '0.00'}</td>")
        if customer and customer != "Retail Price" and customer_idx != -1:
            html.append(f"<td>{float(row[customer_idx]) if row[customer_idx] else ''}</td>")
        html.append("</tr>")
    html.append("</table>")

    return jsonify({"price_list": "".join(html)})

@app.route("/add_customer", methods=["POST"])
def add_customer():
    model = request.form.get("model")
    customer = request.form.get("customer")
    sheet = spreadsheet.worksheet(model)
    data = sheet.get_all_values()
    headers = data[0]
    if customer not in headers[3:]:  # Add new customer column after Retail Price
        sheet.update_cell(1, len(headers) + 1, customer)

    for row in data[1:]:
        if row:
            part_id_idx = headers.index("Part ID")
            retail_price_idx = headers.index("Retail Price")
            customer_idx = len(headers)
            if not row[customer_idx - 1]:  # If no price exists for this customer
                sheet.update_cell(int(row[0]) + 1, customer_idx + 1, row[retail_price_idx] or "0.00")

    return jsonify({"message": f"Customer '{customer}' added with default prices.", "success": True})

import pandas as pd

@app.route("/add_customer_prices/<customer_name>", methods=["GET", "POST"])
def add_customer_prices(customer_name):
    model = request.form.get("model") or request.args.get("model")
    if not model:
        return redirect(url_for("add_customer_view"))

    sheet = spreadsheet.worksheet(model)
    data = sheet.get_all_values()
    headers = data[0]
    parts = data[1:]  # Skip header
    df = pd.DataFrame(parts, columns=headers)  # Convert to DataFrame

    if request.method == "POST":
        prices = request.form.getlist("prices[]")
        customer_idx = headers.index(customer_name) if customer_name in headers else -1
        if customer_idx == -1:
            sheet.update_cell(1, len(headers) + 1, customer_name)
            customer_idx = len(headers)

        for i, price in enumerate(prices):
            if price and price.replace('.', '').isdigit():
                sheet.update_cell(i + 2, customer_idx + 1, float(price))  # +2 for header and 1-based indexing

        return render_template("add_customer_prices.html", model=model, customer_name=customer_name, df=df, message="Successfully updated!")

    return render_template("add_customer_prices.html", model=model, customer_name=customer_name, df=df)

@app.route("/update_prices", methods=["POST"])
def update_prices():
    model = request.form.get("model")
    customer = request.form.get("customer")
    prices = request.form.getlist("prices[]")
    sheet = spreadsheet.worksheet(model)
    data = sheet.get_all_values()
    headers = data[0]
    parts = data[1:]  # Skip header
    customer_idx = headers.index(customer) if customer in headers else -1

    if customer_idx == -1:
        sheet.update_cell(1, len(headers) + 1, customer)
        customer_idx = len(headers)

    for i, price in enumerate(prices):
        if price and price.replace('.', '').isdigit():
            sheet.update_cell(i + 2, customer_idx + 1, float(price))  # +2 for header and 1-based indexing

    return jsonify({"message": "Prices updated."})

@app.route("/add_model", methods=["POST"])
def add_model():
    model = request.form.get("model")
    parts = request.form.getlist("parts[]")
    sheet = spreadsheet.add_worksheet(title=model, rows="100", cols="20")
    headers = ["Part ID", "Part Name", "Retail Price"]
    sheet.append_row(headers)

    for part in parts:
        part_id, part_name, price = part.split(",")
        sheet.append_row([part_id, part_name, float(price)])

    return jsonify({"message": f"Model '{model}' added with parts.", "success": True})

@app.route("/get_part_suggestions", methods=["POST"])
def get_part_suggestions():
    model = request.form.get("model")
    term = request.form.get("term")

    if not model or not term:
        return jsonify({"suggestions": []})

    sheet = spreadsheet.worksheet(model)
    data = sheet.get_all_values()[1:]  # Skip header
    suggestions = [f"{row[0]} - {row[1]}" for row in data if row and (term.lower() in row[0].lower() or term.lower() in row[1].lower())]
    return jsonify({"suggestions": suggestions})

@app.route("/price_list_view")
def price_list_view():
    return render_template("price_list.html")

@app.route("/add_customer_view")
def add_customer_view():
    return render_template("add_customer.html")

@app.route("/add_model_view")
def add_model_view():
    return render_template("add_model.html")

if __name__ == "__main__":
    import os
    port = int(os.getenv("PORT", 5000))  # Use Render’s port or 5000 locally
    app.run(host="0.0.0.0", port=port, debug=True)