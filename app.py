from flask import Flask, render_template, request, redirect, url_for, flash
from flask_mysqldb import MySQL
from flask_paginate import Pagination, get_page_parameter
from dotenv import load_dotenv
import os

# Load environment variables from .env
load_dotenv()

# Initialize the Flask application
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')

# MySQL configurations
app.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST')
app.config['MYSQL_USER'] = os.getenv('MYSQL_USER')
app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD')
app.config['MYSQL_DB'] = os.getenv('MYSQL_DB')
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

# Initialize MySQL with the Flask app
mysql = MySQL(app)

@app.route('/')
def index():
    return render_template('report.html')

@app.route('/submit-issue', methods=['POST'])
def submit_issue():
    room = request.form.get('room')
    issues = request.form.getlist('issues')
    other_issue = request.form.get('other_issue')
    details = request.form.get('details')

    issues_str = ', '.join(issues)
    if other_issue:
        issues_str += f", Other: {other_issue}"

    try:
        cur = mysql.connection.cursor()
        cur.execute("""
            INSERT INTO issues (room, issues, other_issue, details)
            VALUES (%s, %s, %s, %s)
        """, (room, issues_str, other_issue, details))
        mysql.connection.commit()
        cur.close()
        return render_template('success.html')
    except Exception as e:
        print(f"Database error: {e}")
        return "An error occurred while submitting the issue. Please try again."

@app.route('/admin')
def admin():
    status = request.args.get('status', 'All')
    partial = request.args.get('partial') == '1'
    page = request.args.get(get_page_parameter(), type=int, default=1)
    per_page = 100

    cur = mysql.connection.cursor()

    count_query = "SELECT COUNT(*) as total FROM issues"
    count_params = []
    if status != 'All':
        count_query += " WHERE status = %s"
        count_params.append(status)
    cur.execute(count_query, count_params)
    total = cur.fetchone()['total']

    data_query = "SELECT id, room, issues, status, submitted_at FROM issues"
    data_params = []
    if status != 'All':
        data_query += " WHERE status = %s"
        data_params.append(status)
    data_query += " ORDER BY id DESC LIMIT %s OFFSET %s"
    data_params.extend([per_page, (page - 1) * per_page])
    cur.execute(data_query, data_params)
    issues = cur.fetchall()
    cur.close()

    pagination = Pagination(
        page=page,
        total=total,
        per_page=per_page,
        css_framework='bootstrap5',
        record_name='issues'
    )

    if partial:
        return render_template('partials/_issues_table.html', issues=issues, pagination=pagination)

    return render_template('admin.html', issues=issues, pagination=pagination, status=status)

@app.route('/update-status/<int:issue_id>', methods=['POST'])
def update_status(issue_id):
    new_status = request.form.get('status')
    if new_status not in ['Pending', 'In Progress', 'Resolved']:
        flash("Invalid status update.", "danger")
        return redirect(url_for('admin'))

    try:
        cur = mysql.connection.cursor()
        cur.execute("UPDATE issues SET status = %s WHERE id = %s", (new_status, issue_id))
        mysql.connection.commit()
        cur.close()
        flash(f"Issue #{issue_id} updated to '{new_status}'", "success")
    except Exception as e:
        print(f"Error updating status: {e}")
        flash("Database error. Please try again.", "danger")

    return redirect(url_for('admin'))

if __name__ == '__main__':
    app.run(debug=True)
