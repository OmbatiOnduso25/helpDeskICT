from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_mysqldb import MySQL
from flask_paginate import Pagination, get_page_parameter
from dotenv import load_dotenv
import os
from werkzeug.security import check_password_hash

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

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE username = %s", [username])
        user = cur.fetchone()
        cur.close()

        if user and password == user['password'] and user['role'] in ['admin', 'superadmin']:
            session['admin_logged_in'] = True
            session['admin_username'] = user['username']
            session['admin_role'] = user['role']
            flash("Login successful.", "success")
            return redirect(url_for('admin'))
        else:
            flash("Invalid credentials or access denied.", "danger")
            return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/admin')
def admin():
    # Require login
    if not session.get('admin_logged_in'):
        flash("Please log in to access admin panel.", "warning")
        return redirect(url_for('login'))

    status = request.args.get('status', 'All')
    partial = request.args.get('partial') == '1'
    page = request.args.get(get_page_parameter(), type=int, default=1)
    per_page = 20

    cur = mysql.connection.cursor()

    # Count total issues
    count_query = "SELECT COUNT(*) as total FROM issues"
    count_params = []
    if status != 'All':
        count_query += " WHERE status = %s"
        count_params.append(status)
    cur.execute(count_query, count_params)
    total = cur.fetchone()['total']

    # Fetch paginated issue records
    data_query = "SELECT id, room, issues, status, submitted_at FROM issues"
    data_params = []
    if status != 'All':
        data_query += " WHERE status = %s"
        data_params.append(status)
    data_query += " ORDER BY id DESC LIMIT %s OFFSET %s"
    data_params.extend([per_page, (page - 1) * per_page])
    cur.execute(data_query, data_params)
    issues = cur.fetchall()

    # Superadmin: load all admins
    admin_list = []
    if session.get('admin_role') == 'superadmin':
        cur.execute("SELECT id, name, username, role FROM users WHERE role IN ('admin', 'superadmin')")
        admin_list = cur.fetchall()

    cur.close()

    # Pagination setup
    pagination = Pagination(
        page=page,
        total=total,
        per_page=per_page,
        css_framework='bootstrap5',
        record_name='issues'
    )

    # HTMX partial update (table only)
    if partial:
        return render_template('partials/_issues_table.html', issues=issues, pagination=pagination)

    # Full page render
    return render_template(
        'admin.html',
        issues=issues,
        pagination=pagination,
        status=status,
        admin_list=admin_list
    )


@app.route('/update-status/<int:issue_id>', methods=['POST'])
def update_status(issue_id):
    if not session.get('admin_logged_in'):
        flash("Unauthorized access.", "danger")
        return redirect(url_for('login'))
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

from flask import session

# Admin management page - only for superadmin
@app.route('/manage-admins')
def manage_admins():
    if session.get('admin_role') != 'superadmin':
        flash('Access denied.', 'danger')
        return redirect(url_for('admin'))

    cur = mysql.connection.cursor()
    cur.execute("SELECT id, name, username, role FROM users WHERE role = 'admin'")
    admins = cur.fetchall()
    cur.close()
    return render_template('manage_admins.html', admins=admins)

# Add admin
@app.route('/add-admin', methods=['POST'])
def add_admin():
    if session.get('admin_role') != 'superadmin':
        flash('Access denied.', 'danger')
        return redirect(url_for('admin'))

    name = request.form.get('name')
    username = request.form.get('username')
    password = request.form.get('password')

    try:
        cur = mysql.connection.cursor()
        cur.execute("""
            INSERT INTO users (name, room, username, password, role)
            VALUES (%s, %s, %s, %s, 'admin')
        """, (name, '', username, password))  # You can add room if needed
        mysql.connection.commit()
        flash('New admin added.', 'success')
    except Exception as e:
        print("Add admin error:", e)
        flash('Could not add admin. Check for duplicate username.', 'danger')
    return redirect(url_for('manage_admins'))

# Delete admin
@app.route('/delete-admin/<int:admin_id>', methods=['POST'])
def delete_admin(admin_id):
    if session.get('admin_role') != 'superadmin':
        flash('Access denied.', 'danger')
        return redirect(url_for('admin'))

    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM users WHERE id = %s AND role = 'admin'", (admin_id,))
    mysql.connection.commit()
    flash('Admin removed.', 'success')
    return redirect(url_for('manage_admins'))


@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)
