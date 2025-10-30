"""
Flask ICT Help Desk core application (app.py) - corrected and self-contained.
"""

from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_file, abort
from flask_mysqldb import MySQL
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, TextAreaField
from wtforms.validators import DataRequired, Length, Optional
import os
from datetime import datetime, timedelta
from collections import Counter
import math
from io import BytesIO
import json
import secrets
import hmac
import hashlib
import traceback

# Optional PDF support (robust)
reportlab_available = False
pdf_canvas = None
inch = None
letter = None
try:
    from reportlab.lib.pagesizes import letter as RPL_LETTER
    from reportlab.lib.units import inch as RPL_INCH
    from reportlab.pdfgen import canvas as RPL_CANVAS
    letter = RPL_LETTER
    inch = RPL_INCH
    pdf_canvas = RPL_CANVAS
    reportlab_available = True
except Exception:
    reportlab_available = False
    pdf_canvas = None
    inch = None
    letter = None

# Load environment (.env should contain SECRET_KEY and MySQL credentials)
load_dotenv()

app = Flask(__name__)
# require SECRET_KEY in non-debug / production
env_secret = os.getenv('SECRET_KEY')
if not env_secret and os.getenv('FLASK_DEBUG') not in ('1', 'true', 'True'):
    raise RuntimeError('SECRET_KEY environment variable is required in production')
app.secret_key = env_secret or 'dev-secret-change-me'
app.config['WTF_CSRF_TIME_LIMIT'] = None
csrf = CSRFProtect(app)

# MySQL config
app.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST', 'localhost')
app.config['MYSQL_USER'] = os.getenv('MYSQL_USER', 'ombati')
app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD', 'Mama001!')
app.config['MYSQL_DB'] = os.getenv('MYSQL_DB', 'Ictsupport')
app.config['MYSQL_CURSORCLASS'] = os.getenv('MYSQL_CURSORCLASS', 'DictCursor')
mysql = MySQL(app)

# Serializer for password reset tokens
serializer = URLSafeTimedSerializer(app.secret_key)

# -------------------------
# Forms
# -------------------------
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(max=100)])
    password = PasswordField('Password', validators=[DataRequired()])

class RegisterForm(FlaskForm):
    name = StringField('Full name', validators=[Optional(), Length(max=150)])
    username = StringField('Username', validators=[DataRequired(), Length(max=100)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=4)])

class AddAdminForm(FlaskForm):
    name = StringField('Full name', validators=[Optional(), Length(max=150)])
    username = StringField('Username', validators=[DataRequired(), Length(max=100)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=4)])

class SubmitIssueForm(FlaskForm):
    room = StringField('Room', validators=[DataRequired(), Length(max=100)])
    other_issue = StringField('Other', validators=[Optional(), Length(max=255)])
    details = TextAreaField('Details', validators=[Optional()])

class CommentForm(FlaskForm):
    comment = TextAreaField('Comment', validators=[DataRequired(), Length(max=2000)])

class SearchForm(FlaskForm):
    q = StringField('q', validators=[Optional(), Length(max=200)])
    category = StringField('category', validators=[Optional(), Length(max=100)])
    status = StringField('status', validators=[Optional(), Length(max=50)])

class PasswordResetRequestForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(max=100)])

class PasswordResetForm(FlaskForm):
    new_password = PasswordField('New Password', validators=[DataRequired(), Length(min=6)])

class DeleteAdminForm(FlaskForm):
    # no fields needed; hidden_tag() is enough for CSRF
    pass

class AssignIssueForm(FlaskForm):
    """Empty form only used for CSRF protection when assigning issues."""
    pass

class SearchForm(FlaskForm):
    q = StringField('Search')
    category = StringField('Category')
    status = StringField('Status')




# -------------------------
# Issue category mapping
# -------------------------
ISSUE_GROUPS = {
    'network': [
        "No internet access", "Slow internet connection", "Cannot connect to WiFi",
        "LAN port not working", "IP conflict detected", "Network cable issue"
    ],
    'printing': [
        "Printer not working", "Printer out of paper/ink", "Cannot print from my PC",
        "Scanner not responding", "Print queue stuck"
    ],
    'computer': [
        "Computer won’t start", "Slow performance", "Frequent freezing/crashing",
        "Blue screen (BSOD)", "Unexpected restart", "Overheating"
    ],
    'software': [
        "Application not launching", "License/activation issue", "Error when opening software",
        "Software update needed", "Microsoft Office problems", "Antivirus issue"
    ],
    'login': [
        "Forgot password", "Cannot log in to system", "Account locked",
        "Two-factor authentication issue", "Email access issue"
    ],
    'file': [
        "Unable to access shared folder", "File deleted or missing",
        "Low disk space warning", "Backup failed"
    ],
    'hardware': [
        "Mouse/keyboard not working", "Monitor/display issue", "USB ports not detecting devices",
        "Projector/display not working", "Audio not working (no sound)", "Webcam not working"
    ],
    'comm': [
        "Zoom/Teams not working", "Mic not detected", "Camera not working in meetings",
        "Can't join online class/meeting"
    ],
    'web': [
        "Website not opening", "VPN not connecting", "Proxy/server settings issue",
        "Online form or portal not loading"
    ],
    'other': [
        "Request new hardware", "Request software installation", "General ICT enquiry"
    ]
}

ISSUE_TEXT_TO_GROUP = {}
for grp, items in ISSUE_GROUPS.items():
    for it in items:
        ISSUE_TEXT_TO_GROUP[it.strip()] = grp

# -------------------------
# Utilities: DB helpers, audit, schema ensure
# -------------------------
def query_db(query, params=None, one=False):
    cur = None
    try:
        cur = mysql.connection.cursor()
        cur.execute(query, params or [])
        rv = cur.fetchall()
        return (rv[0] if rv else None) if one else rv
    except Exception as e:
        print('DB query error:', e)
        print(traceback.format_exc())
        raise
    finally:
        try:
            if cur:
                cur.close()
        except Exception:
            pass

def execute_db(query, params=None):
    cur = None
    try:
        cur = mysql.connection.cursor()
        cur.execute(query, params or [])
        mysql.connection.commit()
        return cur.lastrowid
    except Exception as e:
        try:
            conn = getattr(mysql, 'connection', None)
            if conn and hasattr(conn, 'rollback'):
                conn.rollback()
        except Exception:
            pass
        print('DB execute error:', e)
        print(traceback.format_exc())
        raise
    finally:
        try:
            if cur:
                cur.close()
        except Exception:
            pass

def audit(action, user_id=None, details=None):
    try:
        execute_db(
            "INSERT INTO audit_logs (action, user_id, details, created_at) VALUES (%s, %s, %s, %s)",
            (action, user_id, json.dumps(details) if details else None, datetime.now())
        )
    except Exception as e:
        print('Audit error:', e)

def ensure_schema():
    """Create helper tables and add missing columns to issues table if needed."""
    try:
        execute_db("""
            CREATE TABLE IF NOT EXISTS users (
                id INT PRIMARY KEY AUTO_INCREMENT,
                name VARCHAR(150) NULL,
                username VARCHAR(100) NOT NULL,
                password VARCHAR(255) NULL,
                role VARCHAR(50) NOT NULL DEFAULT 'staff',
                room_number VARCHAR(50) NULL,
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE KEY ux_users_username (username)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """)
        execute_db("""
            CREATE TABLE IF NOT EXISTS issues (
                id INT PRIMARY KEY AUTO_INCREMENT,
                room VARCHAR(100) NOT NULL,
                issues TEXT NULL,
                other_issue VARCHAR(255) NULL,
                details TEXT NULL,
                user_id INT NULL,
                assigned_admin_id INT NULL,
                category VARCHAR(255) NULL,
                status VARCHAR(50) DEFAULT 'Pending',
                submitted_at DATETIME NOT NULL,
                INDEX idx_user_id (user_id),
                INDEX idx_assigned_admin (assigned_admin_id),
                INDEX idx_category (category)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """)
        execute_db("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INT PRIMARY KEY AUTO_INCREMENT,
                action VARCHAR(255) NOT NULL,
                user_id INT NULL,
                details TEXT NULL,
                created_at DATETIME NOT NULL
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """)
        execute_db("""
            CREATE TABLE IF NOT EXISTS issue_comments (
                id INT PRIMARY KEY AUTO_INCREMENT,
                issue_id INT NOT NULL,
                user_id INT NOT NULL,
                comment TEXT NOT NULL,
                created_at DATETIME NOT NULL
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """)
        execute_db("""
            CREATE TABLE IF NOT EXISTS api_tokens (
                id INT PRIMARY KEY AUTO_INCREMENT,
                token_hmac VARCHAR(128) NOT NULL,
                user_id INT NOT NULL,
                created_at DATETIME NOT NULL,
                expires_at DATETIME NULL,
                UNIQUE KEY ux_token_hmac (token_hmac)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """)
        # Defensive check for 'category' column
        cur = mysql.connection.cursor()
        cur.execute("SELECT COUNT(*) as cnt FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=%s AND TABLE_NAME='issues' AND COLUMN_NAME='category'", (app.config['MYSQL_DB'],))
        if cur.fetchone()['cnt'] == 0:
            execute_db("ALTER TABLE issues ADD COLUMN category VARCHAR(255) NULL")
        cur.close()
    except Exception as e:
        print("Schema ensure error (you may need ALTER privileges):", e)
        print(traceback.format_exc())

# -------------------------
# Role decorators
# -------------------------
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('user_id'):
            flash('Please log in.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('user_id') or session.get('role') not in ('admin', 'superadmin'):
            flash('Admin access required.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def superadmin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('user_id') or session.get('role') != 'superadmin':
            flash('Superadmin access required.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

# -------------------------
# Auth + registration
# -------------------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data
        name = (form.name.data or '').strip()
        existing = query_db("SELECT * FROM users WHERE username=%s", (username,), one=True)
        if existing:
            flash('Username taken.', 'danger')
            return redirect(url_for('register'))
        pw_hash = generate_password_hash(password)
        try:
            execute_db("INSERT INTO users (name, username, password, role, room_number) VALUES (%s,%s,%s,%s,%s)", (name, username, pw_hash, 'staff', None))
        except Exception as e:
            if 'Duplicate entry' in str(e):
                flash('Username already exists.', 'danger')
                return redirect(url_for('register'))
            raise
        audit('register', None, {'username': username})
        flash('Registered. Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/register-admin-first', methods=['GET', 'POST'])
def register_admin_first():
    """
    Page for creating the very first superadmin.
    This page is only accessible if no admin or superadmin exists.
    """
    exists = query_db("SELECT COUNT(*) AS cnt FROM users WHERE role IN ('admin','superadmin')", one=True)
    if exists and exists.get('cnt', 0) > 0:
        flash('An admin account already exists. Please log in.', 'info')
        return redirect(url_for('login'))

    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data
        name = (form.name.data or 'System Admin').strip()
        if not username or not password:
            flash('Username and password are required.', 'warning')
            return render_template('register_admin_first.html', form=form)
        pw_hash = generate_password_hash(password)
        try:
            execute_db(
                "INSERT INTO users (name, username, password, role, room_number, created_at) VALUES (%s,%s,%s,%s,%s,%s)",
                (name, username, pw_hash, 'superadmin', None, datetime.now())
            )
        except Exception as e:
            if 'Duplicate entry' in str(e) or 'ux_users_username' in str(e):
                flash('Username already exists. Choose another.', 'danger')
                return render_template('register_admin_first.html', form=form)
            raise
        audit('create_superadmin', None, {'username': username})
        flash('Superadmin account created. Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register_admin_first.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data
        user = query_db("SELECT * FROM users WHERE username = %s", (username,), one=True)
        if not user or not user.get('password'):
            flash('Invalid credentials.', 'danger')
            return redirect(url_for('login'))
        try:
            ok = check_password_hash(user['password'], password)
        except Exception:
            ok = False
        if not ok:
            flash('Invalid credentials.', 'danger')
            return redirect(url_for('login'))
        session.clear()
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['role'] = user['role']
        audit('login', user['id'], {'username': user['username']})
        flash('Logged in.', 'success')
        return redirect(url_for('index' if user['role']=='staff' else 'admin'))
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    uid = session.get('user_id')
    session.clear()
    if uid:
        audit('logout', uid)
    flash('Logged out.', 'info')
    return redirect(url_for('login'))

# -------------------------
# Password reset (console dev-only)
# -------------------------
@app.route('/password-reset-request', methods=['GET', 'POST'])
def password_reset_request():
    form = PasswordResetRequestForm()
    if form.validate_on_submit():
        email_or_username = form.username.data.strip()
        user = query_db("SELECT * FROM users WHERE username = %s", (email_or_username,), one=True)
        if not user:
            flash('If the user exists, a reset link was generated (check console).', 'info')
            return redirect(url_for('login'))
        token = serializer.dumps({'user_id': user['id']})
        reset_url = url_for('password_reset', token=token, _external=True)
        print(f"[PASSWORD RESET] User: {user['username']} -> {reset_url} (token expires in 15 minutes)")
        audit('password_reset_requested', user['id'])
        flash('Password reset link generated (check server console).', 'info')
        return redirect(url_for('login'))
    return render_template('password_reset_request.html', form=form)

@app.route('/password-reset/<token>', methods=['GET', 'POST'])
def password_reset(token):
    form = PasswordResetForm()
    try:
        data = serializer.loads(token, max_age=900)  # 15 minutes
    except Exception:
        flash('Invalid or expired reset link.', 'danger')
        return redirect(url_for('login'))

    if form.validate_on_submit():
        new_password = form.new_password.data.strip()
        hashed_pw = generate_password_hash(new_password)
        user_id = data['user_id']
        execute_db("UPDATE users SET password=%s WHERE id=%s", (hashed_pw, user_id))
        audit('password_reset_completed', user_id)
        flash('Password reset successful. Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('password_reset.html', form=form)

# -------------------------
# Submit issue, my-issues, comments
# -------------------------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/submit-issue', methods=['GET', 'POST'])
@login_required
def submit_issue():
    form = SubmitIssueForm()
    if form.validate_on_submit():
        room = form.room.data.strip()
        details = form.details.data or ''
        other_issue = form.other_issue.data or ''
        issues_list = request.form.getlist('issues')
        issues_str = ', '.join(issues_list)
        if other_issue:
            issues_str = (issues_str + ', Other: ' + other_issue) if issues_str else ('Other: ' + other_issue)
        categories = set()
        for it in issues_list:
            grp = ISSUE_TEXT_TO_GROUP.get(it.strip())
            if grp:
                categories.add(grp)
        if not categories and other_issue:
            categories.add('other')
        category_str = ','.join(sorted(categories)) if categories else None
        now = datetime.now()
        if category_str:
            execute_db("INSERT INTO issues (room, issues, other_issue, details, user_id, category, status, submitted_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
                       (room, issues_str, other_issue, details, session.get('user_id'), category_str, 'Pending', now))
        else:
            execute_db("INSERT INTO issues (room, issues, other_issue, details, user_id, status, submitted_at) VALUES (%s,%s,%s,%s,%s,%s,%s)",
                       (room, issues_str, other_issue, details, session.get('user_id'), 'Pending', now))
        audit('issue_submitted', session.get('user_id'), {'room': room, 'issues': issues_str})
        flash('Issue submitted. Thank you.', 'success')
        return render_template('success.html')
    return render_template('report.html', form=form, issue_groups=ISSUE_GROUPS)

@app.route('/my-issues')
@login_required
def my_issues():
    uid = session.get('user_id')
    issues = query_db("SELECT i.id,i.room,i.issues,i.status,i.submitted_at,i.assigned_admin_id,i.category,u.username AS assigned_admin FROM issues i LEFT JOIN users u ON i.assigned_admin_id = u.id WHERE i.user_id = %s ORDER BY i.id DESC", (uid,))
    return render_template('my_issues.html', issues=issues)

@app.route('/issues/<int:issue_id>/comments', methods=['GET', 'POST'])
@login_required
def issue_comments(issue_id):
    form = CommentForm()
    if request.method == 'POST':
        if not form.validate_on_submit():
            flash('Comment is required.', 'warning')
            return redirect(url_for('issue_comments', issue_id=issue_id))
        comment = form.comment.data.strip()
        execute_db("INSERT INTO issue_comments (issue_id, user_id, comment, created_at) VALUES (%s,%s,%s,%s)",
                   (issue_id, session.get('user_id'), comment, datetime.now()))
        audit('comment_added', session.get('user_id'), {'issue_id': issue_id})
        flash('Comment added.', 'success')
        return redirect(url_for('issue_comments', issue_id=issue_id))
    comments = query_db("SELECT c.id,c.comment,c.created_at,u.username FROM issue_comments c JOIN users u ON c.user_id = u.id WHERE c.issue_id = %s ORDER BY c.id ASC", (issue_id,))
    issue = query_db("SELECT * FROM issues WHERE id = %s", (issue_id,), one=True)
    if not issue:
        flash('Issue not found.', 'warning')
        return redirect(url_for('admin') if session.get('role') in ('admin','superadmin') else url_for('my_issues'))
    return render_template('issue_comments.html', issue=issue, comments=comments, form=form)

# -------------------------
# Admin panel, assign & update status
# -------------------------
@app.route('/admin')
@admin_required
def admin():
    category = request.args.get('category', 'All')
    sort = request.args.get('sort', 'id_desc')
    # allow report period as a query param (weekly/monthly/yearly)
    period = request.args.get('period', 'weekly')

    sort_map = {
        'id_desc': 'i.id DESC',
        'id_asc': 'i.id ASC',
        'date_desc': 'i.submitted_at DESC',
        'date_asc': 'i.submitted_at ASC',
        'category_asc': 'i.category ASC',
        'category_desc': 'i.category DESC',
        'status_asc': 'i.status ASC',
        'status_desc': 'i.status DESC'
    }
    order_by = sort_map.get(sort, 'i.id DESC')

    base_query = (
        "SELECT i.id,i.room,i.issues,i.status,i.submitted_at,i.user_id,"
        "i.assigned_admin_id,i.category,u.username AS assigned_admin "
        "FROM issues i LEFT JOIN users u ON i.assigned_admin_id = u.id"
    )
    params = []
    if category and category != 'All':
        base_query += " WHERE i.category LIKE %s"
        params.append('%' + category + '%')
    base_query += f" ORDER BY {order_by} LIMIT 500"

    issues = query_db(base_query, params)
    categories = ['All'] + sorted(ISSUE_GROUPS.keys())

    admin_list = []
    if session.get('role') == 'superadmin':
        admin_list = query_db("SELECT id,name,username,role FROM users WHERE role IN ('admin','superadmin')")

    # make sure AssignIssueForm is defined earlier in your file
    assign_form = AssignIssueForm()

    # compute report summary (used by the dashboard cards)
    try:
        report = compute_report(period)
    except Exception:
        # fallback to simple counts if compute_report fails for some reason
        report = {
            'total_issues': len(issues),
            'by_status': {},
            'by_category': {},
            'time_series': {'labels': [], 'counts': []},
            'top_issues': []
        }

    return render_template(
        'admin.html',
        issues=issues,
        admin_list=admin_list,
        categories=categories,
        selected_category=category,
        selected_sort=sort,
        assign_form=assign_form,
        report=report,
        period=period
    )


@app.route('/assign-issue/<int:issue_id>', methods=['POST'])
@admin_required
def assign_issue(issue_id):
    admin_id = session.get('user_id')
    row = query_db("SELECT assigned_admin_id FROM issues WHERE id = %s", (issue_id,), one=True)
    if not row:
        flash('Issue not found.', 'warning')
        return redirect(url_for('admin'))
    if row.get('assigned_admin_id'):
        flash('Issue already assigned.', 'info')
        return redirect(url_for('admin'))
    execute_db("UPDATE issues SET assigned_admin_id=%s, status=%s WHERE id=%s", (admin_id, 'In Progress', issue_id))
    audit('issue_assigned', admin_id, {'issue_id': issue_id})
    flash('Issue assigned to you and marked In Progress.', 'success')
    return redirect(url_for('admin'))

@app.route('/update-status/<int:issue_id>', methods=['POST'])
@admin_required
def update_status(issue_id):
    new_status = request.form.get('status')
    allowed = ['Pending', 'In Progress', 'Resolved']
    if new_status not in allowed:
        flash('Invalid status.', 'danger')
        return redirect(url_for('admin'))
    row = query_db("SELECT assigned_admin_id FROM issues WHERE id = %s", (issue_id,), one=True)
    admin_id = session.get('user_id')
    if new_status == 'In Progress' and row and not row.get('assigned_admin_id'):
        execute_db("UPDATE issues SET assigned_admin_id=%s, status=%s WHERE id=%s", (admin_id, new_status, issue_id))
        audit('issue_assigned_by_status', admin_id, {'issue_id': issue_id})
    else:
        execute_db("UPDATE issues SET status=%s WHERE id = %s", (new_status, issue_id))
        audit('issue_status_updated', session.get('user_id'), {'issue_id': issue_id, 'status': new_status})
    flash('Issue status updated.', 'success')
    return redirect(url_for('admin'))

# -------------------------
# Search route (basic LIKE search)
# -------------------------
@app.route('/search', methods=['GET', 'POST'])
@admin_required
def search():
    form = SearchForm()
    q = form.q.data if form.q.data else request.args.get('q', '')
    category = form.category.data if form.category.data else request.args.get('category', '')
    status = form.status.data if form.status.data else request.args.get('status', '')
    params = []
    where = []
    if q:
        where.append("(i.issues LIKE %s OR i.details LIKE %s)")
        params.extend(['%' + q + '%', '%' + q + '%'])
    if category:
        where.append("i.category LIKE %s")
        params.append('%' + category + '%')
    if status:
        where.append("i.status = %s")
        params.append(status)
    sql = "SELECT i.id,i.room,i.issues,i.status,i.submitted_at,i.category,u.username AS assigned_admin FROM issues i LEFT JOIN users u ON i.assigned_admin_id = u.id"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY i.submitted_at DESC LIMIT 500"
    issues = query_db(sql, params)
    return render_template('search_results.html', issues=issues, form=form)

# -------------------------
# Simple REST API with token auth
# -------------------------
def _hmac_token(token: str) -> str:
    key = (app.secret_key or '').encode()
    return hmac.new(key, token.encode(), hashlib.sha256).hexdigest()

def generate_api_token(user_id, ttl_hours=24):
    token = secrets.token_urlsafe(32)
    token_h = _hmac_token(token)
    expires = datetime.now() + timedelta(hours=ttl_hours)
    execute_db("INSERT INTO api_tokens (token_hmac, user_id, created_at, expires_at) VALUES (%s,%s,%s,%s)", (token_h, user_id, datetime.now(), expires))
    return token

def get_user_by_api_token(token):
    if not token:
        return None
    token_h = _hmac_token(token)
    row = query_db("SELECT user_id, expires_at FROM api_tokens WHERE token_hmac = %s", (token_h,), one=True)
    if not row:
        return None
    if row.get('expires_at') and row['expires_at'] < datetime.now():
        return None
    return query_db("SELECT * FROM users WHERE id = %s", (row['user_id'],), one=True)

def api_auth_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = (request.headers.get('Authorization') or '').strip()
        if not auth:
            return jsonify({'error':'missing token'}), 401
        if auth.lower().startswith('bearer '):
            token = auth.split(' ',1)[1].strip()
        else:
            token = auth
        user = get_user_by_api_token(token)
        if not user:
            return jsonify({'error':'invalid token'}), 401
        request.api_user = user
        return f(*args, **kwargs)
    return decorated

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.json or {}
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'error':'username and password required'}), 400
    user = query_db("SELECT * FROM users WHERE username = %s", (username,), one=True)
    if not user or not user.get('password'):
        return jsonify({'error':'invalid credentials'}), 401
    try:
        ok = check_password_hash(user['password'], password)
    except Exception:
        ok = False
    if not ok:
        return jsonify({'error':'invalid credentials'}), 401
    token = generate_api_token(user['id'])
    audit('api_login', user['id'])
    return jsonify({'token': token, 'user': {'id': user['id'], 'username': user['username'], 'role': user['role']}})

@app.route('/api/issues', methods=['GET', 'POST'])
@api_auth_required
def api_issues():
    if request.method == 'GET':
        user = request.api_user
        args = request.args
        sql = "SELECT id,room,issues,status,submitted_at,category FROM issues"
        params = []
        where = []
        if args.get('my') == '1':
            where.append("user_id = %s")
            params.append(user['id'])
        if args.get('status'):
            where.append("status = %s")
            params.append(args.get('status'))
        if args.get('category'):
            where.append("category LIKE %s")
            params.append('%' + args.get('category') + '%')
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY submitted_at DESC LIMIT 200"
        rows = query_db(sql, params)
        return jsonify(rows)
    else:
        data = request.json or {}
        room = data.get('room')
        issues_list = data.get('issues') or []
        other_issue = data.get('other_issue', '')
        details = data.get('details', '')
        if not room or not issues_list:
            return jsonify({'error': 'room and issues required'}), 400
        issues_str = ', '.join(issues_list)
        if other_issue:
            issues_str = (issues_str + ', Other: ' + other_issue) if issues_str else ('Other: ' + other_issue)
        categories = set()
        for it in issues_list:
            grp = ISSUE_TEXT_TO_GROUP.get(it.strip())
            if grp:
                categories.add(grp)
        category_str = ','.join(sorted(categories)) if categories else None
        user = request.api_user
        now = datetime.now()
        if category_str:
            execute_db("INSERT INTO issues (room, issues, other_issue, details, user_id, category, status, submitted_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)", (room, issues_str, other_issue, details, user['id'], category_str, 'Pending', now))
        else:
            execute_db("INSERT INTO issues (room, issues, other_issue, details, user_id, status, submitted_at) VALUES (%s,%s,%s,%s,%s,%s,%s)", (room, issues_str, other_issue, details, user['id'], 'Pending', now))
        audit('api_issue_created', user['id'], {'room': room, 'issues': issues_str})
        return jsonify({'status':'ok'}), 201

@app.route('/api/issues/<int:issue_id>', methods=['GET'])
@api_auth_required
def api_issue_detail(issue_id):
    user = request.api_user
    row = query_db("SELECT * FROM issues WHERE id = %s", (issue_id,), one=True)
    if not row:
        return jsonify({'error':'not found'}), 404
    if user['role'] == 'staff' and row.get('user_id') != user['id']:
        return jsonify({'error':'forbidden'}), 403
    return jsonify(row)

# -------------------------
# Reports & PDF export (superadmin)
# -------------------------
def moving_average(data, window=3):
    if not data:
        return []
    if window <= 1:
        return data[:]
    ma = []
    for i in range(len(data)):
        start = max(0, i - window + 1)
        subset = data[start:i + 1]
        ma.append(sum(subset) / len(subset))
    return ma

def linear_regression_slope(xs, ys):
    n = len(xs)
    if n < 2:
        return 0.0
    mean_x = sum(xs) / n
    mean_y = sum(ys) / n
    num = sum((xs[i] - mean_x) * (ys[i] - mean_y) for i in range(n))
    den = sum((xs[i] - mean_x) ** 2 for i in range(n))
    if den == 0:
        return 0.0
    return num / den

def z_score_anomalies(data, threshold=2.5):
    if not data:
        return []
    n = len(data)
    mean = sum(data) / n
    variance = sum((x - mean) ** 2 for x in data) / n
    std = math.sqrt(variance)
    if std == 0:
        return []
    return [i for i, x in enumerate(data) if abs((x - mean) / std) > threshold]

def bucket_dates(start_date, period):
    now = datetime.now()
    labels = []
    if period == 'weekly':
        for i in range(6, -1, -1):
            d = now - timedelta(days=i)
            labels.append(d.strftime('%Y-%m-%d'))
    elif period == 'monthly':
        for i in range(29, -1, -1):
            d = now - timedelta(days=i)
            labels.append(d.strftime('%Y-%m-%d'))
    else:
        for i in range(11, -1, -1):
            d = (now - timedelta(days=30 * i))
            labels.append(d.strftime('%Y-%m'))
    return labels

def compute_report(period='weekly'):
    period = period.lower()
    if period not in ('weekly','monthly','yearly'):
        period = 'weekly'
    now = datetime.now()
    if period == 'weekly':
        start_date = now - timedelta(days=6)
    elif period == 'monthly':
        start_date = now - timedelta(days=29)
    else:
        start_date = now - timedelta(days=365)
    start_str = start_date.strftime('%Y-%m-%d 00:00:00')
    rows = query_db("SELECT id, category, status, issues, submitted_at FROM issues WHERE submitted_at >= %s", (start_str,))
    labels = bucket_dates(start_date, period)
    counts = {label:0 for label in labels}
    total=0
    by_category=Counter()
    by_status=Counter()
    issue_texts=Counter()
    for r in rows:
        total += 1
        cat = r.get('category') or ''
        for c in (cat.split(',') if cat else []):
            c = c.strip()
            if c:
                by_category[c]+=1
        status = r.get('status') or 'Pending'
        by_status[status]+=1
        issues_field = r.get('issues') or ''
        for it in [s.strip() for s in issues_field.split(',') if s.strip()]:
            issue_texts[it]+=1
        submitted = r.get('submitted_at')
        if not submitted:
            continue
        if period in ('weekly','monthly'):
            label = submitted.strftime('%Y-%m-%d')
        else:
            label = submitted.strftime('%Y-%m')
        if label in counts:
            counts[label]+=1
    ts = [counts[label] for label in labels]
    ma = moving_average(ts, window=3)
    xs = list(range(len(ts)))
    slope = linear_regression_slope(xs, ts)
    if slope > 0.1:
        trend='increasing'
    elif slope < -0.1:
        trend='decreasing'
    else:
        trend='stable'
    predicted_next = None
    if ts:
        predicted_next = max(0, ts[-1] + slope)
    anomalies_idx = z_score_anomalies(ts, threshold=2.5)
    anomalies = [labels[i] for i in anomalies_idx]
    top_issues = issue_texts.most_common(10)
    report = {
        'period': period,
        'start_date': start_str,
        'end_date': now.strftime('%Y-%m-%d %H:%M:%S'),
        'total_issues': total,
        'by_category': dict(by_category),
        'by_status': dict(by_status),
        'time_series': {'labels': labels, 'counts': ts, 'moving_average': ma, 'anomalies': anomalies, 'slope': slope, 'trend': trend, 'predicted_next': predicted_next},
        'top_issues': top_issues
    }
    return report

@app.route('/reports')
@superadmin_required
def reports():
    period = request.args.get('period', 'weekly')
    report = compute_report(period)
    return render_template('reports.html', report=report)

@app.route('/reports/json')
@superadmin_required
def reports_json():
    period = request.args.get('period', 'weekly')
    return jsonify(compute_report(period))

# PDF creation (simple textual)
def create_pdf_bytes(report):
    if not reportlab_available or pdf_canvas is None:
        raise RuntimeError('reportlab missing; install reportlab (pip install reportlab)')
    buffer = BytesIO()
    p = pdf_canvas.Canvas(buffer, pagesize=letter)
    width, height = letter
    title = f"ICT Support Report ({report['period'].capitalize()})"
    p.setFont('Helvetica-Bold', 16)
    p.drawString(inch, height - inch, title)
    p.setFont('Helvetica', 10)
    p.drawString(inch, height - inch - 18, f"From: {report['start_date']} To: {report['end_date']}")
    y = height - inch - 40
    p.setFont('Helvetica-Bold', 12)
    p.drawString(inch, y, f"Total issues: {report['total_issues']}")
    y -= 18
    p.setFont('Helvetica-Bold', 11)
    p.drawString(inch, y, 'By Category:')
    y -= 14
    p.setFont('Helvetica', 10)
    if report['by_category']:
        for cat, cnt in sorted(report['by_category'].items(), key=lambda x:-x[1]):
            p.drawString(inch+8, y, f"{cat}: {cnt}")
            y -= 12
            if y < inch:
                p.showPage(); y = height - inch
    else:
        p.drawString(inch+8, y, 'No category data'); y -= 12
    y -= 6
    p.setFont('Helvetica-Bold', 11); p.drawString(inch, y, 'By Status:')
    y -= 14; p.setFont('Helvetica',10)
    if report['by_status']:
        for st,cnt in sorted(report['by_status'].items(), key=lambda x:-x[1]):
            p.drawString(inch+8,y,f"{st}: {cnt}"); y -= 12
            if y < inch: p.showPage(); y = height - inch
    else:
        p.drawString(inch+8, y, 'No status data'); y -= 12
    y -= 6
    p.setFont('Helvetica-Bold',11); p.drawString(inch, y, 'Top Issues:')
    y -= 14; p.setFont('Helvetica',10)
    if report['top_issues']:
        for it,cnt in report['top_issues']:
            p.drawString(inch+8, y, f"{it} ({cnt})"); y -= 12
            if y < inch: p.showPage(); y = height - inch
    else:
        p.drawString(inch+8, y, 'No recurring issues'); y -= 12
    if y < 200: p.showPage(); y = height - inch
    p.setFont('Helvetica-Bold', 11); p.drawString(inch,y,'Time Series (label : count)'); y -= 16
    p.setFont('Helvetica',9)
    labels = report['time_series']['labels']; counts = report['time_series']['counts']
    for label, cnt in zip(labels, counts):
        p.drawString(inch+8, y, f"{label} : {cnt}"); y -= 12
        if y < inch: p.showPage(); y = height - inch
    y -= 10
    p.setFont('Helvetica-Bold',11); p.drawString(inch,y, f"Trend: {report['time_series'].get('trend','N/A')}")
    y -= 14; p.setFont('Helvetica', 10); p.drawString(inch, y, f"Predicted next bucket: {report['time_series'].get('predicted_next','N/A')}")
    p.showPage(); p.save(); buffer.seek(0)
    return buffer

@app.route('/reports/pdf')
@superadmin_required
def reports_pdf():
    if not reportlab_available:
        flash('PDF export requires reportlab. Install it: pip install reportlab', 'danger')
        return redirect(url_for('reports'))
    period = request.args.get('period', 'weekly')
    report = compute_report(period)
    try:
        pdf_bytes = create_pdf_bytes(report)
    except Exception as e:
        print('PDF error creating bytes:', e)
        print(traceback.format_exc())
        flash('Could not create PDF.', 'danger')
        return redirect(url_for('reports'))
    filename = f"ict_report_{period}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    return send_file(pdf_bytes, mimetype='application/pdf', as_attachment=True, download_name=filename)

# -------------------------
# Admin user management (fixed)
# -------------------------
@app.route('/manage-admins')
@admin_required
def manage_admins():
    if session.get('role') != 'superadmin':
        flash('Only superadmin can manage admins.', 'danger')
        return redirect(url_for('admin'))
    admins = query_db("SELECT id, name, username, role FROM users WHERE role IN ('admin','superadmin') ORDER BY id")
    form = AddAdminForm()
    delete_form = DeleteAdminForm()
    return render_template('manage_admins.html', admins=admins, form=form, delete_form=delete_form)



@app.route('/add-admin', methods=['POST'])
@admin_required
def add_admin():
    if session.get('role') != 'superadmin':
        flash('Only superadmin can add admins.', 'danger')
        return redirect(url_for('admin'))
    form = AddAdminForm()
    if not form.validate_on_submit():
        for field, errors in form.errors.items():
            for err in errors:
                flash(f"{field}: {err}", 'warning')
        return redirect(url_for('manage_admins'))
    name = form.name.data or ''
    username = form.username.data.strip()
    password = form.password.data
    if query_db("SELECT * FROM users WHERE username = %s", (username,), one=True):
        flash('Username exists.', 'danger')
        return redirect(url_for('manage_admins'))
    pw_hash = generate_password_hash(password)
    try:
        execute_db("INSERT INTO users (name, username, password, role, room_number, created_at) VALUES (%s,%s,%s,%s,%s,%s)", (name, username, pw_hash, 'admin', None, datetime.now()))
    except Exception as e:
        if 'Duplicate entry' in str(e):
            flash('Username already exists.', 'danger')
            return redirect(url_for('manage_admins'))
        raise
    audit('admin_created', session.get('user_id'), {'username': username})
    flash('Admin created.', 'success')
    return redirect(url_for('manage_admins'))

@app.route('/delete-admin/<int:user_id>', methods=['POST'])
@admin_required
def delete_admin(user_id):
    if session.get('role') != 'superadmin':
        flash('Only superadmin can delete admins.', 'danger')
        return redirect(url_for('manage_admins'))

    form = DeleteAdminForm()
    if not form.validate_on_submit():
        flash('Invalid request (CSRF).', 'warning')
        return redirect(url_for('manage_admins'))

    if user_id == session.get('user_id'):
        flash('Cannot delete yourself.', 'warning')
        return redirect(url_for('manage_admins'))

    execute_db("DELETE FROM users WHERE id = %s AND role = 'admin'", (user_id,))
    audit('admin_deleted', session.get('user_id'), {'deleted_id': user_id})
    flash('Admin removed (if existed).', 'success')
    return redirect(url_for('manage_admins'))



# -------------------------
# Startup
# -------------------------
if __name__ == '__main__':
    with app.app_context():
        ensure_schema()
    debug_flag = os.getenv('FLASK_DEBUG') in ('1', 'true', 'True')
    app.run(debug=debug_flag)
