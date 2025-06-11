from flask import Flask, render_template, request, redirect, url_for
from flask_mysqldb import MySQL
from flask_paginate import Pagination, get_page_parameter
from flask import flash


# Initialize the Flask application
app = Flask(__name__)

# MySQL configurations
# IMPORTANT: Replace 'your_mysql_user' and 'your_mysql_password' with your actual MySQL credentials.
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'ombati'
app.config['MYSQL_PASSWORD'] = 'Mama001!'
app.config['MYSQL_DB'] = 'helpdesk'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor' # Optional: returns results as dict

# Initialize MySQL with the Flask app
mysql = MySQL(app)

@app.route('/')
def index():
    """
    Renders the report submission form.
    This assumes you have a 'report.html' file in a 'templates' directory.
    """
    return render_template('report.html')

@app.route('/submit-issue', methods=['POST'])
def submit_issue():
    """
    Handles the submission of issue reports.
    It retrieves data from the form and inserts it into the MySQL database.
    """
    # Get room number from the form
    room = request.form.get('room')

    # Get selected issues from the checkboxes (returns a list)
    issues = request.form.getlist('issues')

    # Get the "other issue" text input
    other_issue = request.form.get('other_issue')

    # Get additional details from the textarea
    details = request.form.get('details')

    # Combine issues into one string for database storage
    # First, join the checkbox issues with a comma
    issues_str = ', '.join(issues)
    if other_issue:
        # If 'other_issue' is provided, append it to the combined string
        # using a comma for separation.
        issues_str += f", Other: {other_issue}"

    try:
        # Establish a database connection and create a cursor
        cur = mysql.connection.cursor()

        # Execute the SQL INSERT statement
        # The 'issues' table should have columns: room, issues, other_issue, details
        # Note: 'issues' column will store the combined string of selected issues.
        # 'other_issue' column will store the raw text from the 'other_issue' field,
        # or be NULL if not provided.
        cur.execute("""
            INSERT INTO issues (room, issues, other_issue, details)
            VALUES (%s, %s, %s, %s)
        """, (room, issues_str, other_issue, details))

        # Commit the transaction to save changes to the database
        mysql.connection.commit()

        # Close the cursor
        cur.close()

        # Render the success.html template after successful submission
        return render_template('success.html')

    except Exception as e:
        # Basic error handling: print the error and return an error message
        print(f"Database error: {e}")
        return "An error occurred while submitting the issue. Please try again."
    
@app.route('/admin')
def admin():
    status = request.args.get('status', 'All')
    partial = request.args.get('partial') == '1'
    page = request.args.get(get_page_parameter(), type=int, default=1)
    per_page = 100

    cur = mysql.connection.cursor()

    # Count query
    count_query = "SELECT COUNT(*) as total FROM issues"
    count_params = []
    if status != 'All':
        count_query += " WHERE status = %s"
        count_params.append(status)
    cur.execute(count_query, count_params)
    total = cur.fetchone()['total']

    # Data query
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

    # Validate status input
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
    app.secret_key = 'your_super_secret_key'
    # Run the Flask development server
    # debug=True allows for automatic reloading on code changes and provides a debugger.
    app.run(debug=True)
