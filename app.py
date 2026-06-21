from flask import Flask, render_template, request, Response, redirect, session
import csv, io, os, json, secrets, zipfile
from functools import wraps

from log_analysis import analyze_log
from recon import scan_ports
from packet import analyze_pcap
from packet import analyze_live_packets
from threat import analyze_website

from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime

# -----------------------------
# APP CONFIG
# -----------------------------
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

app.config["MYSQL_HOST"] = "localhost"
app.config["MYSQL_USER"] = "root"
app.config["MYSQL_PASSWORD"] = "Rahul2205@"
app.config["MYSQL_DB"] = "cyber_db"

mysql = MySQL(app)

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs("results", exist_ok=True)
ALLOWED_UPLOAD_EXTENSIONS = {"log", "txt", "pcap"}

# -----------------------------
# LOGIN REQUIRED DECORATOR
# -----------------------------
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user" not in session:
            return redirect("/login")
        if session.get("is_blocked"):
            session.clear()
            return redirect("/login")
        if is_session_forced_out():
            session.clear()
            return redirect("/login")
        touch_user_session()
        return f(*args, **kwargs)
    return wrapper

# -----------------------------
# AUTH SYSTEM
# -----------------------------
def csrf_token():
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def validate_csrf():
    token = session.get("csrf_token")
    submitted = request.form.get("csrf_token", "")
    return token and secrets.compare_digest(token, submitted)


def generate_captcha():
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789abcdefghijklmnopqrstuvwxyz"
    captcha_code = "".join(secrets.choice(alphabet) for _ in range(6))
    session["captcha_answer"] = captcha_code
    return captcha_code


def validate_captcha():
    expected_answer = session.get("captcha_answer")
    submitted_answer = request.form.get("captcha_answer", "").strip().upper()
    return expected_answer and secrets.compare_digest(expected_answer, submitted_answer)


def valid_password(password):
    if len(password) < 8:
        return False

    checks = [
        any(char.islower() for char in password),
        any(char.isupper() for char in password),
        any(char.isdigit() for char in password),
        any(not char.isalnum() for char in password),
    ]
    return sum(checks) >= 3


app.jinja_env.globals["csrf_token"] = csrf_token


activity_table_ready = False


def ensure_activity_table():
    global activity_table_ready

    if activity_table_ready:
        return

    try:
        cur = mysql.connection.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS user_activity (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(255) NOT NULL,
                action VARCHAR(100) NOT NULL,
                details TEXT,
                ip_address VARCHAR(64),
                user_agent TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_user_activity_username (username),
                INDEX idx_user_activity_created_at (created_at)
            )
            """
        )
        mysql.connection.commit()
        activity_table_ready = True
    except Exception:
        mysql.connection.rollback()


def ensure_reports_table():
    try:
        cur = mysql.connection.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_reports (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(255) NOT NULL,
                tool VARCHAR(100) NOT NULL,
                target VARCHAR(500),
                summary TEXT,
                result_json LONGTEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_scan_reports_username (username),
                INDEX idx_scan_reports_tool (tool),
                INDEX idx_scan_reports_created_at (created_at)
            )
            """
        )
        mysql.connection.commit()
    except Exception:
        mysql.connection.rollback()


def ensure_notifications_table():
    try:
        cur = mysql.connection.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS admin_notifications (
                id INT AUTO_INCREMENT PRIMARY KEY,
                title VARCHAR(150) NOT NULL,
                message TEXT,
                category VARCHAR(80) NOT NULL DEFAULT 'system',
                is_read TINYINT(1) NOT NULL DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_admin_notifications_read (is_read),
                INDEX idx_admin_notifications_created_at (created_at)
            )
            """
        )
        mysql.connection.commit()
    except Exception:
        mysql.connection.rollback()


def ensure_tool_permissions_table():
    try:
        cur = mysql.connection.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS user_tool_permissions (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(255) NOT NULL,
                tool_key VARCHAR(80) NOT NULL,
                allowed TINYINT(1) NOT NULL DEFAULT 1,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                UNIQUE KEY uniq_user_tool (username, tool_key)
            )
            """
        )
        mysql.connection.commit()
    except Exception:
        mysql.connection.rollback()


def ensure_user_sessions_table():
    try:
        cur = mysql.connection.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS user_sessions (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(255) NOT NULL,
                session_token VARCHAR(128) NOT NULL,
                current_page VARCHAR(255),
                ip_address VARCHAR(64),
                user_agent TEXT,
                is_active TINYINT(1) NOT NULL DEFAULT 1,
                force_logout TINYINT(1) NOT NULL DEFAULT 0,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE KEY uniq_session_token (session_token),
                INDEX idx_user_sessions_username (username),
                INDEX idx_user_sessions_last_seen (last_seen)
            )
            """
        )
        mysql.connection.commit()
    except Exception:
        mysql.connection.rollback()


def add_column_if_missing(table, column, definition):
    if not has_column(table, column):
        cur = mysql.connection.cursor()
        cur.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
        mysql.connection.commit()


def ensure_user_management_columns():
    try:
        add_column_if_missing("users", "is_admin", "TINYINT(1) NOT NULL DEFAULT 0")
        add_column_if_missing("users", "role", "VARCHAR(50) NOT NULL DEFAULT 'user'")
        add_column_if_missing("users", "is_blocked", "TINYINT(1) NOT NULL DEFAULT 0")
        add_column_if_missing("users", "failed_login_attempts", "INT NOT NULL DEFAULT 0")
        add_column_if_missing("users", "locked_until", "DATETIME NULL")
        add_column_if_missing("users", "must_change_password", "TINYINT(1) NOT NULL DEFAULT 0")
        add_column_if_missing("users", "email", "VARCHAR(255) NULL")
        add_column_if_missing("users", "phone", "VARCHAR(50) NULL")
        add_column_if_missing("users", "department", "VARCHAR(120) NULL")
        add_column_if_missing("users", "account_status", "VARCHAR(40) NOT NULL DEFAULT 'active'")
        add_column_if_missing("users", "preferred_theme", "VARCHAR(20) NOT NULL DEFAULT 'dark'")
    except Exception:
        mysql.connection.rollback()


TOOLS = [
    {"key": "log", "label": "Log Analysis", "route": "/log"},
    {"key": "recon", "label": "Network Recon", "route": "/recon"},
    {"key": "packet", "label": "Packet Inspection", "route": "/packet"},
    {"key": "threat", "label": "Threat Intelligence", "route": "/threat"},
]


def create_admin_notification(title, message, category="system"):
    ensure_notifications_table()
    try:
        cur = mysql.connection.cursor()
        cur.execute(
            """
            INSERT INTO admin_notifications(title, message, category)
            VALUES(%s, %s, %s)
            """,
            (title, message, category),
        )
        mysql.connection.commit()
    except Exception:
        mysql.connection.rollback()


def touch_user_session():
    token = session.get("session_token")
    username = session.get("user")
    if not token or not username:
        return

    ensure_user_sessions_table()
    try:
        cur = mysql.connection.cursor()
        cur.execute(
            """
            INSERT INTO user_sessions(username, session_token, current_page, ip_address, user_agent, is_active, force_logout, last_seen)
            VALUES(%s, %s, %s, %s, %s, 1, 0, NOW())
            ON DUPLICATE KEY UPDATE
                current_page=VALUES(current_page),
                ip_address=VALUES(ip_address),
                user_agent=VALUES(user_agent),
                is_active=1,
                last_seen=NOW()
            """,
            (
                username,
                token,
                request.path,
                request.headers.get("X-Forwarded-For", request.remote_addr),
                request.headers.get("User-Agent", "")[:500],
            ),
        )
        mysql.connection.commit()
    except Exception:
        mysql.connection.rollback()


def is_session_forced_out():
    token = session.get("session_token")
    if not token:
        return False

    ensure_user_sessions_table()
    try:
        cur = mysql.connection.cursor()
        cur.execute("SELECT force_logout FROM user_sessions WHERE session_token=%s", (token,))
        row = cur.fetchone()
        return bool(row and row[0])
    except Exception:
        mysql.connection.rollback()
        return False


def end_current_session():
    token = session.get("session_token")
    if not token:
        return

    ensure_user_sessions_table()
    try:
        cur = mysql.connection.cursor()
        cur.execute("UPDATE user_sessions SET is_active=0 WHERE session_token=%s", (token,))
        mysql.connection.commit()
    except Exception:
        mysql.connection.rollback()


def has_tool_access(tool_key):
    if is_current_admin():
        return True

    ensure_tool_permissions_table()
    username = session.get("user")
    if not username:
        return False

    try:
        cur = mysql.connection.cursor()
        cur.execute(
            "SELECT allowed FROM user_tool_permissions WHERE username=%s AND tool_key=%s",
            (username, tool_key),
        )
        row = cur.fetchone()
        return True if row is None else bool(row[0])
    except Exception:
        mysql.connection.rollback()
        return True


def tool_required(tool_key):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if not has_tool_access(tool_key):
                record_activity("permission_denied", f"Denied access to {tool_key}")
                return render_template(
                    "permission_denied.html",
                    tool=next((tool for tool in TOOLS if tool["key"] == tool_key), {"label": tool_key}),
                ), 403
            return f(*args, **kwargs)
        return wrapper
    return decorator


def save_uploaded_file(file, allowed_extensions):
    filename = secure_filename(file.filename or "")
    extension = filename.rsplit(".", 1)[1].lower() if "." in filename else ""

    if not filename or extension not in allowed_extensions:
        return None

    path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(path)
    return path


def record_activity(action, details=""):
    username = session.get("user")
    if not username:
        return

    ensure_activity_table()

    try:
        cur = mysql.connection.cursor()
        cur.execute(
            """
            INSERT INTO user_activity(username, action, details, ip_address, user_agent)
            VALUES(%s, %s, %s, %s, %s)
            """,
            (
                username,
                action,
                details,
                request.headers.get("X-Forwarded-For", request.remote_addr),
                request.headers.get("User-Agent", "")[:500],
            ),
        )
        mysql.connection.commit()
    except Exception:
        mysql.connection.rollback()


def record_report(tool, target, data, summary=""):
    username = session.get("user")
    if not username:
        return

    ensure_reports_table()

    try:
        cur = mysql.connection.cursor()
        cur.execute(
            """
            INSERT INTO scan_reports(username, tool, target, summary, result_json)
            VALUES(%s, %s, %s, %s, %s)
            """,
            (username, tool, target, summary, json.dumps(data, default=str)),
        )
        mysql.connection.commit()
    except Exception:
        mysql.connection.rollback()


def activity_label(action):
    labels = {
        "login": "Login",
        "logout": "Logout",
        "change_password": "Change Password",
        "view_dashboard": "Dashboard",
        "view_profile": "Profile",
        "open_log_analysis": "Log Analysis",
        "log_analysis": "Log Analysis",
        "open_network_recon": "Network Recon",
        "network_recon": "Network Recon",
        "open_packet_analysis": "Packet Inspection",
        "packet_analysis": "Packet Inspection",
        "open_live_packet_monitor": "Live Packet Monitor",
        "live_packet_monitor": "Live Packet Monitor",
        "open_threat_intelligence": "Threat Intelligence",
        "threat_intelligence": "Threat Intelligence",
        "admin_delete_user": "Admin Action",
        "admin_reset_password": "Admin Action",
        "admin_create_admin": "Admin Action",
        "admin_promote_user": "Admin Action",
        "admin_block_user": "Admin Action",
        "admin_unblock_user": "Admin Action",
        "admin_update_role": "Admin Action",
        "admin_update_status": "Admin Action",
        "admin_force_logout": "Admin Action",
        "admin_update_permissions": "Admin Action",
        "admin_export_users": "Admin Export",
        "admin_export_activity": "Admin Export",
        "admin_export_reports": "Admin Export",
        "admin_backup_download": "Admin Backup",
        "admin_restore_backup": "Admin Backup",
        "permission_denied": "Permission Denied",
        "view_reports": "Reports",
        "compare_reports": "Report Compare",
        "view_help": "Help",
    }
    return labels.get(action, action.replace("_", " ").title())


def has_column(table, column):
    cur = mysql.connection.cursor()
    cur.execute(f"SHOW COLUMNS FROM {table} LIKE %s", (column,))
    return cur.fetchone() is not None


def ensure_admin_column():
    ensure_user_management_columns()


def is_current_admin():
    username = session.get("user")
    if not username:
        return False

    if username.lower() == "admin":
        return True

    try:
        ensure_admin_column()
        cur = mysql.connection.cursor()
        cur.execute("SELECT is_admin, role FROM users WHERE username=%s", (username,))
        row = cur.fetchone()
        if row and (row[0] or row[1] in ("admin", "super_admin")):
            return True

    except Exception:
        mysql.connection.rollback()

    return False


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user" not in session:
            return redirect("/login")
        if is_session_forced_out():
            session.clear()
            return redirect("/login")

        if not is_current_admin():
            return redirect("/")

        touch_user_session()
        return f(*args, **kwargs)
    return wrapper


# SIGNUP
@app.route("/signup", methods=["GET", "POST"])
def signup():
    ensure_user_management_columns()
    if request.method == "POST":
        if not validate_csrf():
            return render_template("signup.html", error="Invalid request. Please try again."), 400

        name = request.form["name"].strip()
        username = request.form["username"].strip()
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()
        department = request.form.get("department", "").strip()
        raw_password = request.form["password"]

        if not valid_password(raw_password):
            return render_template(
                "signup.html",
                error="Password must be at least 8 characters and include 3 of: uppercase, lowercase, number, symbol."
            ), 400

        password = generate_password_hash(raw_password)

        cur = mysql.connection.cursor()

        # check duplicate username
        cur.execute("SELECT * FROM users WHERE username=%s", (username,))
        if cur.fetchone():
            return render_template("signup.html", error="Username already exists"), 409

        cur.execute(
            """
            INSERT INTO users(name, username, password, role, is_admin, email, phone, department, account_status)
            VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            (name, username, password, "user", 0, email or None, phone or None, department or None, "active")
        )
        mysql.connection.commit()
        create_admin_notification("New signup", f"{name} ({username}) created an account.", "signup")

        return redirect("/login")

    return render_template("signup.html")


# LOGIN (USERNAME BASED)
@app.route("/login", methods=["GET", "POST"])
def login():
    ensure_user_management_columns()

    if request.method == "POST":
        if not validate_csrf():
            return render_template("login.html", error="Invalid request. Please try again.", captcha_question=generate_captcha()), 400

        if not validate_captcha():
            return render_template("login.html", error="Incorrect CAPTCHA answer. Please try again.", captcha_question=generate_captcha()), 400

        username = request.form["username"].strip()
        password = request.form["password"]

        cur = mysql.connection.cursor()
        cur.execute(
            """
            SELECT id, name, username, password, is_admin, role, is_blocked,
                   failed_login_attempts, locked_until, must_change_password, account_status, preferred_theme
            FROM users
            WHERE username=%s
            """,
            (username,),
        )
        user = cur.fetchone()

        if user:
            if user[6]:
                return render_template("login.html", error="This account is blocked. Contact the administrator.", captcha_question=generate_captcha()), 403

            if user[10] != "active":
                return render_template("login.html", error=f"Your account status is {user[10]}. Contact the administrator.", captcha_question=generate_captcha()), 403

            locked_until = user[8]
            if locked_until and locked_until > datetime.now():
                return render_template("login.html", error=f"Account locked until {locked_until}.", captcha_question=generate_captcha()), 423

            if check_password_hash(user[3], password):
                cur.execute(
                    """
                    UPDATE users
                    SET failed_login_attempts=0, locked_until=NULL
                    WHERE id=%s
                    """,
                    (user[0],),
                )
                mysql.connection.commit()
                session.clear()
                csrf_token()
                session["user"] = user[2]  # username
                session["account_name"] = user[1]
                session["role"] = user[5]
                session["is_admin"] = bool(user[4])
                session["is_blocked"] = bool(user[6])
                session["theme"] = user[11] or "dark"
                session["session_token"] = secrets.token_urlsafe(32)
                touch_user_session()
                record_activity("login", "Signed in successfully")
                if user[9]:
                    return redirect("/change-password")
                return redirect("/")
            else:
                attempts = (user[7] or 0) + 1
                if attempts >= 5:
                    cur.execute(
                        """
                        UPDATE users
                        SET failed_login_attempts=%s,
                            locked_until=DATE_ADD(NOW(), INTERVAL 15 MINUTE)
                        WHERE id=%s
                        """,
                        (attempts, user[0]),
                    )
                    mysql.connection.commit()
                    create_admin_notification("Account locked", f"{username} was locked after failed login attempts.", "security")
                    return render_template("login.html", error="Too many failed attempts. Account locked for 15 minutes.", captcha_question=generate_captcha()), 423

                cur.execute(
                    "UPDATE users SET failed_login_attempts=%s WHERE id=%s",
                    (attempts, user[0]),
                )
                mysql.connection.commit()
                return render_template("login.html", error="Invalid username or password", captcha_question=generate_captcha()), 401
        else:
            return render_template("login.html", error="Invalid username or password", captcha_question=generate_captcha()), 401

    return render_template("login.html", captcha_question=generate_captcha())


# LOGOUT
@app.route("/logout")
def logout():
    record_activity("logout", "Signed out")
    end_current_session()
    session.clear()
    return redirect("/login")


# FORGOT PASSWORD
@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    if request.method == "POST":
        if not validate_csrf():
            return render_template("forgot.html", error="Invalid request. Please try again."), 400

        return render_template(
            "forgot.html",
            message="If this account exists, contact the administrator to verify your identity and reset access."
        )

    return render_template("forgot.html")


# CHANGE PASSWORD
@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        if not validate_csrf():
            return render_template("change_password.html", error="Invalid request. Please try again."), 400

        current_password = request.form["current_password"]
        new_password = request.form["new_password"]
        confirm_password = request.form["confirm_password"]

        if new_password != confirm_password:
            return render_template("change_password.html", error="New passwords do not match."), 400

        if not valid_password(new_password):
            return render_template(
                "change_password.html",
                error="Password must be at least 8 characters and include 3 of: uppercase, lowercase, number, symbol."
            ), 400

        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE username=%s", (session["user"],))
        user = cur.fetchone()

        if not user or not check_password_hash(user[3], current_password):
            return render_template("change_password.html", error="Current password is incorrect."), 401

        new_hash = generate_password_hash(new_password)
        cur.execute(
            "UPDATE users SET password=%s, must_change_password=0 WHERE username=%s",
            (new_hash, session["user"])
        )
        mysql.connection.commit()
        record_activity("change_password", "Changed account password")
        return render_template("change_password.html", message="Password updated successfully.")

    return render_template("change_password.html")


# -----------------------------
# DOWNLOAD HELPER
# -----------------------------
def download_json(data, filename):
    return Response(
        json.dumps(data, indent=4),
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment;filename={filename}"}
    )


def download_csv(filename, headers, rows):
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(headers)
    writer.writerows(rows)

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment;filename={filename}"}
    )


def escape_pdf_text(value):
    return str(value).replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def build_simple_pdf(title, rows):
    lines = [title, ""]
    lines.extend(rows)
    text_commands = ["BT", "/F1 12 Tf", "50 790 Td", "16 TL"]

    for line in lines[:44]:
        text_commands.append(f"({escape_pdf_text(line)}) Tj")
        text_commands.append("T*")

    text_commands.append("ET")
    stream = "\n".join(text_commands).encode("latin-1", errors="replace")
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream",
    ]
    pdf = bytearray(b"%PDF-1.4\n")
    offsets = [0]

    for index, obj in enumerate(objects, start=1):
        offsets.append(len(pdf))
        pdf.extend(f"{index} 0 obj\n".encode())
        pdf.extend(obj)
        pdf.extend(b"\nendobj\n")

    xref_position = len(pdf)
    pdf.extend(f"xref\n0 {len(objects) + 1}\n".encode())
    pdf.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        pdf.extend(f"{offset:010d} 00000 n \n".encode())

    pdf.extend(
        f"trailer << /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_position}\n%%EOF".encode()
    )
    return bytes(pdf)


def get_report_or_404(report_id):
    ensure_reports_table()
    cur = mysql.connection.cursor()
    cur.execute(
        """
        SELECT id, username, tool, target, summary, result_json, created_at
        FROM scan_reports
        WHERE id=%s
        """,
        (report_id,),
    )
    row = cur.fetchone()

    if not row:
        return None

    report = {
        "id": row[0],
        "username": row[1],
        "tool": row[2],
        "target": row[3],
        "summary": row[4],
        "result_json": row[5],
        "created_at": row[6],
    }

    if report["username"] != session.get("user") and not is_current_admin():
        return None

    try:
        report["result"] = json.loads(report["result_json"] or "{}")
    except json.JSONDecodeError:
        report["result"] = {}

    return report


# -----------------------------
# HOME (PROTECTED)
# -----------------------------
@app.route("/")
def home():
    if "user" in session:
        record_activity("view_dashboard", "Opened main dashboard")
        account_name = session["user"]
        dashboard_summary = {
            "total_reports": 0,
            "last_report": None,
            "last_activity": None,
            "allowed_tools": TOOLS,
            "allowed_tool_keys": [tool["key"] for tool in TOOLS],
        }

        try:
            cur = mysql.connection.cursor()
            cur.execute("SELECT name FROM users WHERE username=%s", (session["user"],))
            user_row = cur.fetchone()
            if user_row and user_row[0]:
                account_name = user_row[0]
            ensure_reports_table()
            cur.execute(
                """
                SELECT COUNT(*), MAX(created_at)
                FROM scan_reports
                WHERE username=%s
                """,
                (session["user"],),
            )
            report_row = cur.fetchone()
            dashboard_summary["total_reports"] = report_row[0] if report_row else 0
            dashboard_summary["last_report"] = report_row[1] if report_row else None
            ensure_activity_table()
            cur.execute(
                """
                SELECT action, details, created_at
                FROM user_activity
                WHERE username=%s
                ORDER BY created_at DESC
                LIMIT 1
                """,
                (session["user"],),
            )
            activity_row = cur.fetchone()
            if activity_row:
                dashboard_summary["last_activity"] = {
                    "label": activity_label(activity_row[0]),
                    "details": activity_row[1],
                    "created_at": activity_row[2],
                }
            dashboard_summary["allowed_tools"] = [
                tool for tool in TOOLS if has_tool_access(tool["key"])
            ]
            dashboard_summary["allowed_tool_keys"] = [
                tool["key"] for tool in dashboard_summary["allowed_tools"]
            ]
        except Exception:
            mysql.connection.rollback()

        return render_template(
            "index.html",
            user=session["user"],
            account_name=account_name,
            is_admin=is_current_admin(),
            dashboard_summary=dashboard_summary,
        )
    return redirect("/login")


@app.route("/profile")
@login_required
def profile():
    ensure_user_management_columns()
    ensure_activity_table()
    ensure_reports_table()

    cur = mysql.connection.cursor()
    cur.execute(
        """
        SELECT name, username, role, is_admin, is_blocked, failed_login_attempts,
               locked_until, must_change_password
        FROM users
        WHERE username=%s
        """,
        (session["user"],),
    )
    row = cur.fetchone()
    account = {
        "name": row[0],
        "username": row[1],
        "role": row[2],
        "is_admin": bool(row[3]),
        "is_blocked": bool(row[4]),
        "failed_login_attempts": row[5],
        "locked_until": row[6],
        "must_change_password": bool(row[7]),
    } if row else None

    cur.execute(
        """
        SELECT action, details, ip_address, created_at
        FROM user_activity
        WHERE username=%s
        ORDER BY created_at DESC
        LIMIT 50
        """,
        (session["user"],),
    )
    activities = [
        {
            "action": row[0],
            "label": activity_label(row[0]),
            "details": row[1],
            "ip_address": row[2],
            "created_at": row[3],
        }
        for row in cur.fetchall()
    ]

    cur.execute(
        """
        SELECT id, tool, target, summary, created_at
        FROM scan_reports
        WHERE username=%s
        ORDER BY created_at DESC
        LIMIT 25
        """,
        (session["user"],),
    )
    reports = [
        {
            "id": row[0],
            "tool": row[1],
            "target": row[2],
            "summary": row[3],
            "created_at": row[4],
        }
        for row in cur.fetchall()
    ]

    record_activity("view_profile", "Opened profile page")
    return render_template("profile.html", account=account, activities=activities, reports=reports)


@app.route("/reports/<int:report_id>")
@login_required
def report_detail(report_id):
    report = get_report_or_404(report_id)
    if not report:
        return redirect("/profile")

    record_activity("view_report", f"Opened report #{report_id}")
    return render_template("report.html", report=report)


@app.route("/reports/<int:report_id>/download-json")
@login_required
def report_download_json(report_id):
    report = get_report_or_404(report_id)
    if not report:
        return redirect("/profile")

    return download_json(report["result"], f"report-{report_id}.json")


@app.route("/reports/<int:report_id>/download-pdf")
@login_required
def report_download_pdf(report_id):
    report = get_report_or_404(report_id)
    if not report:
        return redirect("/profile")

    result_preview = json.dumps(report["result"], indent=2, default=str).splitlines()
    rows = [
        f"Tool: {report['tool']}",
        f"User: {report['username']}",
        f"Target: {report['target'] or '-'}",
        f"Summary: {report['summary'] or '-'}",
        f"Created: {report['created_at']}",
        "",
        "Result Preview:",
    ]
    rows.extend(result_preview[:32])
    pdf = build_simple_pdf(f"CyberShield X Report #{report_id}", rows)

    return Response(
        pdf,
        mimetype="application/pdf",
        headers={"Content-Disposition": f"attachment;filename=report-{report_id}.pdf"}
    )


@app.route("/reports")
@login_required
def reports_history():
    ensure_reports_table()
    search = request.args.get("search", "").strip()
    tool_filter = request.args.get("tool", "").strip()
    user_filter = request.args.get("user", "").strip()

    query = """
        SELECT id, username, tool, target, summary, created_at
        FROM scan_reports
    """
    conditions = []
    params = []

    if not is_current_admin():
        conditions.append("username=%s")
        params.append(session["user"])
    elif user_filter:
        conditions.append("username=%s")
        params.append(user_filter)

    if tool_filter:
        conditions.append("tool=%s")
        params.append(tool_filter)

    if search:
        conditions.append("(username LIKE %s OR tool LIKE %s OR target LIKE %s OR summary LIKE %s)")
        term = f"%{search}%"
        params.extend([term, term, term, term])

    if conditions:
        query += " WHERE " + " AND ".join(conditions)

    query += " ORDER BY created_at DESC LIMIT 300"

    cur = mysql.connection.cursor()
    cur.execute(query, tuple(params))
    reports = [
        {
            "id": row[0],
            "username": row[1],
            "tool": row[2],
            "target": row[3],
            "summary": row[4],
            "created_at": row[5],
        }
        for row in cur.fetchall()
    ]
    record_activity("view_reports", "Opened report history")
    return render_template(
        "reports.html",
        reports=reports,
        search=search,
        tool_filter=tool_filter,
        user_filter=user_filter,
        is_admin=is_current_admin(),
    )


@app.route("/reports/compare")
@login_required
def compare_reports():
    first_id = request.args.get("first", type=int)
    second_id = request.args.get("second", type=int)
    first = get_report_or_404(first_id) if first_id else None
    second = get_report_or_404(second_id) if second_id else None
    comparison = None

    if first and second:
        first_keys = set(first["result"].keys()) if isinstance(first["result"], dict) else set()
        second_keys = set(second["result"].keys()) if isinstance(second["result"], dict) else set()
        comparison = {
            "same_tool": first["tool"] == second["tool"],
            "same_target": first["target"] == second["target"],
            "added_keys": sorted(second_keys - first_keys),
            "removed_keys": sorted(first_keys - second_keys),
            "shared_keys": sorted(first_keys & second_keys),
        }
        record_activity("compare_reports", f"Compared report #{first_id} with #{second_id}")

    return render_template("compare_reports.html", first=first, second=second, comparison=comparison)


@app.route("/theme/<theme>")
@login_required
def set_theme(theme):
    if theme not in ("dark", "light"):
        theme = "dark"
    ensure_user_management_columns()
    try:
        cur = mysql.connection.cursor()
        cur.execute("UPDATE users SET preferred_theme=%s WHERE username=%s", (theme, session["user"]))
        mysql.connection.commit()
        session["theme"] = theme
    except Exception:
        mysql.connection.rollback()
    return redirect(request.referrer or "/")


@app.route("/help")
@login_required
def help_page():
    record_activity("view_help", "Opened help page")
    return render_template("help.html", tools=TOOLS)


@app.route("/admin", methods=["GET", "POST"])
@admin_required
def admin():
    ensure_activity_table()
    ensure_admin_column()
    ensure_tool_permissions_table()
    ensure_notifications_table()
    ensure_user_sessions_table()
    message = None
    error = None
    selected_user = request.args.get("user", "").strip()
    selected_tool = request.args.get("tool", "").strip()
    activity_search = request.args.get("search", "").strip()
    user_search = request.args.get("user_search", "").strip().lower()
    role_filter = request.args.get("role_filter", "").strip()
    status_filter = request.args.get("status_filter", "").strip()

    if request.method == "POST":
        if not validate_csrf():
            error = "Invalid request. Please try again."
        else:
            action = request.form.get("action")
            user_id = request.form.get("user_id")

            cur = mysql.connection.cursor()

            if action == "create_admin":
                name = request.form.get("name", "").strip()
                username = request.form.get("username", "").strip()
                raw_password = request.form.get("password", "")
                role = request.form.get("role", "admin")

                if not name or not username or not raw_password:
                    error = "Name, username and password are required."
                elif not valid_password(raw_password):
                    error = "Password must be at least 8 characters and include 3 of: uppercase, lowercase, number, symbol."
                else:
                    cur.execute("SELECT id FROM users WHERE username=%s", (username,))
                    if cur.fetchone():
                        error = "Username already exists."
                    else:
                        cur.execute(
                            """
                            INSERT INTO users(name, username, password, is_admin, role, account_status)
                            VALUES(%s, %s, %s, 1, %s, 'active')
                            """,
                            (name, username, generate_password_hash(raw_password), role),
                        )
                        mysql.connection.commit()
                        record_activity("admin_create_admin", f"Created admin account {username}")
                        message = f"Admin account {username} was created."
            elif action == "restore_backup":
                backup_file = request.files.get("backup_file")
                if not backup_file or not backup_file.filename.lower().endswith(".zip"):
                    error = "Upload a valid backup ZIP file."
                else:
                    try:
                        restored_users = 0
                        restored_permissions = 0
                        with zipfile.ZipFile(backup_file.stream) as archive:
                            if "users.csv" in archive.namelist():
                                user_rows = csv.DictReader(io.TextIOWrapper(archive.open("users.csv"), encoding="utf-8"))
                                for item in user_rows:
                                    username = (item.get("username") or "").strip()
                                    if not username:
                                        continue
                                    cur.execute(
                                        """
                                        UPDATE users
                                        SET name=%s, role=%s, is_admin=%s, is_blocked=%s,
                                            email=%s, phone=%s, department=%s,
                                            account_status=%s, preferred_theme=%s
                                        WHERE username=%s
                                        """,
                                        (
                                            item.get("name") or username,
                                            item.get("role") or "user",
                                            1 if str(item.get("is_admin")).lower() in ("1", "yes", "true") else 0,
                                            1 if str(item.get("is_blocked")).lower() in ("1", "yes", "true") else 0,
                                            item.get("email") or None,
                                            item.get("phone") or None,
                                            item.get("department") or None,
                                            item.get("account_status") or "active",
                                            item.get("preferred_theme") or "dark",
                                            username,
                                        ),
                                    )
                                    restored_users += cur.rowcount
                            if "tool_permissions.csv" in archive.namelist():
                                permission_rows = csv.DictReader(io.TextIOWrapper(archive.open("tool_permissions.csv"), encoding="utf-8"))
                                for item in permission_rows:
                                    username = (item.get("username") or "").strip()
                                    tool_key = (item.get("tool_key") or "").strip()
                                    if not username or tool_key not in [tool["key"] for tool in TOOLS]:
                                        continue
                                    allowed = 1 if str(item.get("allowed")).lower() in ("1", "yes", "true") else 0
                                    cur.execute(
                                        """
                                        INSERT INTO user_tool_permissions(username, tool_key, allowed)
                                        VALUES(%s, %s, %s)
                                        ON DUPLICATE KEY UPDATE allowed=VALUES(allowed)
                                        """,
                                        (username, tool_key, allowed),
                                    )
                                    restored_permissions += 1
                        mysql.connection.commit()
                        record_activity("admin_restore_backup", "Restored admin backup ZIP")
                        message = f"Restore completed. Users updated: {restored_users}. Permissions restored: {restored_permissions}."
                    except Exception:
                        mysql.connection.rollback()
                        error = "Restore failed. Please check the backup ZIP format."
            else:
                cur.execute("SELECT id, username FROM users WHERE id=%s", (user_id,))
                target = cur.fetchone()

                if not target:
                    error = "User not found."
                elif target[1] == session["user"]:
                    error = "You cannot modify your own admin account here."
                elif action == "promote_admin":
                    cur.execute("UPDATE users SET is_admin=1, role='admin' WHERE id=%s", (user_id,))
                    mysql.connection.commit()
                    record_activity("admin_promote_user", f"Promoted {target[1]} to admin")
                    message = f"{target[1]} is now an admin."
                elif action == "block_user":
                    cur.execute("UPDATE users SET is_blocked=1 WHERE id=%s", (user_id,))
                    mysql.connection.commit()
                    record_activity("admin_block_user", f"Blocked {target[1]}")
                    message = f"{target[1]} was blocked."
                elif action == "unblock_user":
                    cur.execute(
                        """
                        UPDATE users
                        SET is_blocked=0, failed_login_attempts=0, locked_until=NULL
                        WHERE id=%s
                        """,
                        (user_id,),
                    )
                    mysql.connection.commit()
                    record_activity("admin_unblock_user", f"Unblocked {target[1]}")
                    message = f"{target[1]} was unblocked."
                elif action == "update_role":
                    role = request.form.get("role", "user")
                    is_admin = 1 if role in ("admin", "super_admin") else 0
                    cur.execute(
                        "UPDATE users SET role=%s, is_admin=%s WHERE id=%s",
                        (role, is_admin, user_id),
                    )
                    mysql.connection.commit()
                    record_activity("admin_update_role", f"Updated {target[1]} role to {role}")
                    message = f"{target[1]} role updated to {role}."
                elif action == "update_status":
                    account_status = request.form.get("account_status", "active")
                    if account_status not in ("active", "pending", "suspended"):
                        error = "Unsupported account status."
                    else:
                        is_blocked = 1 if account_status == "suspended" else 0
                        cur.execute(
                            "UPDATE users SET account_status=%s, is_blocked=%s WHERE id=%s",
                            (account_status, is_blocked, user_id),
                        )
                        mysql.connection.commit()
                        record_activity("admin_update_status", f"Updated {target[1]} status to {account_status}")
                        message = f"{target[1]} status updated to {account_status}."
                elif action == "force_logout":
                    cur.execute(
                        "UPDATE user_sessions SET force_logout=1, is_active=0 WHERE username=%s",
                        (target[1],),
                    )
                    mysql.connection.commit()
                    record_activity("admin_force_logout", f"Forced logout for {target[1]}")
                    message = f"{target[1]} will be logged out."
                elif action == "update_permissions":
                    allowed_tools = set(request.form.getlist("tools"))
                    for tool in TOOLS:
                        cur.execute(
                            """
                            INSERT INTO user_tool_permissions(username, tool_key, allowed)
                            VALUES(%s, %s, %s)
                            ON DUPLICATE KEY UPDATE allowed=VALUES(allowed)
                            """,
                            (target[1], tool["key"], 1 if tool["key"] in allowed_tools else 0),
                        )
                    mysql.connection.commit()
                    record_activity("admin_update_permissions", f"Updated tool permissions for {target[1]}")
                    message = f"Tool permissions updated for {target[1]}."
                elif action == "delete":
                    cur.execute("DELETE FROM user_activity WHERE username=%s", (target[1],))
                    cur.execute("DELETE FROM user_sessions WHERE username=%s", (target[1],))
                    cur.execute("DELETE FROM user_tool_permissions WHERE username=%s", (target[1],))
                    cur.execute("DELETE FROM users WHERE id=%s", (user_id,))
                    mysql.connection.commit()
                    record_activity("admin_delete_user", f"Deleted user {target[1]}")
                    message = f"User {target[1]} was deleted."
                elif action == "reset_password":
                    temporary_password = secrets.token_urlsafe(10) + "A1!"
                    cur.execute(
                        "UPDATE users SET password=%s, must_change_password=1 WHERE id=%s",
                        (generate_password_hash(temporary_password), user_id),
                    )
                    mysql.connection.commit()
                    record_activity("admin_reset_password", f"Reset password for {target[1]}")
                    message = f"Temporary password for {target[1]}: {temporary_password}"
                else:
                    error = "Unsupported admin action."

    cur = mysql.connection.cursor()
    cur.execute(
        """
        SELECT id, name, username, is_admin, role, is_blocked,
               failed_login_attempts, locked_until, must_change_password,
               email, phone, department, account_status, preferred_theme
        FROM users
        ORDER BY id DESC
        """
    )
    users = [
        {
            "id": row[0],
            "name": row[1],
            "username": row[2],
            "is_admin": bool(row[3]) or row[4] in ("admin", "super_admin"),
            "role": row[4],
            "is_blocked": bool(row[5]),
            "failed_login_attempts": row[6],
            "locked_until": row[7],
            "must_change_password": bool(row[8]),
            "email": row[9],
            "phone": row[10],
            "department": row[11],
            "account_status": row[12],
            "preferred_theme": row[13],
        }
        for row in cur.fetchall()
    ]

    cur.execute(
        """
        SELECT username, tool_key, allowed
        FROM user_tool_permissions
        """
    )
    permission_rows = cur.fetchall()
    permissions_by_user = {}
    for row in permission_rows:
        permissions_by_user.setdefault(row[0], {})[row[1]] = bool(row[2])

    for user in users:
        user["tool_permissions"] = {
            tool["key"]: permissions_by_user.get(user["username"], {}).get(tool["key"], True)
            for tool in TOOLS
        }

    cur.execute(
        """
        SELECT username, COUNT(*) AS total, MAX(created_at) AS last_seen
        FROM user_activity
        GROUP BY username
        """
    )
    summaries = {
        row[0]: {"total": row[1], "last_seen": row[2]}
        for row in cur.fetchall()
    }

    cur.execute(
        """
        SELECT username, action, details, ip_address, created_at
        FROM user_activity
        ORDER BY created_at DESC
        LIMIT 300
        """
    )
    recent_activities = [
        {
            "username": row[0],
            "action": row[1],
            "details": row[2],
            "ip_address": row[3],
            "created_at": row[4],
            "label": activity_label(row[1]),
        }
        for row in cur.fetchall()
    ]

    activity_query = """
        SELECT username, action, details, ip_address, created_at
        FROM user_activity
    """
    conditions = []
    params = []

    if selected_user:
        conditions.append("username=%s")
        params.append(selected_user)
    if selected_tool:
        conditions.append("action=%s")
        params.append(selected_tool)
    if activity_search:
        conditions.append("(username LIKE %s OR action LIKE %s OR details LIKE %s OR ip_address LIKE %s)")
        search_term = f"%{activity_search}%"
        params.extend([search_term, search_term, search_term, search_term])

    if conditions:
        activity_query += " WHERE " + " AND ".join(conditions)

    activity_query += " ORDER BY created_at DESC LIMIT 200"
    cur.execute(activity_query, tuple(params))
    activities = [
        {
            "username": row[0],
            "action": row[1],
            "details": row[2],
            "ip_address": row[3],
            "created_at": row[4],
        }
        for row in cur.fetchall()
    ]

    last_activity_by_user = {}
    for activity in recent_activities:
        if activity["username"] not in last_activity_by_user:
            last_activity_by_user[activity["username"]] = activity

    for activity in activities:
        activity["label"] = activity_label(activity["action"])

    for user in users:
        summary = summaries.get(user["username"], {})
        latest = last_activity_by_user.get(user["username"])
        user["activity_count"] = summary.get("total", 0)
        user["last_seen"] = summary.get("last_seen")
        user["last_option"] = latest["label"] if latest else "No activity"
        user["last_details"] = latest["details"] if latest else ""

    if user_search:
        users = [
            user for user in users
            if user_search in (user["name"] or "").lower() or user_search in user["username"].lower()
        ]

    if role_filter:
        users = [user for user in users if user["role"] == role_filter]

    if status_filter == "active":
        users = [user for user in users if not user["is_blocked"]]
    elif status_filter == "blocked":
        users = [user for user in users if user["is_blocked"]]

    admin_users = [user for user in users if user["is_admin"]]
    regular_users = [user for user in users if not user["is_admin"]]
    blocked_users = [user for user in users if user["is_blocked"]]
    locked_users = [user for user in users if user["locked_until"]]
    password_change_users = [user for user in users if user["must_change_password"]]
    pending_users = [user for user in users if user["account_status"] == "pending"]

    stats = {
        "users": len(users),
        "admins": len(admin_users),
        "regular_users": len(regular_users),
        "blocked_users": len(blocked_users),
        "locked_users": len(locked_users),
        "pending_users": len(pending_users),
        "activities": sum(user["activity_count"] for user in users),
        "active_users": sum(1 for user in users if user["activity_count"]),
    }

    cur.execute(
        """
        SELECT username, current_page, ip_address, last_seen, is_active
        FROM user_sessions
        WHERE is_active=1 AND last_seen >= DATE_SUB(NOW(), INTERVAL 10 MINUTE)
        ORDER BY last_seen DESC
        """
    )
    online_users = [
        {
            "username": row[0],
            "current_page": row[1],
            "ip_address": row[2],
            "last_seen": row[3],
            "is_active": bool(row[4]),
        }
        for row in cur.fetchall()
    ]

    cur.execute(
        """
        SELECT id, title, message, category, is_read, created_at
        FROM admin_notifications
        ORDER BY created_at DESC
        LIMIT 20
        """
    )
    notifications = [
        {
            "id": row[0],
            "title": row[1],
            "message": row[2],
            "category": row[3],
            "is_read": bool(row[4]),
            "created_at": row[5],
        }
        for row in cur.fetchall()
    ]

    cur.execute(
        """
        SELECT action, COUNT(*) AS total
        FROM user_activity
        GROUP BY action
        ORDER BY total DESC
        LIMIT 8
        """
    )
    option_usage = [
        {
            "action": row[0],
            "label": activity_label(row[0]),
            "count": row[1],
        }
        for row in cur.fetchall()
    ]
    max_option_count = max((item["count"] for item in option_usage), default=1)

    top_active_users = sorted(
        users,
        key=lambda user: user["activity_count"],
        reverse=True,
    )[:6]

    admin_alerts = []
    if blocked_users:
        admin_alerts.append({
            "icon": "fa-ban",
            "title": "Blocked accounts",
            "text": f"{len(blocked_users)} account(s) are blocked.",
        })
    if locked_users:
        admin_alerts.append({
            "icon": "fa-lock",
            "title": "Locked accounts",
            "text": f"{len(locked_users)} account(s) have a login lock.",
        })
    if password_change_users:
        admin_alerts.append({
            "icon": "fa-key",
            "title": "Password change pending",
            "text": f"{len(password_change_users)} account(s) must change password.",
        })
    if pending_users:
        admin_alerts.append({
            "icon": "fa-user-clock",
            "title": "Pending accounts",
            "text": f"{len(pending_users)} account(s) are waiting for approval.",
        })

    ensure_reports_table()
    cur.execute(
        """
        SELECT id, username, tool, target, summary, created_at
        FROM scan_reports
        ORDER BY created_at DESC
        LIMIT 50
        """
    )
    reports = [
        {
            "id": row[0],
            "username": row[1],
            "tool": row[2],
            "target": row[3],
            "summary": row[4],
            "created_at": row[5],
        }
        for row in cur.fetchall()
    ]

    return render_template(
        "admin.html",
        users=users,
        admin_users=admin_users,
        regular_users=regular_users,
        activities=activities,
        reports=reports,
        stats=stats,
        option_usage=option_usage,
        max_option_count=max_option_count,
        top_active_users=top_active_users,
        admin_alerts=admin_alerts,
        online_users=online_users,
        notifications=notifications,
        tools=TOOLS,
        selected_user=selected_user,
        selected_tool=selected_tool,
        activity_search=activity_search,
        user_search=user_search,
        role_filter=role_filter,
        status_filter=status_filter,
        message=message,
        error=error,
    )


@app.route("/admin/export/users")
@admin_required
def admin_export_users():
    ensure_admin_column()
    cur = mysql.connection.cursor()
    cur.execute(
        """
        SELECT id, name, username, role, is_admin, is_blocked,
               failed_login_attempts, locked_until, must_change_password,
               email, phone, department, account_status, preferred_theme
        FROM users
        ORDER BY id DESC
        """
    )
    rows = [
        [
            row[0],
            row[1],
            row[2],
            row[3],
            "yes" if row[4] else "no",
            "blocked" if row[5] else "active",
            row[6],
            row[7] or "",
            "yes" if row[8] else "no",
            row[9] or "",
            row[10] or "",
            row[11] or "",
            row[12],
            row[13],
        ]
        for row in cur.fetchall()
    ]
    record_activity("admin_export_users", "Exported user management CSV")
    return download_csv(
        "cybershield-users.csv",
        ["ID", "Name", "Username", "Role", "Is Admin", "Status", "Failed Login Attempts", "Locked Until", "Must Change Password", "Email", "Phone", "Department", "Account Status", "Theme"],
        rows,
    )


@app.route("/admin/export/activity")
@admin_required
def admin_export_activity():
    ensure_activity_table()
    cur = mysql.connection.cursor()
    cur.execute(
        """
        SELECT username, action, details, ip_address, created_at
        FROM user_activity
        ORDER BY created_at DESC
        LIMIT 5000
        """
    )
    rows = [
        [row[0], activity_label(row[1]), row[1], row[2], row[3], row[4]]
        for row in cur.fetchall()
    ]
    record_activity("admin_export_activity", "Exported activity CSV")
    return download_csv(
        "cybershield-activity.csv",
        ["Username", "Option", "Raw Action", "Details", "IP Address", "Created At"],
        rows,
    )


@app.route("/admin/export/reports")
@admin_required
def admin_export_reports():
    ensure_reports_table()
    cur = mysql.connection.cursor()
    cur.execute(
        """
        SELECT id, username, tool, target, summary, created_at
        FROM scan_reports
        ORDER BY created_at DESC
        LIMIT 5000
        """
    )
    rows = [list(row) for row in cur.fetchall()]
    record_activity("admin_export_reports", "Exported saved reports CSV")
    return download_csv(
        "cybershield-reports.csv",
        ["ID", "Username", "Tool", "Target", "Summary", "Created At"],
        rows,
    )


@app.route("/admin/backup")
@admin_required
def admin_backup():
    ensure_admin_column()
    ensure_activity_table()
    ensure_reports_table()
    ensure_tool_permissions_table()

    backup = io.BytesIO()
    cur = mysql.connection.cursor()
    datasets = {
        "users.csv": (
            "SELECT id, name, username, role, is_admin, is_blocked, email, phone, department, account_status, preferred_theme FROM users ORDER BY id",
            ["id", "name", "username", "role", "is_admin", "is_blocked", "email", "phone", "department", "account_status", "preferred_theme"],
        ),
        "activity.csv": (
            "SELECT username, action, details, ip_address, created_at FROM user_activity ORDER BY created_at DESC",
            ["username", "action", "details", "ip_address", "created_at"],
        ),
        "reports.csv": (
            "SELECT id, username, tool, target, summary, created_at FROM scan_reports ORDER BY created_at DESC",
            ["id", "username", "tool", "target", "summary", "created_at"],
        ),
        "tool_permissions.csv": (
            "SELECT username, tool_key, allowed, updated_at FROM user_tool_permissions ORDER BY username, tool_key",
            ["username", "tool_key", "allowed", "updated_at"],
        ),
    }

    with zipfile.ZipFile(backup, "w", zipfile.ZIP_DEFLATED) as archive:
        for filename, (query, headers) in datasets.items():
            cur.execute(query)
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(headers)
            writer.writerows(cur.fetchall())
            archive.writestr(filename, output.getvalue())

    record_activity("admin_backup_download", "Downloaded admin backup ZIP")
    backup.seek(0)
    return Response(
        backup.getvalue(),
        mimetype="application/zip",
        headers={"Content-Disposition": "attachment;filename=cybershield-backup.zip"},
    )


# -----------------------------
# LOG ANALYSIS
# -----------------------------
last_log = {}

@app.route("/log", methods=["GET", "POST"])
@login_required
@tool_required("log")
def log():
    global last_log

    if request.method == "POST":
        if not validate_csrf():
            return render_template("log.html", result=None, error="Invalid request. Please try again."), 400

        file = request.files.get("logfile")

        if not file:
            return "No file uploaded"

        path = save_uploaded_file(file, {"log", "txt"})
        if not path:
            return render_template("log.html", result=None, error="Only .log and .txt files are allowed."), 400

        result = analyze_log(path)
        last_log = result
        record_activity("log_analysis", f"Analyzed log file {secure_filename(file.filename)}")
        record_report("Log Analysis", secure_filename(file.filename), result, "Log file analyzed")

        return render_template("log.html", result=result)

    record_activity("open_log_analysis", "Opened Log Analysis option")
    return render_template("log.html", result=None)


@app.route("/download_log")
@login_required
@tool_required("log")
def download_log():
    return download_json(last_log, "log.json")


# -----------------------------
# RECON
# -----------------------------
last_recon = {}

@app.route("/recon", methods=["GET", "POST"])
@login_required
@tool_required("recon")
def recon():
    global last_recon

    if request.method == "POST":
        if not validate_csrf():
            return render_template("recon.html", ports=None, alert=None, error="Invalid request. Please try again."), 400

        ip = request.form["ip"]
        data = scan_ports(ip)
        last_recon = data
        record_activity("network_recon", f"Scanned target {ip}")
        record_report("Network Recon", ip, data, f"Detected {len(data.get('open_ports', []))} open ports")
        return render_template("recon.html", ports=data["open_ports"], alert=data)

    record_activity("open_network_recon", "Opened Network Recon option")
    return render_template("recon.html", ports=None, alert=None)


@app.route("/download_recon")
@login_required
@tool_required("recon")
def download_recon():
    return download_json(last_recon, "recon.json")


# -----------------------------
# PACKET
# -----------------------------
last_packet = {}

@app.route("/packet", methods=["GET", "POST"])
@login_required
@tool_required("packet")
def packet():
    global last_packet

    if request.method == "POST":
        if not validate_csrf():
            return render_template("packet.html", results=None, data=None, error="Invalid request. Please try again."), 400

        file = request.files.get("pcapfile")

        if not file:
            return "No file selected"

        path = save_uploaded_file(file, {"pcap"})
        if not path:
            return render_template("packet.html", results=None, data=None, error="Only .pcap files are allowed."), 400

        data = analyze_pcap(path)
        last_packet = data
        record_activity("packet_analysis", f"Analyzed PCAP file {secure_filename(file.filename)}")
        record_report("Packet Inspection", secure_filename(file.filename), data, f"Analyzed {len(data.get('packets', []))} packets")

        return render_template("packet.html", results=data["packets"], data=data)

    record_activity("open_packet_analysis", "Opened Packet Inspection option")
    return render_template("packet.html", results=None, data=None)


@app.route("/download_packet")
@login_required
@tool_required("packet")
def download_packet():
    return download_json(last_packet, "packet.json")


@app.route("/live_packet", methods=["GET", "POST"])
@login_required
@tool_required("packet")
def live_packet():

    global last_packet

    if request.method == "POST":
        if not validate_csrf():
            return render_template("packet.html", results=None, data=None, error="Invalid request. Please try again."), 400

        ip1 = request.form["ip1"]
        ip2 = request.form["ip2"]
        try:
            duration = int(request.form.get("duration", 20))
        except ValueError:
            duration = 20

        duration = max(5, min(duration, 120))

        data = analyze_live_packets(ip1, ip2, duration)

        last_packet = data
        record_activity("live_packet_monitor", f"Monitored {ip1} to {ip2} for {duration} seconds")
        record_report("Live Packet Monitor", f"{ip1} to {ip2}", data, f"Captured for {duration} seconds")

        return render_template(
            "packet.html",
            results=data["packets"],
            data=data
        )

    record_activity("open_live_packet_monitor", "Opened Live Packet Monitor option")
    return render_template(
        "packet.html",
        results=None,
        data=None
    )


# -----------------------------
# THREAT
# -----------------------------
last_threat = {}

@app.route("/threat", methods=["GET", "POST"])
@login_required
@tool_required("threat")
def threat():
    global last_threat

    if request.method == "POST":
        if not validate_csrf():
            return render_template("threat.html", data=None, error="Invalid request. Please try again."), 400

        url = request.form["url"]
        data = analyze_website(url)

        last_threat = data
        record_activity("threat_intelligence", f"Analyzed website {url}")
        record_report("Threat Intelligence", url, data, "Website analyzed")
        return render_template("threat.html", data=data)

    record_activity("open_threat_intelligence", "Opened Threat Intelligence option")
    return render_template("threat.html", data=None)


@app.route("/download_threat")
@login_required
@tool_required("threat")
def download_threat():
    return download_json(last_threat, "threat.json")


# -----------------------------
# RUN
# -----------------------------
if __name__ == "__main__":
    app.run(debug=True)
