from flask import Flask, render_template, redirect, url_for, request, flash, send_from_directory
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from pymongo import MongoClient, DESCENDING
from pymongo.errors import DuplicateKeyError
from bson import ObjectId
import os, hashlib, functools
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key-change-in-production")

# ─────────────────────────── UPLOAD CONFIG ───────────────────────────
UPLOAD_FOLDER = "static/uploads"
ALLOWED_EXTENSIONS = {"pdf", "ppt", "pptx", "doc", "docx", "txt", "png", "jpg", "jpeg"}
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ─────────────────────────── MONGODB ───────────────────────────
MONGO_URI = os.environ.get("MONGO_URI", "mongodb+srv://ameetm0099_db_user:cyrI36vaOr8cIMSe@documents.ky2g9jl.mongodb.net/?appName=documents")
client = MongoClient(MONGO_URI)
db_mongo = client["eduvault"]

users_col     = db_mongo["users"]
resources_col = db_mongo["resources"]
audit_col     = db_mongo["audit_log"]

# Indexes
users_col.create_index("email", unique=True)
resources_col.create_index("branch")
resources_col.create_index("semester")
resources_col.create_index("status")
resources_col.create_index("file_hash")
resources_col.create_index([("title", "text"), ("subjectName", "text")])

# Seed default admin
if not users_col.find_one({"role": "admin"}):
    users_col.insert_one({
        "name": "Admin",
        "email": "admin@portal.com",
        "password": generate_password_hash("Admin@1234"),
        "role": "admin",
        "created_at": datetime.utcnow()
    })

# ─────────────────────────── LOGIN MANAGER ───────────────────────────
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

class User(UserMixin):
    def __init__(self, doc):
        self.id        = str(doc["_id"])
        self.name      = doc["name"]
        self.email     = doc["email"]
        self.password  = doc["password"]
        self.role      = doc["role"]
        self.created_at = doc.get("created_at", datetime.utcnow())

    @property
    def is_admin(self):    return self.role == "admin"
    @property
    def is_teacher(self):  return self.role in ("teacher", "admin")

@login_manager.user_loader
def load_user(user_id):
    try:
        doc = users_col.find_one({"_id": ObjectId(user_id)})
        return User(doc) if doc else None
    except Exception:
        return None

# ─────────────────────────── HELPERS ───────────────────────────
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def compute_hash(file_stream):
    sha256 = hashlib.sha256()
    for chunk in iter(lambda: file_stream.read(8192), b""):
        sha256.update(chunk)
    file_stream.seek(0)
    return sha256.hexdigest()

def log_action(user_id, action, detail=""):
    audit_col.insert_one({
        "user_id":    user_id,
        "action":     action,
        "detail":     detail,
        "created_at": datetime.utcnow()
    })

def fmt_resource(doc):
    """Normalize a MongoDB resource doc for templates."""
    if doc is None:
        return None
    d = dict(doc)
    d["id"] = str(doc["_id"])
    if "created_at" in d and isinstance(d["created_at"], datetime):
        d["created_at"] = d["created_at"].strftime("%Y-%m-%d %H:%M:%S")
    return d

def fmt_user(doc):
    if doc is None:
        return None
    d = dict(doc)
    d["id"] = str(doc["_id"])
    if "created_at" in d and isinstance(d["created_at"], datetime):
        d["created_at"] = d["created_at"].strftime("%Y-%m-%d %H:%M:%S")
    return d

def role_required(*roles):
    def decorator(f):
        @functools.wraps(f)
        @login_required
        def wrapped(*args, **kwargs):
            if current_user.role not in roles:
                flash("Access denied: insufficient permissions.", "danger")
                return redirect(url_for("dashboard"))
            return f(*args, **kwargs)
        return wrapped
    return decorator

# ─────────────────────────── AUTH ───────────────────────────
@app.route("/", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        email    = request.form["email"].strip().lower()
        password = request.form["password"]
        doc = users_col.find_one({"email": email})
        if doc and check_password_hash(doc["password"], password):
            u = User(doc)
            login_user(u)
            log_action(u.id, "LOGIN")
            return redirect(url_for("dashboard"))
        flash("Invalid email or password.", "danger")
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name     = request.form["name"].strip()
        email    = request.form["email"].strip().lower()
        password = request.form["password"]
        role     = request.form.get("role", "student")
        if role not in ("student", "teacher"):
            role = "student"
        if len(password) < 6:
            flash("Password must be at least 6 characters.", "warning")
            return render_template("register.html")
        try:
            users_col.insert_one({
                "name":       name,
                "email":      email,
                "password":   generate_password_hash(password),
                "role":       role,
                "created_at": datetime.utcnow()
            })
            flash("Account created! Please login.", "success")
            return redirect(url_for("login"))
        except DuplicateKeyError:
            flash("Email already registered.", "danger")
    return render_template("register.html")

@app.route("/logout")
@login_required
def logout():
    log_action(current_user.id, "LOGOUT")
    logout_user()
    return redirect(url_for("login"))

# ─────────────────────────── DASHBOARD ───────────────────────────
@app.route("/dashboard")
@login_required
def dashboard():
    total_resources = resources_col.count_documents({"status": {"$in": ["approved", "verified"]}})
    my_uploads_count = resources_col.count_documents({"uploaded_by": current_user.id})
    stats = {"total_resources": total_resources, "my_uploads": my_uploads_count}

    recent_docs = list(resources_col.aggregate([
        {"$match": {"status": {"$in": ["approved", "verified"]}}},
        {"$sort":  {"created_at": -1}},
        {"$limit": 5},
        {"$lookup": {"from": "users", "localField": "uploaded_by",
                     "foreignField": "_id", "as": "uploader"}},
        {"$addFields": {"uploader_name": {"$arrayElemAt": ["$uploader.name", 0]}}}
    ]))
    recent = [fmt_resource(r) for r in recent_docs]
    return render_template("dashboard.html", stats=stats, recent=recent)

# ─────────────────────────── UPLOAD ───────────────────────────
@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    if request.method == "POST":
        title       = request.form["title"].strip()
        subjectName = request.form["subjectName"].strip()
        semester    = request.form["semester"]
        branch      = request.form["branch"]
        batch       = request.form["batch"]
        note_type   = request.form["note_type"]
        file        = request.files.get("file")

        if not file or file.filename == "":
            flash("Please select a file to upload.", "warning")
            return redirect(url_for("upload"))
        if not allowed_file(file.filename):
            flash(f"File type not allowed.", "warning")
            return redirect(url_for("upload"))

        file_hash = compute_hash(file)
        existing  = resources_col.find_one({"file_hash": file_hash})
        if existing:
            flash(f"Duplicate file! '{existing['title']}' already exists.", "warning")
            return redirect(url_for("upload"))

        filename    = secure_filename(file.filename)
        unique_name = f"{file_hash[:8]}_{filename}"
        file.save(os.path.join(app.config["UPLOAD_FOLDER"], unique_name))

        if note_type == "Question Bank":
            status = "pending" if "ask_verification" in request.form else "approved"
        elif current_user.role in ("teacher", "admin"):
            status = "verified"
        else:
            status = "approved"

        resources_col.insert_one({
            "title":       title,
            "subjectName": subjectName,
            "semester":    semester,
            "filename":    unique_name,
            "file_hash":   file_hash,
            "branch":      branch,
            "batch":       batch,
            "note_type":   note_type,
            "status":      status,
            "uploaded_by": current_user.id,
            "views":       0,
            "downloads":   0,
            "created_at":  datetime.utcnow()
        })
        log_action(current_user.id, "UPLOAD", f"{title} ({note_type})")
        msg_map = {"pending": "Uploaded! Awaiting verification.", "verified": "Uploaded and auto-verified.", "approved": "Uploaded successfully."}
        flash(msg_map.get(status, "Uploaded."), "success")
        return redirect(url_for("upload"))
    return render_template("upload.html")

# ─────────────────────────── RESOURCES ───────────────────────────
@app.route("/resources")
@login_required
def resources():
    branch    = request.args.get("branch", "")
    semester  = request.args.get("semester", "")
    note_type = request.args.get("note_type", "")
    search    = request.args.get("q", "").strip()

    query = {"status": {"$in": ["approved", "verified"]}}
    if branch:    query["branch"]    = branch
    if semester:  query["semester"]  = semester
    if note_type: query["note_type"] = note_type
    if search:    query["$text"]     = {"$search": search}

    docs = list(resources_col.aggregate([
        {"$match": query},
        {"$sort":  {"created_at": -1}},
        {"$lookup": {"from": "users", "localField": "uploaded_by",
                     "foreignField": "_id", "as": "uploader"}},
        {"$addFields": {"uploader_name": {"$arrayElemAt": ["$uploader.name", 0]}}}
    ]))
    data = [fmt_resource(r) for r in docs]
    return render_template("resources.html", data=data,
                           branch=branch, semester=semester,
                           note_type=note_type, search=search)

@app.route("/download/<filename>")
@login_required
def download(filename):
    resources_col.update_one({"filename": filename}, {"$inc": {"downloads": 1}})
    log_action(current_user.id, "DOWNLOAD", filename)
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename, as_attachment=True)

# ─────────────────────────── MY UPLOADS ───────────────────────────
@app.route("/my-uploads")
@login_required
def my_uploads():
    docs = list(resources_col.find(
        {"uploaded_by": current_user.id},
        sort=[("created_at", DESCENDING)]
    ))
    data = [fmt_resource(r) for r in docs]
    return render_template("my_uploads.html", data=data)

# ─────────────────────────── ADMIN ───────────────────────────
@app.route("/admin")
@role_required("admin")
def admin_dashboard():
    stats = {
        "total_users":     users_col.count_documents({}),
        "total_resources": resources_col.count_documents({}),
        "pending":         resources_col.count_documents({"status": "pending"}),
        "approved":        resources_col.count_documents({"status": "approved"}),
        "verified":        resources_col.count_documents({"status": "verified"}),
        "total_downloads": list(resources_col.aggregate([
            {"$group": {"_id": None, "total": {"$sum": "$downloads"}}}
        ]))[0]["total"] if resources_col.count_documents({}) else 0
    }
    logs_raw = list(audit_col.aggregate([
        {"$sort": {"created_at": -1}},
        {"$limit": 20},
        {"$lookup": {"from": "users", "localField": "user_id",
                     "foreignField": "_id", "as": "user"}},
        {"$addFields": {
            "name":  {"$arrayElemAt": ["$user.name",  0]},
            "email": {"$arrayElemAt": ["$user.email", 0]}
        }}
    ]))
    logs = []
    for l in logs_raw:
        d = dict(l)
        d["id"] = str(l["_id"])
        if isinstance(d.get("created_at"), datetime):
            d["created_at"] = d["created_at"].strftime("%Y-%m-%d %H:%M:%S")
        logs.append(d)
    return render_template("admin/dashboard.html", stats=stats, logs=logs)

@app.route("/admin/users")
@role_required("admin")
def admin_users():
    docs  = list(users_col.find().sort("created_at", DESCENDING))
    users = [fmt_user(u) for u in docs]
    return render_template("admin/users.html", users=users)

@app.route("/admin/users/<uid>/role", methods=["POST"])
@role_required("admin")
def change_role(uid):
    new_role = request.form.get("role")
    if new_role not in ("student", "teacher", "admin"):
        flash("Invalid role.", "danger")
        return redirect(url_for("admin_users"))
    users_col.update_one({"_id": ObjectId(uid)}, {"$set": {"role": new_role}})
    log_action(current_user.id, "ROLE_CHANGE", f"User {uid} → {new_role}")
    flash("Role updated.", "success")
    return redirect(url_for("admin_users"))

@app.route("/admin/users/<uid>/delete", methods=["POST"])
@role_required("admin")
def delete_user(uid):
    if uid == current_user.id:
        flash("You cannot delete yourself.", "danger")
        return redirect(url_for("admin_users"))
    users_col.delete_one({"_id": ObjectId(uid)})
    log_action(current_user.id, "DELETE_USER", f"User {uid}")
    flash("User deleted.", "success")
    return redirect(url_for("admin_users"))

@app.route("/admin/resources")
@role_required("admin", "teacher")
def admin_resources():
    status_filter = request.args.get("status", "")
    query = {"status": status_filter} if status_filter else {}
    docs = list(resources_col.aggregate([
        {"$match": query},
        {"$sort":  {"created_at": -1}},
        {"$lookup": {"from": "users", "localField": "uploaded_by",
                     "foreignField": "_id", "as": "uploader"}},
        {"$addFields": {"uploader_name": {"$arrayElemAt": ["$uploader.name", 0]}}}
    ]))
    data = [fmt_resource(r) for r in docs]
    return render_template("admin/resources.html", data=data, status_filter=status_filter)

@app.route("/admin/resources/<rid>/status", methods=["POST"])
@role_required("admin", "teacher")
def change_resource_status(rid):
    new_status = request.form.get("status")
    if new_status not in ("approved", "verified", "pending", "rejected"):
        flash("Invalid status.", "danger")
        return redirect(url_for("admin_resources"))
    resources_col.update_one({"_id": ObjectId(rid)}, {"$set": {"status": new_status}})
    log_action(current_user.id, "STATUS_CHANGE", f"Resource {rid} → {new_status}")
    flash(f"Resource marked as {new_status}.", "success")
    return redirect(url_for("admin_resources"))

@app.route("/admin/resources/<rid>/delete", methods=["POST"])
@role_required("admin")
def delete_resource(rid):
    doc = resources_col.find_one({"_id": ObjectId(rid)})
    if doc:
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], doc["filename"])
        if os.path.exists(filepath):
            os.remove(filepath)
        resources_col.delete_one({"_id": ObjectId(rid)})
    log_action(current_user.id, "DELETE_RESOURCE", f"Resource {rid}")
    flash("Resource deleted.", "success")
    return redirect(url_for("admin_resources"))

@app.errorhandler(404)
def not_found(e):
    return render_template("errors/404.html"), 404

@app.errorhandler(413)
def too_large(e):
    flash("File too large. Maximum size is 16 MB.", "danger")
    return redirect(url_for("upload"))

if __name__ == "__main__":
    app.run(debug=True)
