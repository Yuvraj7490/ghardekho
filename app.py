import os
import re
import sqlite3
import uuid
from functools import wraps
from urllib.parse import urlparse

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, abort
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename


BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE = os.path.join(BASE_DIR, "ghar_dekho.db")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "uploads")

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)

app.secret_key = os.environ.get(
    "GHAR_DEKHO_SECRET",
    "local-development-key-change-before-deployment"
)

app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp"}

ALLOWED_ROOM_TYPES = [
    "Single Room", "1 BHK", "2 BHK",
    "3 BHK", "PG", "Hostel"
]

ALLOWED_AMENITIES = [
    "Wi-Fi", "Parking", "AC",
    "Furnished", "Kitchen", "Attached Bathroom"
]


# --------------------------------------------------
# DATABASE
# --------------------------------------------------

def get_db():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    return db


def init_db():
    with get_db() as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                role TEXT NOT NULL
                    CHECK(role IN ('owner', 'tenant'))
            );

            CREATE TABLE IF NOT EXISTS rooms (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                room_type TEXT NOT NULL,
                location TEXT NOT NULL,
                address TEXT NOT NULL,
                rent INTEGER NOT NULL,
                deposit INTEGER NOT NULL DEFAULT 0,
                description TEXT NOT NULL,
                amenities TEXT DEFAULT '',
                photo TEXT DEFAULT '',
                available INTEGER NOT NULL DEFAULT 1,
                contact_number TEXT DEFAULT '',
                maps_link TEXT DEFAULT '',
                FOREIGN KEY(owner_id)
                    REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS favourites (
                tenant_id INTEGER NOT NULL,
                room_id INTEGER NOT NULL,
                PRIMARY KEY(tenant_id, room_id),
                FOREIGN KEY(tenant_id)
                    REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY(room_id)
                    REFERENCES rooms(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS enquiries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id INTEGER NOT NULL,
                room_id INTEGER NOT NULL,
                message TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Pending',
                UNIQUE(tenant_id, room_id),
                FOREIGN KEY(tenant_id)
                    REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY(room_id)
                    REFERENCES rooms(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS contact_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL,
                message TEXT NOT NULL
            );
        """)

        # Migration for existing databases.
        columns = {
            row["name"]
            for row in db.execute(
                "PRAGMA table_info(rooms)"
            ).fetchall()
        }

        if "contact_number" not in columns:
            db.execute("""
                ALTER TABLE rooms
                ADD COLUMN contact_number TEXT DEFAULT ''
            """)

        if "maps_link" not in columns:
            db.execute("""
                ALTER TABLE rooms
                ADD COLUMN maps_link TEXT DEFAULT ''
            """)


# --------------------------------------------------
# AUTHENTICATION
# --------------------------------------------------

def current_user():
    return session.get("user")


def login_required(role=None):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            user = current_user()

            if not user:
                flash("Please log in first.")
                return redirect(url_for("login"))

            if role and user["role"] != role:
                abort(403)

            return view(*args, **kwargs)

        return wrapped

    return decorator


@app.context_processor
def inject_user():
    return {"current_user": current_user()}


# --------------------------------------------------
# VALIDATION HELPERS
# --------------------------------------------------

def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower()
        in ALLOWED_EXTENSIONS
    )


def valid_maps_link(link):
    if not link:
        return True

    try:
        parsed = urlparse(link)

        hostname = (parsed.hostname or "").lower()

        allowed_hosts = {
            "google.com",
            "www.google.com",
            "maps.google.com",
            "maps.app.goo.gl",
            "goo.gl"
        }

        return (
            parsed.scheme == "https"
            and hostname in allowed_hosts
            and parsed.username is None
            and parsed.password is None
        )

    except ValueError:
        return False


def valid_contact_number(number):
    if not number:
        return True

    # Allows digits, spaces, +, hyphens and parentheses.
    if not re.fullmatch(r"[0-9+() -]{7,30}", number):
        return False

    digits = re.sub(r"\D", "", number)

    return 7 <= len(digits) <= 15


def save_uploaded_photo(photo):
    if not photo or not photo.filename:
        return None

    if not allowed_file(photo.filename):
        raise ValueError(
            "Use JPG, JPEG, PNG or WEBP images only."
        )

    filename = secure_filename(photo.filename)

    if "." not in filename:
        raise ValueError("Invalid image filename.")

    extension = filename.rsplit(".", 1)[1].lower()
    new_filename = f"{uuid.uuid4().hex}.{extension}"

    photo.save(
        os.path.join(UPLOAD_FOLDER, new_filename)
    )

    return new_filename


def delete_photo(filename):
    if not filename:
        return

    # Never allow a filename to escape the upload folder.
    if os.path.basename(filename) != filename:
        return

    path = os.path.join(UPLOAD_FOLDER, filename)

    if os.path.isfile(path):
        os.remove(path)


# --------------------------------------------------
# HOME PAGE / SEARCH
# --------------------------------------------------

@app.route("/")
def index():
    location = request.args.get(
        "location", ""
    ).strip()

    room_type = request.args.get(
        "room_type", ""
    ).strip()

    min_rent = request.args.get(
        "min_rent", ""
    ).strip()

    max_rent = request.args.get(
        "max_rent", ""
    ).strip()

    query = """
        SELECT rooms.*, users.name AS owner_name
        FROM rooms
        JOIN users ON rooms.owner_id = users.id
        WHERE rooms.available = 1
    """

    params = []

    if location:
        query += """
            AND (
                rooms.location LIKE ?
                OR rooms.address LIKE ?
            )
        """

        params.extend([
            f"%{location}%",
            f"%{location}%"
        ])

    if room_type:
        if room_type in ALLOWED_ROOM_TYPES:
            query += " AND rooms.room_type = ?"
            params.append(room_type)
        else:
            room_type = ""

    if min_rent.isdigit():
        query += " AND rooms.rent >= ?"
        params.append(int(min_rent))

    if max_rent.isdigit():
        query += " AND rooms.rent <= ?"
        params.append(int(max_rent))

    query += " ORDER BY rooms.id DESC"

    with get_db() as db:
        rooms = db.execute(query, params).fetchall()

        saved = set()

        user = current_user()

        if user and user["role"] == "tenant":
            rows = db.execute(
                """
                SELECT room_id
                FROM favourites
                WHERE tenant_id = ?
                """,
                (user["id"],)
            ).fetchall()

            saved = {
                row["room_id"] for row in rows
            }

    return render_template(
        "index.html",
        rooms=rooms,
        saved=saved,
        location=location,
        room_type=room_type,
        min_rent=min_rent,
        max_rent=max_rent
    )


# --------------------------------------------------
# REGISTER
# --------------------------------------------------

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get(
            "name", ""
        ).strip()

        email = request.form.get(
            "email", ""
        ).strip().lower()

        password = request.form.get(
            "password", ""
        )

        role = request.form.get("role", "")

        if (
            not name or len(name) > 100
            or not email or len(email) > 254
            or len(password) < 8
            or role not in ("owner", "tenant")
        ):
            flash(
                "Enter valid details. "
                "Password must be at least 8 characters."
            )

            return render_template("register.html")

        try:
            with get_db() as db:
                db.execute(
                    """
                    INSERT INTO users(
                        name, email, password, role
                    )
                    VALUES(?,?,?,?)
                    """,
                    (
                        name,
                        email,
                        generate_password_hash(password),
                        role
                    )
                )

            flash(
                "Registration successful. Please log in."
            )

            return redirect(url_for("login"))

        except sqlite3.IntegrityError:
            flash("This email is already registered.")

    return render_template("register.html")


# --------------------------------------------------
# LOGIN
# --------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get(
            "email", ""
        ).strip().lower()

        password = request.form.get("password", "")

        with get_db() as db:
            user = db.execute(
                "SELECT * FROM users WHERE email = ?",
                (email,)
            ).fetchone()

        if user and check_password_hash(
            user["password"], password
        ):
            session.clear()

            session["user"] = {
                "id": user["id"],
                "name": user["name"],
                "email": user["email"],
                "role": user["role"]
            }

            if user["role"] == "owner":
                return redirect(
                    url_for("owner_dashboard")
                )

            return redirect(
                url_for("tenant_dashboard")
            )

        flash("Incorrect email or password.")

    return render_template("login.html")


# --------------------------------------------------
# LOGOUT
# --------------------------------------------------

@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    flash("You have logged out.")
    return redirect(url_for("index"))


# --------------------------------------------------
# OWNER DASHBOARD
# --------------------------------------------------

@app.route("/owner")
@login_required("owner")
def owner_dashboard():
    with get_db() as db:
        rooms = db.execute(
            """
            SELECT *
            FROM rooms
            WHERE owner_id = ?
            ORDER BY id DESC
            """,
            (current_user()["id"],)
        ).fetchall()

        enquiries = db.execute(
            """
            SELECT
                enquiries.*,
                rooms.title,
                users.name AS tenant_name,
                users.email AS tenant_email
            FROM enquiries
            JOIN rooms
                ON enquiries.room_id = rooms.id
            JOIN users
                ON enquiries.tenant_id = users.id
            WHERE rooms.owner_id = ?
            ORDER BY enquiries.id DESC
            """,
            (current_user()["id"],)
        ).fetchall()

    return render_template(
        "owner_dashboard.html",
        rooms=rooms,
        enquiries=enquiries
    )


# --------------------------------------------------
# ADD ROOM
# --------------------------------------------------

@app.route("/owner/add", methods=["POST"])
@login_required("owner")
def add_room():
    form = request.form

    title = form.get("title", "").strip()
    room_type = form.get("room_type", "").strip()
    location = form.get("location", "").strip()
    address = form.get("address", "").strip()
    description = form.get("description", "").strip()

    contact_number = form.get(
        "contact_number", ""
    ).strip()

    maps_link = form.get(
        "maps_link", ""
    ).strip()

    amenities = ", ".join([
        item for item in form.getlist("amenities")
        if item in ALLOWED_AMENITIES
    ])

    try:
        rent = int(form.get("rent", "0"))
        deposit = int(form.get("deposit", "0"))
    except ValueError:
        flash("Enter valid rent and deposit amounts.")
        return redirect(url_for("owner_dashboard"))

    if (
        not title or len(title) > 150
        or room_type not in ALLOWED_ROOM_TYPES
        or not location or len(location) > 150
        or not address or len(address) > 500
        or not description or len(description) > 3000
        or rent <= 0 or deposit < 0
        or len(contact_number) > 30
        or len(maps_link) > 2000
        or not valid_contact_number(contact_number)
        or not valid_maps_link(maps_link)
    ):
        flash("Please enter valid property details.")
        return redirect(url_for("owner_dashboard"))

    try:
        photo_path = save_uploaded_photo(
            request.files.get("photo")
        )
    except ValueError as error:
        flash(str(error))
        return redirect(url_for("owner_dashboard"))

    try:
        with get_db() as db:
            db.execute(
                """
                INSERT INTO rooms(
                    owner_id, title, room_type,
                    location, address, rent, deposit,
                    description, amenities, photo,
                    contact_number, maps_link
                )
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    current_user()["id"],
                    title,
                    room_type,
                    location,
                    address,
                    rent,
                    deposit,
                    description,
                    amenities,
                    photo_path or "",
                    contact_number,
                    maps_link
                )
            )

    except Exception:
        delete_photo(photo_path or "")
        raise

    flash("Your property has been added.")
    return redirect(url_for("owner_dashboard"))


# --------------------------------------------------
# EDIT ROOM
# --------------------------------------------------

@app.route(
    "/owner/edit/<int:room_id>",
    methods=["GET", "POST"]
)
@login_required("owner")
def edit_room(room_id):
    with get_db() as db:
        room = db.execute(
            """
            SELECT *
            FROM rooms
            WHERE id = ? AND owner_id = ?
            """,
            (room_id, current_user()["id"])
        ).fetchone()

        if not room:
            abort(404)

        if request.method == "POST":
            form = request.form

            title = form.get(
                "title", ""
            ).strip()

            room_type = form.get(
                "room_type", ""
            ).strip()

            location = form.get(
                "location", ""
            ).strip()

            address = form.get(
                "address", ""
            ).strip()

            description = form.get(
                "description", ""
            ).strip()

            contact_number = form.get(
                "contact_number", ""
            ).strip()

            maps_link = form.get(
                "maps_link", ""
            ).strip()

            amenities = ", ".join([
                item for item in form.getlist("amenities")
                if item in ALLOWED_AMENITIES
            ])

            try:
                rent = int(form.get("rent", "0"))
                deposit = int(form.get("deposit", "0"))
            except ValueError:
                flash("Enter valid rent and deposit amounts.")
                return redirect(
                    url_for("edit_room", room_id=room_id)
                )

            if (
                not title or len(title) > 150
                or room_type not in ALLOWED_ROOM_TYPES
                or not location or len(location) > 150
                or not address or len(address) > 500
                or not description or len(description) > 3000
                or rent <= 0 or deposit < 0
                or len(contact_number) > 30
                or len(maps_link) > 2000
                or not valid_contact_number(contact_number)
                or not valid_maps_link(maps_link)
            ):
                flash("Please enter valid property details.")
                return redirect(
                    url_for("edit_room", room_id=room_id)
                )

            old_photo = room["photo"] or ""
            new_photo = None

            try:
                new_photo = save_uploaded_photo(
                    request.files.get("photo")
                )
            except ValueError as error:
                flash(str(error))
                return redirect(
                    url_for("edit_room", room_id=room_id)
                )

            photo_path = new_photo or old_photo

            try:
                db.execute(
                    """
                    UPDATE rooms
                    SET title = ?,
                        room_type = ?,
                        location = ?,
                        address = ?,
                        rent = ?,
                        deposit = ?,
                        description = ?,
                        amenities = ?,
                        photo = ?,
                        contact_number = ?,
                        maps_link = ?
                    WHERE id = ? AND owner_id = ?
                    """,
                    (
                        title,
                        room_type,
                        location,
                        address,
                        rent,
                        deposit,
                        description,
                        amenities,
                        photo_path,
                        contact_number,
                        maps_link,
                        room_id,
                        current_user()["id"]
                    )
                )

            except Exception:
                delete_photo(new_photo or "")
                raise

            # Remove old image only after the update succeeds.
            if new_photo and old_photo:
                delete_photo(old_photo)

            flash("Your room listing has been updated.")
            return redirect(
                url_for("owner_dashboard")
            )

    return render_template(
        "edit_room.html",
        room=room,
        allowed_room_types=ALLOWED_ROOM_TYPES,
        allowed_amenities=ALLOWED_AMENITIES
    )


# --------------------------------------------------
# MARK AVAILABLE / UNAVAILABLE
# --------------------------------------------------

@app.route(
    "/owner/toggle/<int:room_id>",
    methods=["POST"]
)
@login_required("owner")
def toggle_room(room_id):
    with get_db() as db:
        room = db.execute(
            """
            SELECT *
            FROM rooms
            WHERE id = ? AND owner_id = ?
            """,
            (room_id, current_user()["id"])
        ).fetchone()

        if not room:
            abort(404)

        db.execute(
            """
            UPDATE rooms
            SET available = ?
            WHERE id = ? AND owner_id = ?
            """,
            (
                0 if room["available"] else 1,
                room_id,
                current_user()["id"]
            )
        )

    flash("Room availability updated.")
    return redirect(url_for("owner_dashboard"))


# --------------------------------------------------
# DELETE ROOM
# --------------------------------------------------

@app.route(
    "/owner/delete/<int:room_id>",
    methods=["POST"]
)
@login_required("owner")
def delete_room(room_id):
    with get_db() as db:
        room = db.execute(
            """
            SELECT *
            FROM rooms
            WHERE id = ? AND owner_id = ?
            """,
            (room_id, current_user()["id"])
        ).fetchone()

        if not room:
            abort(404)

        photo = room["photo"] or ""

        db.execute(
            "DELETE FROM rooms WHERE id = ? AND owner_id = ?",
            (room_id, current_user()["id"])
        )

    delete_photo(photo)

    flash("Property deleted.")
    return redirect(url_for("owner_dashboard"))


# --------------------------------------------------
# TENANT DASHBOARD
# --------------------------------------------------

@app.route("/tenant")
@login_required("tenant")
def tenant_dashboard():
    tenant_id = current_user()["id"]

    with get_db() as db:
        favourites = db.execute(
            """
            SELECT rooms.*, users.name AS owner_name
            FROM favourites
            JOIN rooms
                ON favourites.room_id = rooms.id
            JOIN users
                ON rooms.owner_id = users.id
            WHERE favourites.tenant_id = ?
            """,
            (tenant_id,)
        ).fetchall()

        enquiries = db.execute(
            """
            SELECT enquiries.*, rooms.title
            FROM enquiries
            JOIN rooms
                ON enquiries.room_id = rooms.id
            WHERE enquiries.tenant_id = ?
            ORDER BY enquiries.id DESC
            """,
            (tenant_id,)
        ).fetchall()

    return render_template(
        "tenant_dashboard.html",
        favourites=favourites,
        enquiries=enquiries
    )


# --------------------------------------------------
# FAVOURITES
# --------------------------------------------------

@app.route(
    "/favourite/<int:room_id>",
    methods=["POST"]
)
@login_required("tenant")
def favourite(room_id):
    tenant_id = current_user()["id"]

    with get_db() as db:
        room = db.execute(
            """
            SELECT id
            FROM rooms
            WHERE id = ? AND available = 1
            """,
            (room_id,)
        ).fetchone()

        if not room:
            abort(404)

        exists = db.execute(
            """
            SELECT 1
            FROM favourites
            WHERE tenant_id = ? AND room_id = ?
            """,
            (tenant_id, room_id)
        ).fetchone()

        if exists:
            db.execute(
                """
                DELETE FROM favourites
                WHERE tenant_id = ? AND room_id = ?
                """,
                (tenant_id, room_id)
            )
        else:
            db.execute(
                """
                INSERT INTO favourites(tenant_id, room_id)
                VALUES(?,?)
                """,
                (tenant_id, room_id)
            )

    return redirect(request.referrer or url_for("index"))


# --------------------------------------------------
# TENANT ENQUIRIES
# --------------------------------------------------

@app.route(
    "/enquire/<int:room_id>",
    methods=["POST"]
)
@login_required("tenant")
def enquire(room_id):
    tenant_id = current_user()["id"]

    message = request.form.get(
        "message",
        "I am interested in renting this property."
    ).strip()

    if not message or len(message) > 1000:
        flash("Enter a message of up to 1000 characters.")
        return redirect(request.referrer or url_for("index"))

    with get_db() as db:
        room = db.execute(
            """
            SELECT id
            FROM rooms
            WHERE id = ? AND available = 1
            """,
            (room_id,)
        ).fetchone()

        if not room:
            abort(404)

        try:
            db.execute(
                """
                INSERT INTO enquiries(
                    tenant_id, room_id, message
                )
                VALUES(?,?,?)
                """,
                (tenant_id, room_id, message)
            )

            flash("Your enquiry has been sent.")

        except sqlite3.IntegrityError:
            flash(
                "You have already enquired about this property."
            )

    return redirect(request.referrer or url_for("index"))


# --------------------------------------------------
# UPDATE ENQUIRY STATUS
# --------------------------------------------------

@app.route(
    "/enquiry/<int:enquiry_id>/<status>",
    methods=["POST"]
)
@login_required("owner")
def update_enquiry(enquiry_id, status):
    if status not in ("Accepted", "Declined"):
        abort(400)

    with get_db() as db:
        result = db.execute(
            """
            UPDATE enquiries
            SET status = ?
            WHERE id = ?
            AND room_id IN (
                SELECT id
                FROM rooms
                WHERE owner_id = ?
            )
            """,
            (
                status,
                enquiry_id,
                current_user()["id"]
            )
        )

        if result.rowcount == 0:
            abort(404)

    flash("Enquiry status updated.")
    return redirect(url_for("owner_dashboard"))


# --------------------------------------------------
# CONTACT PAGE
# --------------------------------------------------

@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        name = request.form.get(
            "name", ""
        ).strip()

        email = request.form.get(
            "email", ""
        ).strip()

        message = request.form.get(
            "message", ""
        ).strip()

        if (
            not name or not email or not message
            or len(name) > 100
            or len(email) > 254
            or len(message) > 3000
        ):
            flash("Please complete the form with valid details.")
            return redirect(url_for("contact"))

        with get_db() as db:
            db.execute(
                """
                INSERT INTO contact_messages(
                    name, email, message
                )
                VALUES(?,?,?)
                """,
                (name, email, message)
            )

        flash("Your message has been saved on this device.")
        return redirect(url_for("contact"))

    return render_template(
        "index.html",
        rooms=[],
        saved=set(),
        location="",
        room_type="",
        min_rent="",
        max_rent="",
        contact_only=True
    )


# --------------------------------------------------
# FILE SIZE ERROR
# --------------------------------------------------

@app.errorhandler(413)
def too_large(error):
    flash("The upload is too large. Maximum request size is 8 MB.")

    return redirect(
        request.referrer or url_for("owner_dashboard")
    )


# --------------------------------------------------
# START APPLICATION
# --------------------------------------------------

init_db()


if __name__ == "__main__":
    app.run(debug=True)