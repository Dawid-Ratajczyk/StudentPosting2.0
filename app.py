import base64
import hashlib
import io
import logging
import os
import secrets
import time
from threading import Thread
from base64 import b64encode

from PIL import Image, ImageOps
from dotenv import load_dotenv
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    send_file,
    flash,
    send_from_directory,
    abort,
    jsonify,
)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from werkzeug.security import check_password_hash, generate_password_hash

load_dotenv()
from ai import prompt_img


app = Flask(__name__)
app.debug = False
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-change-me")
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024
app.static_folder = "static"
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("app.log"), logging.StreamHandler()],
)


def ensure_csrf_token():
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


def current_user_is_admin():
    return session.get("uzytkownik") == ADMIN_USERNAME


@app.context_processor
def inject_csrf_token():
    return {"csrf_token": ensure_csrf_token(), "is_admin": current_user_is_admin()}


@app.before_request
def validate_csrf():
    if request.method != "POST":
        return
    token = session.get("_csrf_token")
    form_token = request.form.get("csrf_token")
    if not token or not form_token or not secrets.compare_digest(token, form_token):
        abort(400, "Invalid CSRF token")

# Database--------------------------------------------------------
db_path = os.environ.get(
    "DATABASE_PATH", os.path.join(os.path.dirname(__file__), "instance/data.db")
)
desc_db_path = os.environ.get(
    "DESC_DATABASE_PATH", os.path.join(os.path.dirname(__file__), "instance/desc.db")
)
os.makedirs(os.path.dirname(db_path), exist_ok=True)
os.makedirs(os.path.dirname(desc_db_path), exist_ok=True)
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{db_path}"
app.config["SQLALCHEMY_BINDS"] = {
    "data": "sqlite:///data.db",
    "desc": f"sqlite:///{desc_db_path}",
}
db = SQLAlchemy(app)
API_SECURITY_TOKEN = "foobar"
ALLOWED_IMAGE_FORMATS = {"JPEG", "PNG", "WEBP", "GIF"}
MAX_IMAGE_PIXELS = 20_000_000
ADMIN_USERNAME = "StudentDawid"


class Uzytkownik(db.Model):
    __tablename__ = "uzytkownik"
    id = db.Column(db.Integer, primary_key=True)
    nazwa_uzytkownika = db.Column(db.String(20), unique=True)
    haslo = db.Column(db.String(255))


class Post(db.Model):
    __tablename__ = "post"
    id = db.Column(db.Integer, primary_key=True)
    tresc = db.Column(db.Text(350))
    autor_id = db.Column(db.Integer, db.ForeignKey("uzytkownik.id"))
    autor = db.relationship("Uzytkownik", backref=db.backref("posty", lazy=True))
    img = db.Column(db.LargeBinary)
    img_name = db.Column(db.Text)
    location = db.Column(db.String(80))

    def toDict(self):
        return {
            "tresc": self.tresc,
            "id": self.id,
            "autorId": self.autor.id,
            "img": base64.b64encode(self.img).decode() if self.img else None,
            "location": self.location,
        }


class Desc(db.Model):
    __bind_key__ = "desc"
    __tablename__ = "desc"
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer)
    desc = db.Column(db.Text(200))


def validate_image_blob(blob_data):
    if not blob_data:
        return False, "Pusty plik"
    try:
        image = Image.open(io.BytesIO(blob_data))
        image.verify()
        image = Image.open(io.BytesIO(blob_data))
        image.load()
        image_format = (image.format or "").upper()
        if image_format not in ALLOWED_IMAGE_FORMATS:
            return False, "Niedozwolony format obrazu"
        width, height = image.size
        if width * height > MAX_IMAGE_PIXELS:
            return False, "Obraz ma za duzą rozdzielczość"
    except Exception:
        return False, "Plik nie jest poprawnym obrazem"
    return True, None


def enqueue_ai_description(post_id, text, image_blob=None):
    def worker():
        with app.app_context():
            try:
                if Desc.query.filter_by(post_id=post_id).first():
                    return
                encoded_img = base64.b64encode(image_blob).decode() if image_blob else None
                ai_desc = prompt_img(encoded_img, text, app.logger)
                if ai_desc:
                    db.session.add(Desc(post_id=post_id, desc=ai_desc))
                    db.session.commit()
            except Exception as exc:
                app.logger.exception(exc)

    Thread(target=worker, daemon=True).start()


with app.app_context():
    db.create_all()
    post_columns = db.session.execute(text("PRAGMA table_info(post)")).fetchall()
    if "location" not in [column[1] for column in post_columns]:
        db.session.execute(text("ALTER TABLE post ADD COLUMN location TEXT"))
        db.session.commit()


# Site---------------------------------------------------------------
class IgnoreEndpointFilter(logging.Filter):
    def filter(self, record):
        # record.msg contains request line, e.g. "127.0.0.1 - - [..] "GET /healthz HTTP/1.1" 200 -"
        # You can check against request path here
        return "/picture" not in record.getMessage()


log = logging.getLogger("werkzeug")
log.addFilter(IgnoreEndpointFilter())


@app.route("/favicon.ico", methods=["GET"])
def favicon():
    return send_file("static/favicon.gif", mimetype="image/ico")


@app.after_request  # Cache for static files and favicon
def add_cache_header(response):
    if request.path.startswith("/static/"):
        response.headers["Cache-Control"] = "public, max-age=86400"
    return response


@app.template_filter("b64encode")
def base64_encode_filter(data):
    if data:
        return b64encode(data).decode("utf-8")
    return None


@app.route("/")
def index():
    posty = Post.query.filter(Post.img.isnot(None)).order_by(Post.id.desc()).all()
    opisy = {d.post_id: d.desc for d in Desc.query.order_by(Desc.id.desc()).all()}

    return render_template("index.html", posty=posty, opisy=opisy)


@app.route("/notki")
def notki():
    posty = Post.query.filter(Post.img.is_(None)).order_by(Post.id.desc()).all()
    return render_template("notki.html", posty=posty)


@app.route("/uzytkownik/<string:nazwa_uzytkownika>")
def posty_uzytkownika(nazwa_uzytkownika):
    user = Uzytkownik.query.filter_by(nazwa_uzytkownika=nazwa_uzytkownika).first_or_404()
    posty = Post.query.filter_by(autor_id=user.id).order_by(Post.id.desc()).all()
    opisy = {d.post_id: d.desc for d in Desc.query.order_by(Desc.id.desc()).all()}
    return render_template("posty_uzytkownika.html", user=user, posty=posty, opisy=opisy)


@app.route("/styles.css")
def serve_css():
    return send_from_directory("static", "styles.css")


# User---------------------------------------------------------------
@app.route("/rejestracja", methods=["GET", "POST"])
def rejestracja():
    if request.method == "POST":
        nazwa_uzytkownika = request.form["nazwa_uzytkownika"]
        haslo = request.form["haslo"]

        if Uzytkownik.query.filter_by(nazwa_uzytkownika=nazwa_uzytkownika).first():
            flash(message="Użytkownik już istnieje", category="warning")
            return redirect(url_for("rejestracja"))

        flash(message="Rejestracja udana", category="success")
        nowy_uzytkownik = Uzytkownik(
            nazwa_uzytkownika=nazwa_uzytkownika,
            haslo=generate_password_hash(haslo),
        )
        db.session.add(nowy_uzytkownik)
        db.session.commit()

        return redirect(url_for("logowanie"))
    return render_template("rejestracja.html")


@app.route("/logowanie", methods=["GET", "POST"])
def logowanie():
    if request.method == "POST":
        login = request.form["nazwa_uzytkownika"]
        user = Uzytkownik.query.filter_by(nazwa_uzytkownika=login).first()
        if user and (
            check_password_hash(user.haslo, request.form["haslo"])
            or user.haslo == request.form["haslo"]
        ):
            if user.haslo == request.form["haslo"]:
                # Backward compatibility for old plaintext passwords.
                user.haslo = generate_password_hash(request.form["haslo"])
                db.session.commit()
            app.logger.info(f"Logged by: {user}")
            flash(message="Zalogowano", category="success")
            session["uzytkownik"] = login
            return redirect(url_for("index"))
        flash(message="Błędne dane", category="warning")
    return render_template("logowanie.html")


@app.route("/wyloguj")
def wyloguj():
    flash(message="Wylogowano", category="success")
    session.pop("uzytkownik", None)
    return redirect(url_for("index"))


# Posty---------------------------------------------------
def description_update():
    legacy_desc_rows = Desc.query.filter(Desc.post_id.is_(None)).all()
    for row in legacy_desc_rows:
        row.post_id = row.id
    if legacy_desc_rows:
        db.session.commit()

    existing_post_ids = {
        post_id for (post_id,) in db.session.query(Desc.post_id).filter(Desc.post_id.isnot(None))
    }
    for post_id, image_blob, text in db.session.query(Post.id, Post.img, Post.tresc):
        if post_id in existing_post_ids:
            continue
        enqueue_ai_description(post_id, text, image_blob)


@app.route("/api/post", methods=["GET"])  # Api for getting all the posts as json
def all_posts():
    # if 'Authentication' not in request.headers:
    #   abort(401, "No auth header")
    # if request.headers['Authentication'] != API_SECURITY_TOKEN:
    #    abort(401, "Invalid token")
    post_type = request.args.get("type", "all")
    user = request.args.get("user")
    page = max(request.args.get("page", default=1, type=int), 1)
    per_page = min(max(request.args.get("per_page", default=20, type=int), 1), 100)

    query = Post.query
    if post_type == "image":
        query = query.filter(Post.img.isnot(None))
    elif post_type == "text":
        query = query.filter(Post.img.is_(None))

    if user:
        user_obj = Uzytkownik.query.filter_by(nazwa_uzytkownika=user).first()
        if not user_obj:
            return jsonify({"items": [], "meta": {"page": page, "per_page": per_page, "total": 0}})
        query = query.filter(Post.autor_id == user_obj.id)

    pagination = query.order_by(Post.id.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    opisy = {
        d.post_id: d.desc
        for d in Desc.query.filter(Desc.post_id.in_([p.id for p in pagination.items])).all()
    }
    items = []
    for post in pagination.items:
        payload = post.toDict()
        payload["autor"] = post.autor.nazwa_uzytkownika if post.autor else None
        payload["opinia"] = opisy.get(post.id)
        items.append(payload)
    return jsonify(
        {
            "items": items,
            "meta": {
                "page": page,
                "per_page": per_page,
                "total": pagination.total,
                "pages": pagination.pages,
            },
        }
    )


@app.route("/dodaj_post", methods=["GET", "POST"])  # Dodawanie postow
def dodaj_post():
    if "uzytkownik" not in session:
        return redirect(url_for("logowanie"))
    if request.method == "POST":

        tresc = request.form["tresc"]
        location = request.form.get("location", "").strip()[:80] or None
        uploaded_file = request.files.get("file")
        has_file = bool(uploaded_file and uploaded_file.filename)
        max_length = 80
        tresc = tresc[:max_length]
        if not has_file:
            flash(message="Post wymaga zdjęcia", category="warning")
            return redirect(url_for("dodaj_post"))
        picture = None
        picture_type = None
        raw_picture = uploaded_file.stream.read()
        if raw_picture:
            try:
                is_valid, validation_error = validate_image_blob(raw_picture)
                if not is_valid:
                    flash(message=validation_error, category="warning")
                    return redirect(url_for("dodaj_post"))
                picture = force_resize_blob(raw_picture, 900, 900)
                picture_type = uploaded_file.content_type
            except Exception as exc:
                app.logger.exception(exc)
                flash(message="Nie udało się przetworzyć zdjęcia", category="warning")
                return redirect(url_for("dodaj_post"))
        if not picture:
            flash(message="Dodaj poprawne zdjęcie", category="warning")
            return redirect(url_for("dodaj_post"))

        # Prevent rapid duplicate submissions (common on mobile multi-tap).
        picture_hash = hashlib.sha256(picture).hexdigest()
        dedupe_key = f"{session['uzytkownik']}|{tresc}|{location or ''}|{picture_hash}"
        last_key = session.get("last_post_key")
        last_ts = session.get("last_post_ts", 0)
        now_ts = time.time()
        if last_key == dedupe_key and (now_ts - float(last_ts)) < 10:
            flash(message="Ten post został już dodany chwilę temu", category="warning")
            return redirect(url_for("index"))
        session["last_post_key"] = dedupe_key
        session["last_post_ts"] = now_ts

        uzytkownik = Uzytkownik.query.filter_by(
            nazwa_uzytkownika=session["uzytkownik"]
        ).first()

        # Create Post first to get ID
        nowy_post = Post(
            tresc=tresc,
            autor_id=uzytkownik.id,
            img=picture,
            img_name=picture_type,
            location=location,
        )
        db.session.add(nowy_post)
        db.session.commit()

        enqueue_ai_description(nowy_post.id, tresc, picture)

        app.logger.info(f"Adding post by: {uzytkownik}")
        flash(
            message="Dodano Post. Opinia studenta wygeneruje się za chwilę.",
            category="success",
        )
        return redirect(url_for("index"))

    return render_template("dodaj_post.html")


@app.route("/dodaj_notke", methods=["GET", "POST"])
def dodaj_notke():
    if "uzytkownik" not in session:
        return redirect(url_for("logowanie"))
    if request.method == "POST":
        tresc = request.form["tresc"][:350]
        uzytkownik = Uzytkownik.query.filter_by(
            nazwa_uzytkownika=session["uzytkownik"]
        ).first()
        nowy_post = Post(
            tresc=tresc,
            autor_id=uzytkownik.id,
            img=None,
            img_name=None,
        )
        db.session.add(nowy_post)
        db.session.commit()
        enqueue_ai_description(nowy_post.id, tresc)
        flash(message="Dodano notkę. Opinia studenta wygeneruje się za chwilę.", category="success")
        return redirect(url_for("notki"))
    return render_template("dodaj_notke.html")


@app.route("/picture/<int:post_id>")
def picture(post_id):
    post = Post.query.get_or_404(post_id)
    if not post.img:
        return "", 404
    img = io.BytesIO(post.img)
    return send_file(img, mimetype=post.img_name)


@app.route("/moje_posty")
def moje_posty():
    if "uzytkownik" not in session:

        return redirect(url_for("logowanie"))

    uzytkownik = Uzytkownik.query.filter_by(
        nazwa_uzytkownika=session["uzytkownik"]
    ).first()
    posty = Post.query.filter_by(autor_id=uzytkownik.id).order_by(Post.id.desc()).all()

    return render_template("moje_posty.html", posty=posty)


@app.route("/usun_post/<int:post_id>", methods=["POST"])
def usun_post(post_id):
    back_url = request.referrer or url_for("moje_posty")
    if "uzytkownik" not in session:
        return redirect(url_for("logowanie"))

    uzytkownik = Uzytkownik.query.filter_by(
        nazwa_uzytkownika=session["uzytkownik"]
    ).first()
    post = Post.query.get_or_404(post_id)
    if post.autor_id != uzytkownik.id and not current_user_is_admin():
        flash(message="Nie możesz usunąć cudzego wpisu", category="warning")
        return redirect(back_url)

    Desc.query.filter_by(post_id=post.id).delete()
    db.session.delete(post)
    db.session.commit()
    flash(message="Usunięto wpis", category="success")
    return redirect(back_url)


@app.route("/admin/regeneruj_opis/<int:post_id>", methods=["POST"])
def regeneruj_opis_admin(post_id):
    back_url = request.referrer or url_for("index")
    if "uzytkownik" not in session:
        return redirect(url_for("logowanie"))
    if not current_user_is_admin():
        flash(message="Brak uprawnień administratora", category="warning")
        return redirect(back_url)

    post = Post.query.get_or_404(post_id)
    Desc.query.filter_by(post_id=post.id).delete()
    db.session.commit()
    enqueue_ai_description(post.id, post.tresc, post.img)
    flash(message="Uruchomiono regenerację opinii AI dla wpisu", category="success")
    return redirect(back_url)


# Image--------------------------------------------------


def force_resize_blob(
    blob_data,
    target_width,
    target_height,
):
    image = Image.open(io.BytesIO(blob_data))
    # Respect iPhone EXIF orientation before resizing.
    image = ImageOps.exif_transpose(image)
    resized_image = image.resize(
        (target_width, target_height),
    )
    output_blob = io.BytesIO()

    if image.format and image.format.upper() in ["PNG", "GIF", "BMP", "TIFF"]:
        resized_image.save(output_blob, format=image.format)
    else:
        resized_image.save(output_blob, format="JPEG", quality=95)

    return output_blob.getvalue()


# Main---------------------------------------------------
if __name__ == "__main__":
    # Run data updates at startup
    with app.app_context():
        description_update()
    app.run(host="0.0.0.0", port=5000)
