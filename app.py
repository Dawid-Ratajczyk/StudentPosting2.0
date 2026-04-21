import base64
import hashlib
import io
import logging
import os
import random
import re
import secrets
import time
from collections import deque
from datetime import datetime, timezone
from threading import Lock, Thread
from base64 import b64encode
from urllib.parse import urlparse

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
from sqlalchemy import func, text
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
ALLOWED_IMAGE_MIMETYPES = frozenset(
    {"image/jpeg", "image/png", "image/webp", "image/gif", "image/jpg"}
)
MAX_IMAGE_PIXELS = 20_000_000
ADMIN_USERNAME = "StudentDawid"

USERNAME_RE = re.compile(r"^[a-zA-Z0-9._-]{2,20}$")
_RATE_LOCK = Lock()
_RATE_BUCKETS: dict[str, deque] = {}


def allow_rate_limit(key: str, max_events: int, window_sec: float) -> bool:
    """Return True if request is allowed; False if rate limit exceeded."""
    now = time.monotonic()
    with _RATE_LOCK:
        dq = _RATE_BUCKETS.setdefault(key, deque())
        while dq and dq[0] < now - window_sec:
            dq.popleft()
        if len(dq) >= max_events:
            return False
        dq.append(now)
        return True


def rate_limit_client_ip(suffix: str, max_events: int, window_sec: float) -> bool:
    ip = request.remote_addr or "unknown"
    return allow_rate_limit(f"{suffix}:{ip}", max_events, window_sec)


def rate_limit_user(suffix: str, user_id: int, max_events: int, window_sec: float) -> bool:
    return allow_rate_limit(f"{suffix}:u{user_id}", max_events, window_sec)


def safe_log_fragment(value, max_len: int = 120) -> str:
    """Reduce log injection (newlines / long blobs) from user-controlled strings."""
    if value is None:
        return ""
    s = str(value).replace("\r", " ").replace("\n", " ").strip()
    return s[:max_len] if len(s) > max_len else s


def sanitize_printable_line(s: str, max_len: int) -> str:
    out = "".join(c for c in (s or "") if c.isprintable() and c not in "\x00\x7f")
    return out.strip()[:max_len] or None


def is_safe_redirect_url(url: str) -> bool:
    if not url or not url.startswith(("http://", "https://")):
        return False
    try:
        target = urlparse(url)
        base = urlparse(request.host_url)
        if not target.netloc or target.netloc != base.netloc:
            return False
        return target.scheme in ("http", "https")
    except Exception:
        return False


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


class Grupa(db.Model):
    __tablename__ = "grupa"
    id = db.Column(db.Integer, primary_key=True)
    nazwa = db.Column(db.String(80), unique=True, nullable=False)
    opis = db.Column(db.String(300))
    tworca_id = db.Column(db.Integer, db.ForeignKey("uzytkownik.id"), nullable=False)
    tworca = db.relationship("Uzytkownik", foreign_keys=[tworca_id])
    czlonkowie_rel = db.relationship(
        "GrupaCzlonek", back_populates="grupa", cascade="all, delete-orphan"
    )
    wiadomosci = db.relationship(
        "WiadomoscGrupy",
        back_populates="grupa",
        cascade="all, delete-orphan",
    )

    def liczba_czlonkow(self):
        return len(self.czlonkowie_rel)


class GrupaCzlonek(db.Model):
    __tablename__ = "grupa_czlonek"
    grupa_id = db.Column(db.Integer, db.ForeignKey("grupa.id"), primary_key=True)
    uzytkownik_id = db.Column(db.Integer, db.ForeignKey("uzytkownik.id"), primary_key=True)
    grupa = db.relationship("Grupa", back_populates="czlonkowie_rel")
    uzytkownik = db.relationship("Uzytkownik", backref=db.backref("grupa_czlonkostwo", lazy=True))


class WiadomoscGrupy(db.Model):
    __tablename__ = "wiadomosc_grupy"
    id = db.Column(db.Integer, primary_key=True)
    grupa_id = db.Column(db.Integer, db.ForeignKey("grupa.id"), nullable=False)
    autor_id = db.Column(db.Integer, db.ForeignKey("uzytkownik.id"), nullable=False)
    tresc = db.Column(db.Text(1000), nullable=False)
    utworzono = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    grupa = db.relationship("Grupa", back_populates="wiadomosci")
    autor = db.relationship("Uzytkownik")


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
                time.sleep(random.uniform(0, 0.4))
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


@app.after_request
def add_cache_and_security_headers(response):
    if request.path.startswith("/static/"):
        response.headers["Cache-Control"] = "public, max-age=86400"
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; "
        "script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
        "style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
        "img-src 'self' data: blob:; "
        "font-src 'self' https://cdn.jsdelivr.net data:; "
        "connect-src 'self'; "
        "base-uri 'self'; "
        "form-action 'self'",
    )
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
        if not rate_limit_client_ip("register", 5, 3600):
            flash(message="Zbyt wiele prób rejestracji z tej sieci. Spróbuj później.", category="warning")
            return redirect(url_for("rejestracja"))
        nazwa_uzytkownika = (request.form.get("nazwa_uzytkownika") or "").strip()
        haslo = request.form.get("haslo") or ""
        if not USERNAME_RE.match(nazwa_uzytkownika):
            flash(
                message="Login: 2–20 znaków, tylko litery, cyfry, . _ -",
                category="warning",
            )
            return redirect(url_for("rejestracja"))
        if len(haslo) < 8:
            flash(message="Hasło musi mieć co najmniej 8 znaków", category="warning")
            return redirect(url_for("rejestracja"))

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
        if not rate_limit_client_ip("login", 12, 15 * 60):
            flash(message="Zbyt wiele prób logowania. Odczekaj kilkanaście minut.", category="warning")
            return redirect(url_for("logowanie"))
        login = (request.form.get("nazwa_uzytkownika") or "").strip()[:20]
        password = request.form.get("haslo") or ""
        user = Uzytkownik.query.filter_by(nazwa_uzytkownika=login).first()
        if user and (
            check_password_hash(user.haslo, password)
            or user.haslo == password
        ):
            if user.haslo == password:
                # Backward compatibility for old plaintext passwords.
                user.haslo = generate_password_hash(password)
                db.session.commit()
            app.logger.info(
                "Login ok user=%s ip=%s",
                safe_log_fragment(login, 24),
                safe_log_fragment(request.remote_addr or "", 45),
            )
            flash(message="Zalogowano", category="success")
            session["uzytkownik"] = login
            return redirect(url_for("index"))
        app.logger.warning(
            "Login failed user=%s ip=%s",
            safe_log_fragment(login, 24),
            safe_log_fragment(request.remote_addr or "", 45),
        )
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
        user = (user or "").strip()[:20]
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
        uzytkownik = Uzytkownik.query.filter_by(
            nazwa_uzytkownika=session["uzytkownik"]
        ).first()
        if not uzytkownik:
            session.pop("uzytkownik", None)
            return redirect(url_for("logowanie"))
        if not rate_limit_user("dodaj_post", uzytkownik.id, 12, 10 * 60):
            flash(message="Zbyt często dodajesz posty. Spróbuj za kilka minut.", category="warning")
            return redirect(url_for("dodaj_post"))

        max_length = 80
        tresc = (request.form.get("tresc") or "").replace("\x00", "")[:max_length]
        location = sanitize_printable_line(request.form.get("location", ""), 80)
        uploaded_file = request.files.get("file")
        has_file = bool(uploaded_file and uploaded_file.filename)
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
                ct = (uploaded_file.content_type or "").split(";")[0].strip().lower()
                picture_type = ct if ct in ALLOWED_IMAGE_MIMETYPES else "image/jpeg"
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

        app.logger.info(
            "Adding post user=%s post_id=%s",
            safe_log_fragment(session.get("uzytkownik"), 24),
            nowy_post.id,
        )
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
        uzytkownik = Uzytkownik.query.filter_by(
            nazwa_uzytkownika=session["uzytkownik"]
        ).first()
        if not uzytkownik:
            session.pop("uzytkownik", None)
            return redirect(url_for("logowanie"))
        if not rate_limit_user("dodaj_notke", uzytkownik.id, 24, 10 * 60):
            flash(message="Zbyt często dodajesz notki. Spróbuj za kilka minut.", category="warning")
            return redirect(url_for("dodaj_notke"))
        tresc = (request.form.get("tresc") or "").replace("\x00", "")[:350]
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
    mime = (post.img_name or "").split(";")[0].strip().lower()
    if mime not in ALLOWED_IMAGE_MIMETYPES:
        mime = "image/jpeg"
    return send_file(img, mimetype=mime)


@app.route("/moje_posty")
def moje_posty():
    if "uzytkownik" not in session:

        return redirect(url_for("logowanie"))

    uzytkownik = Uzytkownik.query.filter_by(
        nazwa_uzytkownika=session["uzytkownik"]
    ).first()
    posty = Post.query.filter_by(autor_id=uzytkownik.id).order_by(Post.id.desc()).all()

    return render_template("moje_posty.html", posty=posty)


def uzytkownik_z_sesji():
    if "uzytkownik" not in session:
        return None
    return Uzytkownik.query.filter_by(nazwa_uzytkownika=session["uzytkownik"]).first()


def czy_w_grupie(grupa, user):
    if not user:
        return False
    return GrupaCzlonek.query.filter_by(grupa_id=grupa.id, uzytkownik_id=user.id).first() is not None


@app.route("/grupy", methods=["GET", "POST"])
def grupy():
    user = uzytkownik_z_sesji()
    if request.method == "POST":
        if not user:
            flash(message="Zaloguj się, aby utworzyć grupę", category="warning")
            return redirect(url_for("logowanie"))
        if not rate_limit_user("grupa_create", user.id, 8, 60 * 60):
            flash(message="Osiągnięto limit tworzenia grup na ten czas.", category="warning")
            return redirect(url_for("grupy"))
        nazwa = sanitize_printable_line(request.form.get("nazwa") or "", 80) or ""
        opis = sanitize_printable_line(request.form.get("opis") or "", 300) or ""
        if len(nazwa) < 2:
            flash(message="Nazwa grupy musi mieć co najmniej 2 znaki", category="warning")
            return redirect(url_for("grupy"))
        if Grupa.query.filter(func.lower(Grupa.nazwa) == nazwa.lower()).first():
            flash(message="Grupa o takiej nazwie już istnieje", category="warning")
            return redirect(url_for("grupy"))
        grupa = Grupa(nazwa=nazwa, opis=opis or None, tworca_id=user.id)
        db.session.add(grupa)
        db.session.flush()
        db.session.add(GrupaCzlonek(grupa_id=grupa.id, uzytkownik_id=user.id))
        db.session.commit()
        flash(message="Utworzono grupę — jesteś jej członkiem", category="success")
        return redirect(url_for("grupa_chat", grupa_id=grupa.id))

    grupy_list = Grupa.query.order_by(Grupa.nazwa.asc()).all()
    moje_id_grup = set()
    if user:
        moje_id_grup = {
            r.grupa_id for r in GrupaCzlonek.query.filter_by(uzytkownik_id=user.id).all()
        }
    return render_template("grupy.html", grupy_list=grupy_list, moje_id_grup=moje_id_grup)


@app.route("/grupy/<int:grupa_id>", methods=["GET"])
def grupa_chat(grupa_id):
    grupa = Grupa.query.get_or_404(grupa_id)
    user = uzytkownik_z_sesji()
    if not user or not czy_w_grupie(grupa, user):
        flash(message="Dołącz do grupy, aby zobaczyć czat", category="warning")
        return redirect(url_for("grupy"))
    wiadomosci = (
        WiadomoscGrupy.query.filter_by(grupa_id=grupa.id).order_by(WiadomoscGrupy.id.asc()).limit(500).all()
    )
    czlonkowie = [c.uzytkownik for c in grupa.czlonkowie_rel]
    return render_template(
        "grupa_chat.html",
        grupa=grupa,
        wiadomosci=wiadomosci,
        czlonkowie=czlonkowie,
    )


@app.route("/grupy/<int:grupa_id>/dolacz", methods=["POST"])
def grupa_dolacz(grupa_id):
    user = uzytkownik_z_sesji()
    if not user:
        flash(message="Zaloguj się, aby dołączyć do grupy", category="warning")
        return redirect(url_for("logowanie"))
    grupa = Grupa.query.get_or_404(grupa_id)
    if GrupaCzlonek.query.filter_by(grupa_id=grupa.id, uzytkownik_id=user.id).first():
        flash(message="Już należysz do tej grupy", category="warning")
        return redirect(url_for("grupy"))
    db.session.add(GrupaCzlonek(grupa_id=grupa.id, uzytkownik_id=user.id))
    db.session.commit()
    flash(message="Dołączono do grupy", category="success")
    return redirect(url_for("grupa_chat", grupa_id=grupa.id))


@app.route("/grupy/<int:grupa_id>/opusc", methods=["POST"])
def grupa_opusc(grupa_id):
    user = uzytkownik_z_sesji()
    if not user:
        return redirect(url_for("logowanie"))
    grupa = Grupa.query.get_or_404(grupa_id)
    rekord = GrupaCzlonek.query.filter_by(grupa_id=grupa.id, uzytkownik_id=user.id).first()
    if not rekord:
        flash(message="Nie jesteś w tej grupie", category="warning")
        return redirect(url_for("grupy"))
    gid = grupa.id
    db.session.delete(rekord)
    db.session.flush()
    pozostalo = GrupaCzlonek.query.filter_by(grupa_id=gid).count()
    if pozostalo == 0:
        WiadomoscGrupy.query.filter_by(grupa_id=gid).delete()
        Grupa.query.filter_by(id=gid).delete()
        db.session.commit()
        flash(
            message="Opuściłeś grupę — grupa została usunięta (nikt już w niej nie był)",
            category="success",
        )
        return redirect(url_for("grupy"))
    db.session.commit()
    flash(message="Opuściłeś grupę", category="success")
    return redirect(url_for("grupy"))


@app.route("/grupy/<int:grupa_id>/wiadomosc", methods=["POST"])
def grupa_wiadomosc(grupa_id):
    user = uzytkownik_z_sesji()
    if not user:
        return redirect(url_for("logowanie"))
    grupa = Grupa.query.get_or_404(grupa_id)
    if not czy_w_grupie(grupa, user):
        flash(message="Nie możesz pisać w tej grupie", category="warning")
        return redirect(url_for("grupy"))
    if not allow_rate_limit(f"gr_chat:u{user.id}:g{grupa.id}", 45, 60):
        flash(message="Wysyłasz wiadomości zbyt często. Odczekaj chwilę.", category="warning")
        return redirect(url_for("grupa_chat", grupa_id=grupa.id))
    tresc = ((request.form.get("tresc") or "").replace("\x00", ""))[:1000].strip()
    if not tresc:
        flash(message="Wiadomość nie może być pusta", category="warning")
        return redirect(url_for("grupa_chat", grupa_id=grupa.id))
    db.session.add(
        WiadomoscGrupy(
            grupa_id=grupa.id,
            autor_id=user.id,
            tresc=tresc,
            utworzono=datetime.now(timezone.utc),
        )
    )
    db.session.commit()
    return redirect(url_for("grupa_chat", grupa_id=grupa.id))


@app.route("/grupy/<int:grupa_id>/wiadomosci")
def grupa_wiadomosci_json(grupa_id):
    user = uzytkownik_z_sesji()
    if not user:
        abort(401)
    grupa = Grupa.query.get_or_404(grupa_id)
    if not czy_w_grupie(grupa, user):
        abort(403)
    after_id = max(request.args.get("after", default=0, type=int), 0)
    rows = (
        WiadomoscGrupy.query.filter(
            WiadomoscGrupy.grupa_id == grupa.id, WiadomoscGrupy.id > after_id
        )
        .order_by(WiadomoscGrupy.id.asc())
        .limit(200)
        .all()
    )
    return jsonify(
        {
            "items": [
                {
                    "id": w.id,
                    "autor": w.autor.nazwa_uzytkownika if w.autor else "?",
                    "tresc": w.tresc,
                    "utworzono": w.utworzono.isoformat() if w.utworzono else None,
                }
                for w in rows
            ]
        }
    )


@app.route("/usun_post/<int:post_id>", methods=["POST"])
def usun_post(post_id):
    ref = request.referrer
    back_url = ref if (ref and is_safe_redirect_url(ref)) else url_for("moje_posty")
    if "uzytkownik" not in session:
        return redirect(url_for("logowanie"))

    uzytkownik = Uzytkownik.query.filter_by(
        nazwa_uzytkownika=session["uzytkownik"]
    ).first()
    if not uzytkownik:
        session.pop("uzytkownik", None)
        return redirect(url_for("logowanie"))
    if not rate_limit_user("usun_post", uzytkownik.id, 50, 3600):
        flash(message="Zbyt wiele usunięć w krótkim czasie. Spróbuj później.", category="warning")
        return redirect(back_url)
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
    ref = request.referrer
    back_url = ref if (ref and is_safe_redirect_url(ref)) else url_for("index")
    if "uzytkownik" not in session:
        return redirect(url_for("logowanie"))
    if not current_user_is_admin():
        flash(message="Brak uprawnień administratora", category="warning")
        return redirect(back_url)

    admin_user = Uzytkownik.query.filter_by(nazwa_uzytkownika=session["uzytkownik"]).first()
    if admin_user and not rate_limit_user("regen_opis", admin_user.id, 40, 3600):
        flash(message="Zbyt wiele regeneracji AI w tym czasie.", category="warning")
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
