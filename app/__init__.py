from flask import Flask, flash, redirect, render_template, session, url_for
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from flask_socketio import SocketIO, emit, join_room, leave_room, send
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from werkzeug.security import check_password_hash, generate_password_hash
from wtforms import PasswordField, StringField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Email, EqualTo, Length

# Flask
app = Flask(__name__)
app.secret_key = "SECRET"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///project.db"

# SQLAlchemy
db = SQLAlchemy(app)

# Flask Login
login_manager = LoginManager()
login_manager.init_app(app)

# SocketIO
socketio = SocketIO(app)


# Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String, unique=True, nullable=False)
    password = db.Column(db.String)

    def __repr__(self) -> str:
        return super().__repr__()

    def save(self):
        db.session.add(self)
        db.session.commit()

    def delete(self):
        db.session.delete(self)
        db.session.commit()


with app.app_context():
    db.create_all()


@login_manager.user_loader
def user_loader(user_id):
    return User.query.get(user_id)


# Forms
class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=6)])
    remember_me = BooleanField(label="Remember me")
    submit = SubmitField("Log in")


class CreateUserForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField(
        "Confirm Password", validators=[DataRequired(), EqualTo("password")]
    )
    submit = SubmitField("Create")


class DeleteUserForm(FlaskForm):
    submit = SubmitField("Delete User")


class ChatForm(FlaskForm):
    public_submit = SubmitField("Public")
    room = StringField("Room", validators=[])
    create_room_submit = SubmitField("Create")
    message = StringField("Message", validators=[])
    broadcast_submit = SubmitField("Send")


# Auth
@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("protected"))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember_me.data)
            return redirect(url_for("protected"))
        else:
            flash(message="Login failed; Invalid email or password.", category="danger")

    return render_template("login.html", form=form)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/protected")
@login_required
def protected():
    return render_template("protected.html")


@app.route("/logout")
def logout():
    logout_user()
    return render_template("index.html")


# Errors
@app.errorhandler(401)
def page_unauthorized(e):
    return render_template("401.html"), 401


@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404


@app.errorhandler(500)
def internal_server_error(e):
    return render_template("500.html"), 500


# Users CRUD
@app.route("/users")
@login_required
def user_list():
    users = db.session.execute(db.select(User).order_by(User.email)).scalars()
    return render_template("user/list.html", users=users)


@app.route("/users/create", methods=["GET", "POST"])
def user_create():
    form = CreateUserForm()

    if form.validate_on_submit():
        user_exist = User.query.filter_by(email=form.email.data).first()
        if not user_exist:
            hashed_password = generate_password_hash(
                form.password.data, method="sha256"
            )
            new_user = User(email=form.email.data, password=hashed_password)
            new_user.save()
            flash("User created successfully", category="success")
            return redirect(url_for("login"))
        else:
            flash("User already exist", category="info")

    return render_template("user/create.html", form=form)


@app.route("/user/<int:id>")
@login_required
def user_detail(id):
    user = db.get_or_404(User, id)
    return render_template("user/detail.html", user=user)


@app.route("/user/<int:id>/delete", methods=["GET", "POST"])
@login_required
def user_delete(id):
    user = db.get_or_404(User, id)

    form = DeleteUserForm()

    if form.validate_on_submit():
        user.delete()
        return redirect(url_for("user_list"))

    return render_template("user/delete.html", user=user, form=form)


# Chat
@app.route("/chat", methods=["GET", "POST"])
@login_required
def chat():
    form = ChatForm()

    if form.validate_on_submit():
        if form.public_submit.data:
            return redirect(url_for("public"))

        if form.broadcast_submit.data:
            data = {
                "email": current_user.email,
                "message": form.message.data,
            }
            emit("broadcast", data, broadcast=True, namespace="/")

        if form.create_room_submit.data:
            return redirect(url_for("private", room=form.room.data))

    return render_template("chat/chat.html", form=form)


@app.route("/public")
@login_required
def public():
    room = "public"
    session["room"] = room
    return render_template("chat/public.html", room=room)


@app.route("/private/<room>")
@login_required
def private(room: str):
    session["room"] = room
    return render_template("chat/private.html", room=room)


@socketio.on("message")
def handle_message(msg):
    room = session.get("room")
    data = {
        "email": current_user.email,
        "message": msg["message"],
    }
    print(f"Received message: {msg['message']} from room: {room}")
    send(message=data, to=room)


@socketio.on("connect")
def connect():
    room = session.get("room")
    join_room(room)
    data = {"email": current_user.email, "message": "has entered the room"}
    send(data, to=room)


@socketio.on("disconnect")
def disconnect():
    room = session.get("room")
    leave_room(room)
    data = {"email": current_user.email, "message": "has left the room"}
    send(data, to=room)
    print(f"{current_user.email} has left the room {room}")
