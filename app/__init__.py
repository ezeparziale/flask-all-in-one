from flask import Flask, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo

from werkzeug.security import generate_password_hash, check_password_hash

from flask_login import (
    LoginManager,
    UserMixin,
    login_required,
    logout_user,
    current_user,
    login_user,
)

# Flask
app = Flask(__name__)
app.secret_key = "SECRET"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///project.db"

# SQLAlchemy
db = SQLAlchemy(app)

# Flask Login
login_manager = LoginManager()
login_manager.init_app(app)


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

# Auth
@app.route("/", methods=["GET", "POST"])
@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated: # type: ignore
        return redirect(url_for("protected"))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for("protected"))
        else:
            flash(message="Login failed; Invalid email or password.", category="danger")

    return render_template("login.html", form=form)


@app.route("/protected")
@login_required
def protected():
    return render_template("protected.html")


@app.route("/logout")
def logout():
    logout_user()
    return render_template("logout.html")


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
