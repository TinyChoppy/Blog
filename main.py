from flask import Flask, render_template, redirect, url_for, request, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, LoginManager, login_required, current_user, logout_user, login_user
from flask_gravatar import Gravatar
from sqlalchemy import ForeignKey, Integer, Column, String, Text
from functools import wraps
from forms import CreatePostForm, RegisterForm, LogInForm, CommentForm
import os

app_root = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
ckeditor = CKEditor(app)
Bootstrap(app)
gravatar = Gravatar(app, size=100, rating="g")

# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(app_root, 'blog.db')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URI", "sqlite:///" + os.path.join(app_root, "blog.db"))
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    email = Column(String(100), unique=True)
    password = Column(String(100), nullable=False)
    name = Column(String(100), nullable=False)

    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")

    def __repr__(self):
        return f"User {self.name}"


class BlogPost(db.Model):
    __tablename__ = 'blog_posts'
    id = Column(Integer, primary_key=True)
    author_id = Column(Integer, ForeignKey("users.id"))
    author = relationship("User", back_populates="posts")

    comments = relationship("Comment", back_populates="parent_post")

    title = Column(String(250), unique=True, nullable=False)
    subtitle = Column(String(250), nullable=False)
    date = Column(String(250), nullable=False)
    body = Column(Text, nullable=False)
    img_url = Column(String(250), nullable=False)


class Comment(db.Model):
    __tablename__ = 'comments'
    id = Column(Integer, primary_key=True)
    author_id = Column(Integer, ForeignKey("users.id"))
    comment_author = relationship("User", back_populates="comments")

    post_id = Column(Integer, ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")

    text = Column(Text, nullable=False)


# create multiple table in database
with app.app_context():
    db.create_all()


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_anonymous or current_user.id != 1:
            return abort(403)
        return f(*args, **kwargs)

    return decorated_function


@app.route('/')
def get_all_posts():
    posts = db.session.query(BlogPost).all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=["POST", "GET"])
def register():
    r_form = RegisterForm()
    if r_form.validate_on_submit():
        r_email = r_form.email.data
        if User.query.filter_by(email=r_email).first():
            msg = "This email already exists, login now!"
            return redirect(url_for("login", msg=msg, email=r_email))
        else:
            pwhash = generate_password_hash(password=r_form.password.data, method="pbkdf2:sha256", salt_length=8)
            new_user = User(
                email=r_email,
                password=pwhash,
                name=r_form.name.data
            )
            db.session.add(new_user)
            db.session.commit()
            login_user(user=new_user)
            return redirect(url_for("get_all_posts"))
    return render_template("register.html", form=r_form)


@app.route('/login', methods=["POST", "GET"])
def login():
    msg = request.args.get('msg')
    l_form = LogInForm()
    if request.args.get("email"):
        l_form.email.data = request.args.get("email")
    if l_form.validate_on_submit():
        l_email = l_form.email.data
        user = User.query.filter_by(email=l_email).first()
        if user is None:
            msg = "This email is not exists, try again"
            return render_template("login.html", form=l_form, msg=msg)
        elif not check_password_hash(user.password, l_form.password.data):
            msg = "Password is not correct, try again"
            return render_template("login.html", form=l_form, msg=msg)
        else:
            login_user(user)
            return redirect(url_for("get_all_posts"))

    return render_template("login.html", form=l_form, msg=msg)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["POST", "GET"])
def show_post(post_id):
    c_form = CommentForm()
    requested_post = BlogPost.query.get(post_id)
    comments = db.session.query(Comment).all()
    if c_form.validate_on_submit():
        if current_user.is_authenticated:
            new_comment = Comment(
                text=c_form.comment.data,
                comment_author=current_user,
                parent_post=requested_post
            )

            db.session.add(new_comment)
            db.session.commit()
            return render_template("post.html", post=requested_post, form=c_form)
        return redirect(url_for('login', msg="You need login or register to comment"))
    return render_template("post.html", post=requested_post, form=c_form, all_comments=comments)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["POST", "GET"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=datetime.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
