from flask import Flask, render_template, flash, request, redirect, url_for
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField, ValidationError
from wtforms.validators import DataRequired, Email, EqualTo, Length

from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from datetime import datetime
import os
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import date
from wtforms.widgets import TextArea
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user

load_dotenv()

# Create a Flask Instance
app = Flask(__name__)
app.app_context().push()

# Add Database
app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+pymysql://root:{os.getenv("SQL_PASSWORD")}@localhost/login'

# Secret Key!
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
# Initialize the Database
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Flask_Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
  return Users.query.get(int(user_id))


# Create Login Form
class LoginForm(FlaskForm):
  username = StringField("Username", validators=[DataRequired()])
  password = PasswordField("Password", validators=[DataRequired()])
  submit = SubmitField("Submit")


# Create Login Page
@app.route('/login', methods=["GET", "POST"])
def login():
  form = LoginForm()
  
  if form.validate_on_submit():
    user = Users.query.filter_by(username=form.username.data).first()
    if user:
      # Check the hash
      if check_password_hash(user.password_hash, form.password.data):
        login_user(user)
        flash("Login Successfully!")
        return redirect(url_for('dashboard'))
      else:
        flash("Wrong Password or Username - Try Again!")
    else:
      flash("That User Doesn't Exist - Try Again!")

  return render_template('login.html', form=form)

# Create Logout Function
@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
  logout_user()
  flash("You Have Been Logged Out!")
  return redirect(url_for('login'))

# Create DashBoard Page
@app.route('/dashboard', methods=["GET", "POST"])
@login_required
def dashboard():
  return render_template('dashboard.html')


# Create a Blog Post model
class Posts(db.Model):
  id = db.Column(db.Integer, primary_key=True)
  title = db.Column(db.String(255))
  content = db.Column(db.Text)
  author = db.Column(db.String(255))
  date_posted = db.Column(db.DateTime, default=datetime.utcnow)
  slug = db.Column(db.String(255))

# Create a Posts Form
class PostForm(FlaskForm):
  title = StringField("Title", validators=[DataRequired()])
  content = StringField("Content", validators=[DataRequired()], widget=TextArea())
  author = StringField("Author", validators=[DataRequired()])
  slug = StringField("Slug", validators=[DataRequired()])
  submit = SubmitField("Submit")

# Create a route decorator
@app.route('/')
def index():
  return render_template('app.html')
# Invalid URL
@app.errorhandler(404)
def page_not_found(e):
  return render_template('404.html')
# Internal Server Error
@app.errorhandler(500)
def page_not_found(e):
  return render_template('500.html')

# Create User Model
class Users(db.Model, UserMixin):
  id = db.Column(db.Integer, primary_key=True)
  username = db.Column(db.String(20), nullable=False, unique=True)
  name = db.Column(db.String(100), nullable=False)
  email = db.Column(db.String(200), nullable=False, unique=True)
  date_added = db.Column(db.DateTime, default=datetime.utcnow)
  
  # Password Hashing
  password_hash = db.Column(db.String(128))

  @property
  def password(self):
    raise AttributeError('Password is not a readable attribute!')
  
  @password.setter
  def password(self, password):
    self.password_hash = generate_password_hash(password)
  
  def verify_password(self, password):
    return check_password_hash(self.password_hash, password)


  # Create A String
  def __repr__(self):
    return '<Name %r>' % self.name
  
# Create a User Form Class
class AddUserForm(FlaskForm):
  name = StringField("Name", validators=[DataRequired()])
  username = StringField("Username", validators=[DataRequired()])
  email = StringField("Email", validators=[Email()])
  password_hash = PasswordField("Password", validators=[DataRequired(), EqualTo('password_hash2', message='Passwords Must Match')])
  password_hash2 = PasswordField("Confirm Password", validators=[DataRequired()])
  submit = SubmitField("Submit")

# Create an User Update Form
class UpdateUserForm(FlaskForm):
  name = StringField("Edit Name", validators=[DataRequired()])
  username = StringField("Username", validators=[DataRequired()])
  email = StringField("Edit Email", validators=[Email()])
  submit = SubmitField("Submit")

# Create a Password Form Class
class PasswordForm(FlaskForm):
  email = StringField("What's Your Email", validators=[DataRequired()])
  password_hash = PasswordField("What's Your Password", validators=[DataRequired()])
  submit = SubmitField("Submit")

# Create User Page
@app.route('/user/add', methods=['GET','POST'])
def add_user():
  name = None
  email = None
  password_hash = None
  username = None

  form = AddUserForm()
  # Validate Form
  if form.validate_on_submit():
    name = form.name.data
    username = form.username.data
    email = form.email.data
    password_hash = form.password_hash.data

    form.name.data = ''
    form.username.data = ''
    form.email.data = ''
    form.password_hash.data = ''

    # Hash the password
    hashed_pw = generate_password_hash(password_hash, method="pbkdf2")

    new_user = Users(name=name, username=username, email=email, password_hash=hashed_pw)
    db.session.add(new_user)
    db.session.commit()

    flash("User Added Successfully!")

  our_users=Users.query.order_by(Users.date_added)
  return render_template('user.html',
    name = name,
    form = form,
    our_users=our_users)

# Update Database Record
@app.route('/user/update/<int:id>',methods=['GET','POST'])
def user_update(id):
  form = UpdateUserForm()
  user_to_update = Users.query.get_or_404(id)
  if request.method == "POST":
    user_to_update.name = request.form['name']
    user_to_update.email = request.form['email']
    user_to_update.username = request.form['username']
    try:
      db.session.commit()
      flash('User Updated Successfully!')
      return render_template("edit_user.html",
        form=form,
        user_to_update=user_to_update)
    except:
      flash('Error! Looks like there was a problem... Try Again!')
      return render_template("edit_user.html",
        form=form,
        user_to_update=user_to_update,
        id=id)
  else:
    return render_template("edit_user.html",
        form=form,
        user_to_update=user_to_update,
        id=id)

# Delete Database Record
@app.route('/user/delete/<int:id>')
def user_delete(id):
  user_to_delete = Users.query.get_or_404(id)
  name = None
  form = AddUserForm()

  try:
    db.session.delete(user_to_delete)
    db.session.commit()
    flash("User Deleted Successfully!")
    our_users=Users.query.order_by(Users.date_added)
    return render_template('user.html',
      name = name,
      form = form,
      our_users=our_users)

  except:
    flash("Whoops! There was a problem deleting user, try again...")
    return render_template('user.html',
      name = name,
      form = form,
      our_users=our_users)
  
# Create Password Test Page
@app.route('/test_pw', methods=['GET','POST'])
def test_pw():
  email = None
  password = None
  pw_to_check = None
  passed = None

  form = PasswordForm()

  # Validate Form
  if form.validate_on_submit():
    email = form.email.data
    password = form.password_hash.data

    # Clear the form
    form.email.data = ''
    form.password_hash.data = ''

    # Lookup User by Email Address
    pw_to_check = Users.query.filter_by(email=email).first()

    # Check Hashed Password
    passed = check_password_hash(pw_to_check.password_hash, password)

  return render_template("test_pw.html",
    email = email,
    password = password,
    pw_to_check=pw_to_check,
    passed = passed,
    form = form)

# Creates Page to Display All Posts
@app.route('/posts')
def posts():
  # Grab all the posts from the database
  posts = Posts.query.order_by(Posts.date_posted)
  return render_template("posts.html", posts=posts)

# Open Specific Post Page
@app.route('/posts/<int:id>')
def post(id):
  post = Posts.query.get_or_404(id)
  return render_template('post.html', post=post)

# Add Post Page
@app.route('/add-post', methods=['GET','POST'])
def add_post():
  form = PostForm()

  if form.validate_on_submit():
    post = Posts(title=form.title.data, 
      content=form.content.data,
      author=form.author.data,
      slug=form.slug.data)
    # Clear the Form
    form.title.data = ''
    form.content.data = ''
    form.author.data = ''
    form.slug.data = ''

    # Add post data to database
    db.session.add(post)
    db.session.commit()

    # Return a Messgae
    flash("Blog Post Submitted Successfully!")

  # Redirect to the webpage
  return render_template("add_post.html", form=form)

# Edit Blog Page
@app.route('/posts/edit/<int:id>', methods=['GET','POST'])
def edit_post(id):
  post = Posts.query.get_or_404(id)
  form = PostForm()

  if form.validate_on_submit():
    post.title = form.title.data
    post.author = form.author.data
    post.slug = form.slug.data
    post.content = form.content.data

    # Update Database
    db.session.add(post)
    db.session.commit()
    flash("Post Has Been Updated!")

    return redirect(url_for('post', id=post.id))
  
  form.title.data = post.title
  form.author.data = post.author
  form.slug.data = post.slug
  form.content.data = post.content
  return render_template('edit_post.html', form=form)

# Delete Blog Page
@app.route('/post/delete/<int:id>')
def delete_post(id):
  post_to_delete = Posts.query.get_or_404(id)
  title = None
  form = PostForm()

  try:
    db.session.delete(post_to_delete)
    db.session.commit()
    flash("User Deleted Successfully!")
    our_posts=Posts.query.order_by(Posts.date_posted)
    return render_template('posts.html',
      title = title,
      form = form,
      our_posts=our_posts)

  except:
    flash("Whoops! There was a problem deleting blog, try again...")
    return render_template('posts.html',
      title = title,
      form = form,
      our_posts=our_posts)