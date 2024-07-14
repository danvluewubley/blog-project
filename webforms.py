from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField, ValidationError
from wtforms.validators import DataRequired, Email, EqualTo, Length
from wtforms.widgets import TextArea

# Create Login Form
class LoginForm(FlaskForm):
  username = StringField("Username", validators=[DataRequired()])
  password = PasswordField("Password", validators=[DataRequired()])
  submit = SubmitField("Submit")

# Create a Posts Form
class PostForm(FlaskForm):
  title = StringField("Title", validators=[DataRequired()])
  content = StringField("Content", validators=[DataRequired()], widget=TextArea())
  author = StringField("Author", validators=[DataRequired()])
  slug = StringField("Slug", validators=[DataRequired()])
  submit = SubmitField("Submit")

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