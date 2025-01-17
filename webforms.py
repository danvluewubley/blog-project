from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField, ValidationError, TextAreaField
from wtforms.validators import DataRequired, Email, EqualTo, Length
from wtforms.widgets import TextArea
from flask_ckeditor import CKEditorField
from flask_wtf.file import FileField

# Create A Search Form
class SearchForm(FlaskForm):
  searched = StringField("Searched", validators=[DataRequired()])
  submit = SubmitField("Submit")


# Create Login Form
class LoginForm(FlaskForm):
  username = StringField("Username", validators=[DataRequired()])
  password = PasswordField("Password", validators=[DataRequired()])
  submit = SubmitField("Submit")


# Create a Posts Form
class PostForm(FlaskForm):
  title = StringField("Title", validators=[DataRequired()])
  content = CKEditorField('Content', validators=[DataRequired()])
  slug = StringField("Slug", validators=[DataRequired()])
  submit = SubmitField("Submit")


# Create a User Form Class
class AddUserForm(FlaskForm):
  name = StringField("Name", validators=[DataRequired()])
  username = StringField("Username", validators=[DataRequired()])
  email = StringField("Email", validators=[Email()])
  about_author = TextAreaField("About Author")
  password_hash = PasswordField("Password", validators=[DataRequired(), EqualTo('password_hash2', message='Passwords Must Match')])
  password_hash2 = PasswordField("Confirm Password", validators=[DataRequired()])
  profile_pic = FileField("Profile Pic")
  submit = SubmitField("Submit")


# Create an User Update Form
class UpdateUserForm(FlaskForm):
  name = StringField("Edit Name", validators=[DataRequired()])
  username = StringField("Username", validators=[DataRequired()])
  email = StringField("Edit Email", validators=[Email()])
  about_author = TextAreaField("About Author")
  profile_pic = FileField("Profile Pic")
  submit = SubmitField("Submit")


# Create a Password Form Class
class PasswordForm(FlaskForm):
  email = StringField("What's Your Email", validators=[DataRequired()])
  password_hash = PasswordField("What's Your Password", validators=[DataRequired()])
  submit = SubmitField("Submit")