from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, IntegerField, FileField, SelectField
from wtforms.validators import DataRequired, Email, Length, NumberRange

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(3,80)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(6,128)])
    role = SelectField('Role', choices=[('customer','Customer'),('seller','Seller')], validators=[DataRequired()])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username or Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class ProductForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(1,140)])
    description = TextAreaField('Description')
    price_rwf = IntegerField('Price (RWF)', validators=[DataRequired(), NumberRange(min=0)])
    image = FileField('Product image')
    submit = SubmitField('Create Product')

class CommentForm(FlaskForm):
    text = TextAreaField('Comment', validators=[DataRequired(), Length(max=500)])
    submit = SubmitField('Post Comment')

class MessageForm(FlaskForm):
    text = TextAreaField('Message', validators=[DataRequired(), Length(max=1000)])
    submit = SubmitField('Send Message')
