from flask import Blueprint, render_template, redirect, url_for, request
from flask_bootstrap import Bootstrap
from flask_login import login_user, login_required, logout_user, current_user

from flask_wtf import Form
from wtforms import StringField, PasswordField, BooleanField
from wtforms.fields.html5 import EmailField
from wtforms.validators import DataRequired, Email, Length, EqualTo 

from .models import db, login_manager, User, Recording

from werkzeug.security import generate_password_hash, check_password_hash
from google.cloud import storage

# import librosa
import io
from pydub import AudioSegment
import requests

import logging as lg


class LoginForm(Form):
    email = EmailField('Email', validators=[DataRequired(), Email(message = 'Invalid Email'), Length(min=4, max=50)], render_kw={"placeholder": "Enter email address"})
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8, max=80)], render_kw={"placeholder": "Enter password"})
    remember = BooleanField('Remember password')


class SignupForm(Form):
    first_name = StringField('First Name', validators=[DataRequired(), Length(min=4, max=50)], render_kw={"placeholder": "Enter first name"})
    last_name = StringField('Last Name', validators=[DataRequired(), Length(min=4, max=50)], render_kw={"placeholder": "Enter last name"})
 
    email = EmailField('Email', validators=[DataRequired(), Length(min=4, max=50)], render_kw={"placeholder": "Enter email address"})
    password = PasswordField('Password', validators=[DataRequired(), EqualTo('confirm_password', message='Passwords must match'), Length(min=8, max=80)], render_kw={"placeholder": "Enter password"})
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), Length(min=8, max=80)], render_kw={"placeholder": "Confirm password"})


main_bp = Blueprint('main', __name__, template_folder='templates', static_folder='static', static_url_path='/fapp/static')

login_manager.login_view = 'main.login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id)) 


@main_bp.route('/')
def index():
    return redirect(url_for("main.dashboard"))


@main_bp.route('/dashboard/')
@login_required 
def dashboard():
    recs = Recording.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', user=current_user, recs=recs)


@main_bp.route('/addcall/')
@login_required
def addcall():
    error = request.args.get('error')
    uploaded = request.args.get('uploaded')
    return render_template('addcall.html', user=current_user, error=error, uploaded=uploaded)

# @main_bp.route('/recordings/')
# @login_required
# def addcall():
#     return render_template('addcall.html', user=current_user, error=error, uploaded=uploaded)

@main_bp.route('/login/', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for("main.dashboard"))

        return render_template('login.html', form=form, err='Invalid email or password')
    return render_template('login.html', form=form, err='')


@main_bp.route('/signup/', methods=['GET', 'POST'])
def signup():  
    form = SignupForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(first_name=form.first_name.data, 
                        last_name=form.last_name.data, 
                        email=form.email.data, 
                        password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for("main.login"))

    return render_template('signup.html', form=form)


@main_bp.route('/logout/')
@login_required 
def logout():
    logout_user()
    return redirect(url_for('main.login'))


@main_bp.route('/integrations/aircall-redirect/', methods=['GET'])
@login_required
def aircall_redirect():
    aircall_code = request.args.get('code')
    oauth_client_id = 'bmjuz_rujZ2JFbN2gWhfExGHQ4fdGQs0FwIBuXCc1Os'
    oauth_client_secret = 'tugSX9S25fuLX3AlfTVwgEtvd0SQWmJdRndyItMZvTQ'
    redirect_uri = 'https://gonogo.ai/integrations/aircall-redirect/'
    url = 'https://api.aircall.io/v1/oauth/token'
    myobj = {"client_id": oauth_client_id,
              "client_secret": oauth_client_secret,
              "code": aircall_code,
              "redirect_uri": redirect_uri,
              "grant_type": "authorization_code"}


    x = requests.post(url, data=myobj)
    print(x)
    return redirect(url_for("main.dashboard"))


@main_bp.route('/integrations/aircall-install/', methods=['GET', 'POST'])
@login_required
def aircall_install():
    if request.method == 'POST':
        oauth_client_id = 'bmjuz_rujZ2JFbN2gWhfExGHQ4fdGQs0FwIBuXCc1Os'
        redirect_uri = 'https://gonogo.ai/integrations/aircall-redirect/'
        print("frere")
        return redirect("https://dashboard-v2.aircall.io/oauth/authorize?client_id={0}&redirect_uri={1}&response_type=code&scope=public_api".format(oauth_client_id, redirect_uri))
    elif request.method == 'GET':
        return render_template('integrations_aircall.html')

    return render_template('integrations_aircall.html')

@main_bp.route('/upload', methods=['POST'])
def upload():
    """Process the uploaded file and upload it to Google Cloud Storage."""
    uploaded_file = request.files.get('file')

    if not uploaded_file:
        return 'No file uploaded.', 400

    if "audio" not in uploaded_file.content_type:
        return redirect(url_for('main.addcall', error="format"))

    uploaded_file_read = uploaded_file.read()
    if len(uploaded_file_read) > 1000000:
        return redirect(url_for('main.addcall', error="size"))

    # Create a Cloud Storage client.
    gcs = storage.Client()

    # Get the bucket that the file will be uploaded to.
    bucket = gcs.get_bucket("scribtranscripts")

    # Create a new blob and upload the file's content.
    blob = bucket.blob(uploaded_file.filename)

    blob.upload_from_string(
        uploaded_file_read,
        content_type=uploaded_file.content_type
    )

    audioseg = AudioSegment.from_file(io.BytesIO(uploaded_file_read), format="mp3")
    duration = audioseg.duration_seconds

    new_recording = Recording(file_path=blob.public_url,
                              user_id=current_user.id,
                              file_format=uploaded_file.content_type,
                              file_size=blob.size,
                              duration=duration)

    db.session.add(new_recording)
    db.session.commit()

    # The public URL can be used to directly access the uploaded file via HTTP.
    return redirect(url_for('main.addcall', uploaded=True))


