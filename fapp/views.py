from flask import Blueprint, render_template, redirect, url_for, request
from flask_bootstrap import Bootstrap
from flask_login import login_user, login_required, logout_user, current_user

from flask_wtf import Form
from wtforms import StringField, PasswordField, BooleanField
from wtforms.fields.html5 import EmailField
from wtforms.validators import DataRequired, Email, Length, EqualTo

from .models import db, login_manager, User, Recording, Integration, Call

from werkzeug.security import generate_password_hash, check_password_hash
from google.cloud import storage, tasks_v2
from sqlalchemy import func, desc

# import librosa
import io
from pydub import AudioSegment
import requests
import datetime


import logging as lg


class LoginForm(Form):
    email = EmailField('Email', validators=[DataRequired(), Email(message='Invalid Email'), Length(min=4, max=50)],
                       render_kw={"placeholder": "Enter email address"})
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8, max=80)],
                             render_kw={"placeholder": "Enter password"})
    remember = BooleanField('Remember password')


class SignupForm(Form):
    first_name = StringField('First Name', validators=[DataRequired(), Length(min=4, max=50)],
                             render_kw={"placeholder": "Enter first name"})
    last_name = StringField('Last Name', validators=[DataRequired(), Length(min=4, max=50)],
                            render_kw={"placeholder": "Enter last name"})

    email = EmailField('Email', validators=[DataRequired(), Length(min=4, max=50)],
                       render_kw={"placeholder": "Enter email address"})
    password = PasswordField('Password',
                             validators=[DataRequired(), EqualTo('confirm_password', message='Passwords must match'),
                                         Length(min=8, max=80)], render_kw={"placeholder": "Enter password"})
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), Length(min=8, max=80)],
                                     render_kw={"placeholder": "Confirm password"})


main_bp = Blueprint('main', __name__, template_folder='templates', static_folder='static',
                    static_url_path='/fapp/static')

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


@main_bp.route('/calls/')
@login_required
def calls():
    max_id = db.session.query(func.max(Call.aircall_id)).scalar()
    token = Integration.query.filter_by(name="Aircall").one().token
    get_aircall_calls(token, max_id)

    all_calls = Call.query.order_by(desc(Call.answered_at)).all()
    return render_template('calls.html', user=current_user, calls=all_calls)


@main_bp.route('/call/<int:call_id>/')
def call(call_id):
    transcript_url = generate_download_signed_url_v4('gonogo_transcripts',
                                                     '{0}.wav_transcript.fr.vtt'.format(str(call_id)))
    call_url = generate_download_signed_url_v4('scribtranscripts', '{0}.wav'.format(str(call_id)))
    try:
        transcript_url = generate_download_signed_url_v4('gonogo_transcripts', '{0}.wav_transcript.fr.vtt'.format(str(call_id)))
        call_url = generate_download_signed_url_v4('scribtranscripts', '{0}.wav'.format(str(call_id)))

        # transcript_url = 'gs://gonogo_transcripts/{0}.wav_transcript.fr.vtt'.format(str(call_id))
        # call_url = 'gs://scribtranscripts/{0}.wav'.format(str(call_id))
        return render_template('call_test.html', user=current_user, transcript_url=transcript_url, call_url=call_url)
    except:
        return 'Transcript not yet generated or not found'



@main_bp.route('/addcall/')
@login_required
def addcall():
    error = request.args.get('error')
    uploaded = request.args.get('uploaded')
    return render_template('addcall.html', user=current_user, error=error, uploaded=uploaded)

# @main_bp.route('/calltest/')
# # @login_required
# def calltest():
#     return render_template('call_test.html')

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
    body = {"client_id": oauth_client_id,
            "client_secret": oauth_client_secret,
            "code": aircall_code,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code"}

    x = requests.post(url, data=body)

    token = x.json()['access_token']

    new_integration = Integration(name="Aircall",
                                  token=token)
    db.session.add(new_integration)
    db.session.commit()

    return redirect(url_for("main.aircall_install"))


@main_bp.route('/integrations/aircall-install/', methods=['GET', 'POST'])
@login_required
def aircall_install():
    # to do flow for when inte already installed, but here is a draft lol

    existing_intes = Integration.query.all()
    for x in existing_intes:
        if x.name == 'Aircall':
            return 'Aircall is already installed!'

    if request.method == 'POST':
        oauth_client_id = 'bmjuz_rujZ2JFbN2gWhfExGHQ4fdGQs0FwIBuXCc1Os'
        redirect_uri = 'https://gonogo.ai/integrations/aircall-redirect/'
        return redirect(
            "https://dashboard-v2.aircall.io/oauth/authorize?client_id={0}&redirect_uri={1}&response_type=code&scope=public_api".format(
                oauth_client_id, redirect_uri))
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


def get_aircall_calls(token, max_id):
    def get_calls():
        url = "https://api.aircall.io/v1/calls?order=desc"
        first_page = session.get(url, headers={'Authorization': 'Bearer {0}'.format(token)}).json()
        yield first_page
        num_pages = first_page['meta']['total'] // first_page['meta']['per_page'] + 1
        if num_pages > 1:
            for p in range(2, num_pages + 1):
                next_page = session.get(url, params={'page': p},
                                        headers={'Authorization': 'Bearer {0}'.format(token)}).json()
                yield next_page

    session = requests.Session()
    for page in get_calls():
        all_calls = page['calls']
        max_id = 0 if not max_id else max_id

        for x in all_calls:
            if int(x['id']) <= int(max_id):
                db.session.commit()
                return 'done'

            if x['answered_at'] and x['ended_at'] and x['recording']:
                aircall_id = x['id']
                direction = x['direction']
                answered_at = x['answered_at']
                ended_at = x['ended_at']
                duration = x['duration']

                user_name = x['user']['name'] if x['user'] else None

                number_name = x['number']['name'] if x['number'] else None
                number_digits = x['number']['digits'] if x['number'] else None
                number_country = x['number']['country'] if x['number'] else None

                contact_number_digits = x['raw_digits']

                contact_first_name = x['contact']['first_name'] if x['contact'] else None
                contact_last_name = x['contact']['last_name'] if x['contact'] else None
                contact_company = x['contact']['company_name'] if x['contact'] else None

                tags = '|'.join([y['name'] for y in x['tags']]) if x['tags'] else None
                comments = '|'.join([y['content'] for y in x['comments']]) if x['comments'] else None

                recording_url = x['recording']

                new_call = Call(aircall_id=aircall_id,
                                direction=direction,
                                answered_at=datetime.datetime.fromtimestamp(answered_at),
                                ended_at=datetime.datetime.fromtimestamp(ended_at),
                                duration=duration,
                                user_name=user_name,
                                number_name=number_name,
                                number_digits=number_digits,
                                number_country=number_country,
                                contact_number_digits=contact_number_digits,
                                contact_first_name=contact_first_name,
                                contact_last_name=contact_last_name,
                                contact_company=contact_company,
                                tags=tags,
                                comments=comments)

                db.session.add(new_call)
                db.session.flush()

                call_id = new_call.id
                message = '{{"call_id":"{0}", "recording_url":"{1}"}}'.format(call_id, recording_url)
                function_name = "upload_to_storage"
                queue_name = "upload-to-storage"
                create_task_for_google_function(function_name, queue_name, message)

    db.session.commit()
    return 'done'


def create_task_for_google_function(function_name, queue_name, message):
    # Create a client.
    client = tasks_v2.CloudTasksClient()

    project = 'crucial-media-325221'
    queue = queue_name
    location = 'us-central1'
    url = 'https://us-central1-crucial-media-325221.cloudfunctions.net/' + function_name
    audience = 'https://us-central1-crucial-media-325221.cloudfunctions.net/' + function_name
    service_account_email = 'betterscrib@crucial-media-325221.iam.gserviceaccount.com'
    payload = message

    # Construct the fully qualified queue name.
    parent = client.queue_path(project, location, queue)

    # Construct the request body.
    task = {
        "http_request": {  # Specify the type of request.
            "http_method": tasks_v2.HttpMethod.POST,
            "url": url,  # The full url path that the task will be sent to.
            "oidc_token": {"service_account_email": service_account_email, "audience": audience},
            "headers": {"Content-Type": "application/json"},
        }
    }

    if payload is not None:
        # The API expects a payload of type bytes.
        converted_payload = payload.encode()

        # Add the payload to the request.
        task["http_request"]["body"] = converted_payload

    # Use the client to build and send the task.
    response = client.create_task(request={"parent": parent, "task": task})

    print("Created task {}".format(response.name))



def generate_download_signed_url_v4(bucket_name, blob_name):
    """Generates a v4 signed URL for downloading a blob.

    Note that this method requires a service account key file. You can not use
    this if you are using Application Default Credentials from Google Compute
    Engine or from the Google Cloud SDK.
    """
    # bucket_name = 'your-bucket-name'
    # blob_name = 'your-object-name'

    storage_client = storage.Client()
    bucket = storage_client.bucket(bucket_name)
    blob = bucket.blob(blob_name)

    url = blob.generate_signed_url(
        version="v4",
        # This URL is valid for 15 minutes
        expiration=datetime.timedelta(minutes=15),
        # Allow GET requests using this URL.
        method="GET",
    )

    print("Generated GET signed URL:")
    print(url)
    print("You can use this URL with any user agent, for example:")
    print("curl '{}'".format(url))
    return url