from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import ForeignKey
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, LoginManager,current_user,login_required,logout_user,login_user
from datetime import date, datetime
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import ValidationError, DataRequired, Email, EqualTo
from werkzeug.urls import url_parse
from dateutil import parser
from flask_charts import GoogleCharts, Chart
from flask_bootstrap import Bootstrap


app = Flask(__name__)
app.config['SECRET_KEY'] = 'this is a secret key'
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///project_database.sqlite3"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login = LoginManager(app)
login.login_view = 'login'
charts = GoogleCharts(app)
Bootstrap(app)
#Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(60), index=True, unique=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    trackers = db.relationship('Tracker')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Tracker(db.Model):
    t_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(60))
    description = db.Column(db.String(150))
    type = db.Column(db.String(60))
    settings = db.Column(db.String(60))
    log = db.relationship('Log')
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)


class Log(db.Model):
    l_id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    value = db.Column(db.Integer)
    notes = db.Column(db.String(150))
    tracker_id = db.Column(db.Integer, db.ForeignKey('tracker.t_id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

@login.user_loader
def load_user(id):
    return User.query.get(int(id))

#Forms

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign In')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    password2 = PasswordField(
        'Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Please use a different username.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('Please use a different email address.')

#Routes


@app.route('/')
@app.route('/index')
@login_required
def index():
    tracker = Tracker.query.all()
    return render_template("index.html", user=current_user, tracker=tracker)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            return redirect(url_for('login'))
        login_user(user, remember=True)
        return redirect(url_for('index'))

    return render_template('login.html', title='Sign In', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route('/add-tracker-page', methods=['GET', 'POST'])
@login_required
def add_tracker_page():
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        tracker_type = request.form.get('type')
        settings = request.form.get('settings')

        current_user_id = current_user.id
        tracker = Tracker.query.filter_by(name=name).first()
        if tracker and current_user_id == tracker.user_id:
            return redirect(url_for('index'))
        else:
            new_tracker = Tracker(name=name, description=description, type=tracker_type, settings=settings,
                                    user_id=current_user_id)
            db.session.add(new_tracker)
            db.session.commit()
            return redirect(url_for('index'))

    return render_template("add_tracker_page.html")

@app.route('/add-log-page/<int:t_id>', methods=['GET', 'POST'])
@login_required
def add_log(t_id):
    tracker = Tracker.query.get(t_id)
    now = datetime.now()
    time = now.strftime("%Y-%m-%dT%H:%M:%S")
    mcv=[]
    if tracker.type=="Multiple Choice":
        for i in tracker.settings.split(","):
            mcv.append(i)
    if request.method == 'POST':
        stringtime = request.form.get('timestamp')
        value = request.form.get('value')
        notes = request.form.get('note')
        if stringtime:
            timestamp = parser.parse(stringtime)
            log = Log(timestamp=timestamp, value=value, notes=notes , user_id = current_user.id,tracker_id=t_id)
        else:
            log = Log(value=value, notes=notes , user_id = current_user.id,tracker_id=t_id)
        db.session.add(log)
        db.session.commit()
        return redirect(url_for('index'))

    return render_template('add_log_page.html', tracker = tracker , user=current_user, time=time, mcv=mcv)

@app.route('/edit-tracker/<int:t_id>', methods=['GET', 'POST'])
@login_required
def edit_tracker(t_id):
    tracker = Tracker.query.get(t_id)

    if request.method == 'POST':
        description = request.form.get('description')
        tracker_type = request.form.get('type')
        settings = request.form.get('settings')
        tracker.description = description
        tracker.type = tracker_type
        tracker.settings = settings
        db.session.commit()
        return redirect(url_for('index'))

    return render_template("edit_tracker_page.html", user=current_user, tracker=tracker)

@app.route('/delete-tracker/<int:t_id>', methods=['GET', 'POST'])
@login_required
def delete_tracker(t_id):
    tracker = Tracker.query.get(t_id)
    db.session.delete(tracker)
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/view_tracker/<int:t_id>', methods=['GET', 'POST'])
@login_required
def view_tracker(t_id):
    tracker = Tracker.query.get(t_id)
    trackers = Tracker.query.filter_by(t_id = t_id)
    logs = Log.query.filter_by(tracker_id = t_id)
    my_chart = Chart("LineChart", "my_chart")
    my_chart.data.add_column("datetime", "TimeStamp")
    
    if tracker.type=="Numerical":
        my_chart.data.add_column("number", "Value")
        for i in logs:
            time = i.timestamp
            my_chart.data.add_row([time, i.value])

    elif tracker.type=="Time Duration":
        my_chart.data.add_column("datetime", "Value")
        for i in logs:
            time = i.timestamp
            value = datetime.strptime(i.value,"%H:%M:%S")
            my_chart.data.add_row([time, value])
    else:
        my_chart.data.add_column("number", "Value")
        for i in logs:
            time = i.timestamp
            my_chart.data.add_row([time])
        
    return render_template("view_tracker.html", user=current_user, tracker=tracker, logs = logs , my_chart=my_chart)
    
@app.route('/edit-log-page/<int:l_id>', methods=['GET', 'POST'])
@login_required
def edit_log(l_id):
    log = Log.query.get(l_id)
    tracker = Tracker.query.get(log.tracker_id)
    time = log.timestamp.strftime("%Y-%m-%dT%H:%M:%S")
    mcv=[]
    if tracker.type=="Multiple Choice":
        for i in tracker.settings.split(","):
            mcv.append(i)
    if request.method == 'POST':
        stringtime = request.form.get('timestamp')
        value = request.form.get('value')
        notes = request.form.get('notes')
        timestamp = parser.parse(stringtime)
        log.timestamp = timestamp
        log.value = value
        log.notes = notes
        db.session.commit()
        return redirect(url_for('view_tracker', t_id=log.tracker_id))
    return render_template("edit_log_page.html", user=current_user, tracker=tracker, log=log,time=time,mcv=mcv)

@app.route('/delete-log/<int:l_id>', methods=['GET', 'POST'])
@login_required
def delete_log(l_id):
    log = Log.query.get(l_id)
    t_id = log.tracker_id
    db.session.delete(log)
    db.session.commit()
    return redirect(url_for('view_tracker', t_id=t_id))







if __name__=='__main__':
    app.run(debug = True)
