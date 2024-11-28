from flask import Flask, render_template, url_for, redirect, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
import os
import random
from flask import jsonify
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
csrf = CSRFProtect(app)

# Mail configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'jakob.skole1511@gmail.com'
app.config['MAIL_PASSWORD'] = 'vvzt mtep bcbz rykr'  # Your email password (or App Password)
app.config['MAIL_DEFAULT_SENDER'] = 'jakob.skole1511@gmail.com'
mail = Mail(app)

# Database configuration
bcrypt = Bcrypt(app)
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(basedir, "instance", "database.db")}'
app.config['SECRET_KEY'] = 'Hemmeligpassord'
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
db = SQLAlchemy(app)

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    two_factor_code = db.Column(db.Integer, nullable=True)  # Temporary 2FA code field

class HighScore(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    score = db.Column(db.Integer, nullable=False)

    user = db.relationship('User', backref=db.backref('high_scores', lazy=True))

class RegisterForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Length(min=6, max=120)], render_kw={"placeholder": "Email"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Register')

    def validate_email(self, email):
        existing_user_email = User.query.filter_by(email=email.data).first()
        if existing_user_email:
            raise ValidationError('That email already exists. Please choose a different one.')

class LoginForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Length(min=6, max=120)], render_kw={"placeholder": "Email"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Login')

class ForgotPasswordForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Length(min=6, max=120)], render_kw={"placeholder": "Email"})
    submit = SubmitField('Reset Password')

class TwoFactorForm(FlaskForm):
    code = StringField(validators=[InputRequired(), Length(min=6, max=6)], render_kw={"placeholder": "2FA Code"})
    submit = SubmitField('Verify')

class ResetPasswordForm(FlaskForm):
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "New Password"})
    confirm_password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Confirm Password"})
    submit = SubmitField('Reset Password')

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            two_factor_code = random.randint(100000, 999999)
            user.two_factor_code = two_factor_code
            db.session.commit()

            msg = Message('Your 2FA Code', recipients=[user.email])
            msg.body = f'Your two-factor authentication code is: {two_factor_code}'
            mail.send(msg)

            login_user(user)
            return redirect(url_for('verify_2fa'))
    return render_template('login.html', form=form)




@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = s.dumps(user.email, salt='password-reset-salt')
            msg = Message('Password Reset Request', sender='noreply@yourapp.com', recipients=[user.email])
            link = url_for('reset_with_token', token=token, _external=True)
            msg.body = f'Your link to reset your password is {link}'
            mail.send(msg)
            flash('An email has been sent with instructions to reset your password.', 'info')
        else:
            flash('Email address not found.', 'warning')
    return render_template('forgot_password.html', form=form)

@app.route('/leaderboard', methods=['GET'])
def leaderboard():
    scores = HighScore.query.order_by(HighScore.score.desc()).all()
    return render_template('leaderboard.html', scores=scores)

@app.route('/delete_score/<int:score_id>', methods=['POST'])
@login_required
def delete_score(score_id):
    score = HighScore.query.get_or_404(score_id)
    if score.user_id == current_user.id:
        db.session.delete(score)
        db.session.commit()
        flash('Score deleted successfully!', 'success')
    else:
        flash('You can only delete your own scores!', 'error')
    return redirect(url_for('leaderboard'))

@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset_with_token(token):
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=3600)  # Token is valid for 1 hour
    except Exception as e:
        flash('The password reset link is invalid or has expired.', 'danger')
        return redirect(url_for('forgot_password'))

    user = User.query.filter_by(email=email).first()
    form = ResetPasswordForm()  # Use ResetPasswordForm instead

    if form.validate_on_submit():
        if form.password.data != form.confirm_password.data:
            flash('Passwords do not match.', 'warning')
            return redirect(url_for('reset_with_token', token=token))

        user.password = bcrypt.generate_password_hash(form.password.data)  # Hash the new password
        db.session.commit()
        flash('Your password has been updated!', 'success')
        return redirect(url_for('login'))  # Redirect to login after updating password

    return render_template('reset_password.html', form=form)

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/verify_2fa', methods=['GET', 'POST'])
@login_required
def verify_2fa():
    form = TwoFactorForm()
    if form.validate_on_submit():
        if int(form.code.data) == current_user.two_factor_code:
            current_user.two_factor_code = None
            db.session.commit()
            return redirect(url_for('dashboard'))
        else:
            return 'Invalid 2FA code', 401
    return render_template('verify_2fa.html', form=form)

@app.route('/save_score', methods=['POST'])
@login_required
def save_score():
    data = request.get_json()
    score = data.get('score')
    
    if score is not None:
        # Check if user already has a high score
        existing_score = HighScore.query.filter_by(user_id=current_user.id).first()
        
        if existing_score:
            # Update existing score if new score is higher
            if score > existing_score.score:
                existing_score.score = score
        else:
            # Create new high score entry
            new_score = HighScore(user_id=current_user.id, score=score)
            db.session.add(new_score)
        
        db.session.commit()
        return jsonify({'success': True, 'message': 'Score saved successfully'})
    
    return jsonify({'success': False, 'message': 'Invalid score'}), 400

@app.route('/spill')
@login_required
def spill():
    return render_template('spill.html')

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
