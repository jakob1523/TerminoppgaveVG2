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
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask import request, jsonify
from flask import session



app = Flask(__name__)
csrf = CSRFProtect(app)

# Mail konfigurasjon
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'jakob.skole1511@gmail.com'
app.config['MAIL_PASSWORD'] = 'vvzt mtep bcbz rykr'  # Your email password (or App Password)
app.config['MAIL_DEFAULT_SENDER'] = 'jakob.skole1511@gmail.com'
mail = Mail(app)

# Database konfigurasjon
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
    username = db.Column(db.String(50), nullable=False, unique=True)
    email = db.Column(db.String(120), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    two_factor_code = db.Column(db.Integer, nullable=True)  # Temporary 2FA code field

class HighScore(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    score = db.Column(db.Integer, nullable=False)
    user = db.relationship('User', backref=db.backref('high_scores', lazy=True))

class FlappyHighScore(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    flappyScore = db.Column(db.Integer, nullable=False)
    user = db.relationship('User', backref=db.backref('flappy_high_scores', lazy=True))

class SnakeHighScore(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    snakeScore = db.Column(db.Integer, nullable=False)
    user = db.relationship('User', backref=db.backref('snake_high_scores', lazy=True))


class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=3, max=50)], render_kw={"placeholder": "Brukernavn"})
    email = StringField(validators=[InputRequired(), Length(min=6, max=120)], render_kw={"placeholder": "Epost"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Passord"})
    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError('That username is already taken. Please choose a different one.')

    def validate_email(self, email):
        existing_user_email = User.query.filter_by(email=email.data).first()
        if existing_user_email:
            raise ValidationError('That email already exists. Please choose a different one.')


class LoginForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Length(min=6, max=120)], render_kw={"placeholder": "Epost"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Passord"})
    submit = SubmitField('Login')

class ForgotPasswordForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Length(min=6, max=120)], render_kw={"placeholder": "Epost"})
    submit = SubmitField('Reset Password')

class TwoFactorForm(FlaskForm):
    code = StringField(validators=[InputRequired(), Length(min=6, max=6)], render_kw={"placeholder": "2FA Code"})
    submit = SubmitField('Verify')

class ResetPasswordForm(FlaskForm):
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Ny Passord"})
    confirm_password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Bekreft Passord"})
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

            # Send the 2FA code to the user's email
            msg = Message('Your 2FA Code', recipients=[user.email])
            msg.body = f'Your two-factor authentication code is: {two_factor_code}'
            mail.send(msg)

            # Temporarily store the user's ID in the session
            session['pre_2fa_user_id'] = user.id
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
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)



@app.route('/verify_2fa', methods=['GET', 'POST'])
def verify_2fa():
    form = TwoFactorForm()
    
    # Retrieve the user ID from the session
    user_id = session.get('pre_2fa_user_id')
    if not user_id:
        flash('Session expired or invalid access. Please log in again.', 'warning')
        return redirect(url_for('login'))

    user = User.query.get(user_id)
    if form.validate_on_submit():
        if int(form.code.data) == user.two_factor_code:
            user.two_factor_code = None
            db.session.commit()

            # Log the user in after successful 2FA
            login_user(user)
            session.pop('pre_2fa_user_id', None)  # Remove the temporary session variable
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid 2FA code. Please try again.', 'danger')

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

@app.route('/flappy_score', methods=['POST'])
@login_required
def flappy_score():
    data = request.get_json()
    score = data.get('score')

    if score is not None:
        # Check if user already has a high score
        existing_score = FlappyHighScore.query.filter_by(user_id=current_user.id).first()

        if existing_score:
            # Update existing score if new score is higher
            if score > existing_score.flappyScore:
                existing_score.flappyScore = score
        else:
            # Create new high score entry
            new_score = FlappyHighScore(user_id=current_user.id, flappyScore=score)
            db.session.add(new_score)

        db.session.commit()
        return jsonify({'success': True, 'message': 'Score saved successfully'})

    return jsonify({'success': False, 'message': 'Invalid score'}), 400

@app.route('/snake_score', methods=['POST'])
@login_required
def snake_score():
    data = request.get_json()
    score = data.get('score')

    if score is not None:
        # Check if user already has a high score
        existing_score = SnakeHighScore.query.filter_by(user_id=current_user.id).first()

        if existing_score:
            # Update existing score if new score is higher
            if score > existing_score.snakeScore:
                existing_score.snakeScore = score
        else:
            # Create new high score entry
            new_score = SnakeHighScore(user_id=current_user.id, snakeScore=score)
            db.session.add(new_score)

        db.session.commit()
        return jsonify({'success': True, 'message': 'Score saved successfully'})

    return jsonify({'success': False, 'message': 'Invalid score'}), 400



@app.route('/faq')
def faq():
    return render_template('faq.html')

@app.route('/spill')
@login_required
def spill():
    return render_template('spill.html')

@app.route('/snake')
@login_required
def snake():
    return render_template('snake.html')

@app.route('/flappy')
@login_required
def flappy():
    return render_template('flappy.html')

@app.route('/leaderboard', methods=['GET'])
@login_required
def leaderboard():
    scores = HighScore.query.order_by(HighScore.score.desc()).all()
    return render_template('leaderboard.html', scores=scores)

@app.route('/flappyboard', methods=['GET'])
@login_required
def flappyboard():
    scores = FlappyHighScore.query.order_by(FlappyHighScore.flappyScore.desc()).all()
    return render_template('flappyboard.html', scores=scores)

@app.route('/snakeboard', methods=['GET'])
@login_required
def snakeboard():
    scores = SnakeHighScore.query.order_by(SnakeHighScore.snakeScore.desc()).all()
    return render_template('snakeboard.html', scores = scores)


    

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)