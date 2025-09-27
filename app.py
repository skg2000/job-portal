from flask import Flask, render_template, redirect, url_for, flash, request, Markup
from config import Config
from models.models import db, User, Job, Application
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, SubmitField, SelectField
from wtforms.validators import DataRequired, Email, Length
from sqlalchemy import or_

def create_app():
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(Config)
    db.init_app(app)

    login_manager = LoginManager()
    login_manager.login_view = 'login'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # Jinja filter to convert newlines to <br>
    @app.template_filter('nl2br')
    def nl2br(s):
        if s is None:
            return ''
        return Markup(s.replace('\n', '<br>'))

    # Forms
    class RegisterForm(FlaskForm):
        username = StringField('Username', validators=[DataRequired(), Length(3,80)])
        email = StringField('Email', validators=[DataRequired(), Email()])
        password = PasswordField('Password', validators=[DataRequired(), Length(6,128)])
        role = SelectField('Role', choices=[('jobseeker','Job Seeker'),('employer','Employer')])
        submit = SubmitField('Register')

    class LoginForm(FlaskForm):
        email = StringField('Email', validators=[DataRequired(), Email()])
        password = PasswordField('Password', validators=[DataRequired()])
        submit = SubmitField('Login')

    class JobForm(FlaskForm):
        title = StringField('Job Title', validators=[DataRequired()])
        company = StringField('Company', validators=[DataRequired()])
        location = StringField('Location', validators=[DataRequired()])
        category = StringField('Category')
        salary = StringField('Salary')
        description = TextAreaField('Description', validators=[DataRequired()])
        submit = SubmitField('Post Job')

    class ApplyForm(FlaskForm):
        message = TextAreaField('Message', validators=[DataRequired()])
        resume_url = StringField('Resume URL (optional)')
        submit = SubmitField('Apply')

    # Routes
    @app.route('/')
    def index():
        q = request.args.get('q','').strip()
        location = request.args.get('location','').strip()
        jobs_query = Job.query
        if q:
            jobs_query = jobs_query.filter(or_(Job.title.ilike(f'%%{q}%%'),
                                              Job.description.ilike(f'%%{q}%%'),
                                              Job.company.ilike(f'%%{q}%%')))
        if location:
            jobs_query = jobs_query.filter(Job.location.ilike(f'%%{location}%%'))
        jobs = jobs_query.order_by(Job.created_at.desc()).all()
        return render_template('index.html', jobs=jobs)

    @app.route('/register', methods=['GET','POST'])
    def register():
        if current_user.is_authenticated:
            return redirect(url_for('index'))
        form = RegisterForm()
        if form.validate_on_submit():
            existing = User.query.filter((User.email==form.email.data)|(User.username==form.username.data)).first()
            if existing:
                flash('User with that email/username already exists','danger')
                return redirect(url_for('register'))
            hashed = generate_password_hash(form.password.data)
            user = User(username=form.username.data, email=form.email.data, password=hashed, role=form.role.data)
            db.session.add(user)
            db.session.commit()
            flash('Registered successfully. Please log in.','success')
            return redirect(url_for('login'))
        return render_template('register.html', form=form)

    @app.route('/login', methods=['GET','POST'])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for('index'))
        form = LoginForm()
        if form.validate_on_submit():
            user = User.query.filter_by(email=form.email.data).first()
            if user and check_password_hash(user.password, form.password.data):
                login_user(user)
                flash('Logged in successfully','success')
                next_page = request.args.get('next')
                return redirect(next_page or url_for('index'))
            flash('Invalid credentials','danger')
        return render_template('login.html', form=form)

    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        flash('Logged out','info')
        return redirect(url_for('index'))

    @app.route('/dashboard')
    @login_required
    def dashboard():
        if current_user.role == 'employer':
            # Employer: show jobs they posted
            jobs = Job.query.filter_by(employer_id=current_user.id).order_by(Job.created_at.desc()).all()
            return render_template('dashboard.html', jobs=jobs)

        elif current_user.role == 'jobseeker':
            # Job Seeker: show applications + related jobs
            applications = Application.query.filter_by(user_id=current_user.id).order_by(Application.created_at.desc()).all()
            return render_template('dashboard.html', applications=applications)

        else:
            # Admin: show everything
            jobs = Job.query.order_by(Job.created_at.desc()).all()
            users = User.query.order_by(User.created_at.desc()).all()
            applications = Application.query.order_by(Application.created_at.desc()).all()
            return render_template('admin.html', jobs=jobs, users=users, applications=applications)


    @app.route('/post-job', methods=['GET','POST'])
    @login_required
    def post_job():
        if current_user.role != 'employer':
            flash('Only employers can post jobs','warning')
            return redirect(url_for('index'))
        form = JobForm()
        if form.validate_on_submit():
            job = Job(
                title=form.title.data,
                company=form.company.data,
                location=form.location.data,
                category=form.category.data,
                salary=form.salary.data,
                description=form.description.data,
                employer_id=current_user.id
            )
            db.session.add(job)
            db.session.commit()
            flash('Job posted','success')
            return redirect(url_for('dashboard'))
        return render_template('post_job.html', form=form)

    @app.route('/jobs')
    def jobs_list():
        jobs = Job.query.order_by(Job.created_at.desc()).all()
        return render_template('jobs.html', jobs=jobs)

    @app.route('/job/<int:job_id>', methods=['GET','POST'])
    def job_detail(job_id):
        job = Job.query.get_or_404(job_id)
        form = ApplyForm()
        if form.validate_on_submit():
            if not current_user.is_authenticated or current_user.role != 'jobseeker':
                flash('You must be logged in as a job seeker to apply','warning')
                return redirect(url_for('login'))
            existing = Application.query.filter_by(job_id=job.id, user_id=current_user.id).first()
            if existing:
                flash('You already applied for this job','info')
                return redirect(url_for('job_detail', job_id=job.id))
            appn = Application(message=form.message.data, resume_url=form.resume_url.data, job_id=job.id, user_id=current_user.id)
            db.session.add(appn)
            db.session.commit()
            flash('Application submitted','success')
            return redirect(url_for('dashboard'))
        return render_template('job_detail.html', job=job, form=form)

    @app.route('/delete-job/<int:job_id>', methods=['POST'])
    @login_required
    def delete_job(job_id):
        job = Job.query.get_or_404(job_id)
        if current_user.role == 'admin' or (current_user.role == 'employer' and job.employer_id == current_user.id):
            db.session.delete(job)
            db.session.commit()
            flash('Job deleted','success')
        else:
            flash('Not authorized','danger')
        return redirect(url_for('dashboard'))

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)
