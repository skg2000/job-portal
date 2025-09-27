# Job Portal Web Application

## Features
- User roles: Job Seeker, Employer, Admin
- Register / Login (Flask-Login)
- Post jobs (Employer)
- Search jobs with filters (query + location)
- Apply for jobs (Job Seeker)
- SQLite Database with SQLAlchemy ORM
- Admin panel for users & jobs

## Setup
```bash
python -m venv venv
source venv/bin/activate   # or venv\Scripts\activate
pip install -r requirements.txt
python init_db.py
python run.py
```
Open http://127.0.0.1:5000
