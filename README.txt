
SentinelRE Flask Production Starter

What this is
- A production-ready starter architecture for SentinelRE in Flask
- Includes login, CRM, assessment workflow, SQLite database, and branded PDF reporting
- Faster and more scalable than the Streamlit versions

Default users
- admin / Admin123!
- advisor / Advisor123!

How to run locally
1. Create a virtual environment
2. Install dependencies:
   pip install -r requirements.txt
3. Start:
   flask --app app run

Initialize database manually if needed
- flask --app app init-db

Production start example
- gunicorn -w 2 -b 0.0.0.0:8000 wsgi:app

Important production notes
- Change SECRET_KEY immediately
- Change default passwords immediately
- Use a managed database for larger deployments
- Put the app behind Nginx or another reverse proxy
- Add CSRF protection, password reset flow, and audit logging before public launch
