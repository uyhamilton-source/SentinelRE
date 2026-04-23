
import io, json, os
from datetime import datetime, date
from pathlib import Path
from flask import Flask, render_template, request, redirect, url_for, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
    REPORTLAB_AVAILABLE = True
except Exception:
    REPORTLAB_AVAILABLE = False

BASE_DIR = Path(__file__).resolve().parent
app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "change-this-in-production")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR / 'sentinelre.db'}")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

BRAND = {"company":"Sentinel Risk Compliance Group","product":"SentinelRE™","tagline":"Where Risk Becomes Strategy"}
QUESTIONS = [
    ("email_protection","Transaction Protection","How well are transaction emails and wiring instructions protected?"),
    ("mfa","Access Security","How consistently is multi-factor authentication used?"),
    ("client_data","Data Protection","How securely is client information stored and shared?"),
    ("vendor_risk","Third-Party Risk","How well are title companies, lenders, and vendors managed from a security standpoint?"),
    ("incident_plan","Response Readiness","How prepared is the firm to respond if a transaction is compromised or client data is exposed?"),
    ("backup_recovery","Recovery","How strong are backup and recovery practices for important documents and systems?"),
]
SCORE_MAP = {"Strong":1,"Moderate":2,"Limited":3,"Unknown":3}
FRAMEWORK_MAP = {
    "Transaction Protection":"NIST Protect / Florida data protection",
    "Access Security":"NIST Protect",
    "Data Protection":"NIST Protect / FIPA considerations",
    "Third-Party Risk":"NIST Identify / Govern",
    "Response Readiness":"NIST Respond / FIPA response",
    "Recovery":"NIST Recover",
}

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), nullable=False, default="Advisor")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    def set_password(self, password): self.password_hash = generate_password_hash(password)
    def check_password(self, password): return check_password_hash(self.password_hash, password)

class Lead(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_name = db.Column(db.String(255), nullable=False)
    contact_name = db.Column(db.String(255))
    email = db.Column(db.String(255))
    stage = db.Column(db.String(100), default="Lead")
    estimated_value = db.Column(db.Float, default=0.0)
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Assessment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_name = db.Column(db.String(255), nullable=False)
    business_type = db.Column(db.String(255), nullable=False)
    advisor = db.Column(db.String(255), nullable=False)
    annual_transactions = db.Column(db.Integer, default=0)
    avg_transaction_value = db.Column(db.Float, default=0.0)
    revenue_per_day = db.Column(db.Float, default=0.0)
    downtime_days = db.Column(db.Integer, default=1)
    overall_level = db.Column(db.String(50), nullable=False)
    overall_score = db.Column(db.Float, nullable=False)
    exposure = db.Column(db.Float, default=0.0)
    downtime_loss = db.Column(db.Float, default=0.0)
    findings_json = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id): return db.session.get(User, int(user_id))

@app.context_processor
def inject_brand(): return {"BRAND": BRAND}

def build_findings(form_data):
    findings = []
    for key, category, question in QUESTIONS:
        response = form_data.get(key, "Unknown")
        score = SCORE_MAP.get(response, 3)
        findings.append({
            "category": category,
            "question": question,
            "response": response,
            "risk_score": score,
            "risk_level": "Low" if score == 1 else "Moderate" if score == 2 else "High",
            "framework_alignment": FRAMEWORK_MAP[category],
        })
    return findings

def overall_from_findings(findings):
    score = sum(x["risk_score"] for x in findings) / max(len(findings), 1)
    if score >= 2.4: return "High", score
    if score >= 1.8: return "Moderate", score
    return "Low", score

def exposure_from_value(avg_transaction_value, level):
    return avg_transaction_value * {"Low":0.05,"Moderate":0.15,"High":0.30}[level] if avg_transaction_value > 0 else 0.0

def action_plan(level):
    if level == "High":
        return ["Enable MFA across email and document systems.","Review wiring verification procedures.","Restrict access to sensitive client and transaction data.","Review vendor access and remove anything unnecessary.","Document an incident response process."]
    if level == "Moderate":
        return ["Confirm MFA usage for critical systems.","Review how client data is shared and stored.","Validate backups and incident response readiness."]
    return ["Maintain strong controls and review key access quarterly.","Test backups and update response procedures annually."]

def build_pdf(assessment):
    if not REPORTLAB_AVAILABLE: return None
    findings = json.loads(assessment.findings_json)
    logo_path = BASE_DIR / "static" / "img" / "srcg_logo.png"
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=36, bottomMargin=36, leftMargin=36, rightMargin=36)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("TitleStyle", parent=styles["Title"], textColor=colors.HexColor("#0B122B"), fontSize=18, leading=22)
    sub_style = ParagraphStyle("SubStyle", parent=styles["Normal"], textColor=colors.HexColor("#C99A2E"), fontSize=10, spaceAfter=8)
    head_style = ParagraphStyle("HeadStyle", parent=styles["Heading2"], textColor=colors.HexColor("#0B122B"), fontSize=13, spaceBefore=10)
    normal = styles["BodyText"]
    story = []
    if logo_path.exists(): story.append(Image(str(logo_path), width=60, height=60))
    story.append(Paragraph(BRAND["company"], title_style))
    story.append(Paragraph("SentinelRE™ Assessment Report", sub_style))
    story.append(Paragraph(f"Client: {assessment.client_name} | Date: {assessment.created_at.date().isoformat()}", normal))
    story.append(Spacer(1, 8))
    story.append(Paragraph("Executive Summary", head_style))
    story.append(Paragraph(f"Overall risk level: <b>{assessment.overall_level}</b>. Average score: <b>{assessment.overall_score:.2f}</b>. Estimated exposure per compromised transaction: <b>${assessment.exposure:,.0f}</b>. Estimated downtime loss: <b>${assessment.downtime_loss:,.0f}</b>.", normal))
    story.append(Spacer(1, 8))
    story.append(Paragraph("Key Findings", head_style))
    table_data = [["Category","Response","Risk Level"]]
    for row in findings: table_data.append([row["category"], row["response"], row["risk_level"]])
    table = Table(table_data, repeatRows=1, colWidths=[150,120,100])
    table.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#0B122B")),("TEXTCOLOR",(0,0),(-1,0),colors.white),("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,-1),8),("GRID",(0,0),(-1,-1),0.3,colors.HexColor("#D7D7E0")),("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white, colors.HexColor("#F7F5FB")])]))
    story.append(table)
    story.append(Spacer(1, 8))
    story.append(Paragraph("30–60 Day Action Plan", head_style))
    for idx, item in enumerate(action_plan(assessment.overall_level), start=1):
        story.append(Paragraph(f"{idx}. {item}", normal))
    story.append(Spacer(1, 8))
    story.append(Paragraph("Disclaimer", head_style))
    story.append(Paragraph("This assessment is a strategic business review based on provided information. It is not a technical audit, legal opinion, or certification of compliance.", normal))
    doc.build(story)
    buffer.seek(0)
    return buffer

@app.route("/")
def home():
    return redirect(url_for("dashboard")) if current_user.is_authenticated else redirect(url_for("login"))

@app.route("/login", methods=["GET","POST"])
def login():
    if current_user.is_authenticated: return redirect(url_for("dashboard"))
    if request.method == "POST":
        user = User.query.filter_by(username=request.form.get("username","").strip()).first()
        if user and user.check_password(request.form.get("password","")):
            login_user(user); flash("Signed in successfully.","success"); return redirect(url_for("dashboard"))
        flash("Invalid username or password.","danger")
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user(); flash("Signed out.","info"); return redirect(url_for("login"))

@app.route("/dashboard")
@login_required
def dashboard():
    leads = Lead.query.order_by(Lead.created_at.desc()).limit(100).all()
    assessments = Assessment.query.order_by(Assessment.created_at.desc()).limit(100).all()
    pipeline_value = sum((lead.estimated_value or 0) for lead in leads)
    return render_template("dashboard.html", leads=leads, assessments=assessments, pipeline_value=pipeline_value)

@app.route("/crm", methods=["GET","POST"])
@login_required
def crm():
    if request.method == "POST":
        lead = Lead(client_name=request.form.get("client_name","").strip(), contact_name=request.form.get("contact_name","").strip(), email=request.form.get("email","").strip(), stage=request.form.get("stage","Lead"), estimated_value=float(request.form.get("estimated_value",0) or 0), notes=request.form.get("notes","").strip())
        db.session.add(lead); db.session.commit(); flash("Lead saved.","success"); return redirect(url_for("crm"))
    leads = Lead.query.order_by(Lead.created_at.desc()).all()
    return render_template("crm.html", leads=leads)

@app.route("/assessment", methods=["GET","POST"])
@login_required
def assessment():
    if request.method == "POST":
        client_name = request.form.get("client_name","").strip() or "Unnamed Client"
        business_type = request.form.get("business_type","")
        annual_transactions = int(request.form.get("annual_transactions",0) or 0)
        avg_transaction_value = float(request.form.get("avg_transaction_value",0) or 0)
        revenue_per_day = float(request.form.get("revenue_per_day",0) or 0)
        downtime_days = int(request.form.get("downtime_days",1) or 1)
        findings = build_findings(request.form)
        overall_level, overall_score = overall_from_findings(findings)
        exposure = exposure_from_value(avg_transaction_value, overall_level)
        downtime_loss = revenue_per_day * downtime_days
        item = Assessment(client_name=client_name,business_type=business_type,advisor=current_user.username,annual_transactions=annual_transactions,avg_transaction_value=avg_transaction_value,revenue_per_day=revenue_per_day,downtime_days=downtime_days,overall_level=overall_level,overall_score=overall_score,exposure=exposure,downtime_loss=downtime_loss,findings_json=json.dumps(findings))
        db.session.add(item); db.session.commit(); flash("Assessment completed.","success"); return redirect(url_for("assessment_result", assessment_id=item.id))
    return render_template("assessment.html", questions=QUESTIONS)

@app.route("/assessment/<int:assessment_id>")
@login_required
def assessment_result(assessment_id):
    assessment = Assessment.query.get_or_404(assessment_id)
    findings = json.loads(assessment.findings_json)
    return render_template("assessment_result.html", assessment=assessment, findings=findings, actions=action_plan(assessment.overall_level))

@app.route("/assessment/<int:assessment_id>/pdf")
@login_required
def assessment_pdf(assessment_id):
    assessment = Assessment.query.get_or_404(assessment_id)
    pdf_buffer = build_pdf(assessment)
    if pdf_buffer is None:
        flash("PDF generation requires reportlab.","warning")
        return redirect(url_for("assessment_result", assessment_id=assessment.id))
    return send_file(pdf_buffer, as_attachment=True, download_name=f"SentinelRE_{assessment.client_name.replace(' ', '_')}.pdf", mimetype="application/pdf")

@app.cli.command("init-db")
def init_db_command():
    db.create_all()
    if not User.query.filter_by(username="admin").first():
        admin = User(username="admin", role="Administrator"); admin.set_password("Admin123!")
        advisor = User(username="advisor", role="Advisor"); advisor.set_password("Advisor123!")
        db.session.add_all([admin, advisor]); db.session.commit()
    print("Database initialized.")

def ensure_default_data():
    db.create_all()
    if not User.query.filter_by(username="admin").first():
        admin = User(username="admin", role="Administrator"); admin.set_password("Admin123!")
        advisor = User(username="advisor", role="Advisor"); advisor.set_password("Advisor123!")
        db.session.add_all([admin, advisor])
    if Lead.query.count() == 0:
        db.session.add_all([
            Lead(client_name="Palm Crest Realty", contact_name="Elena Morris", email="elena@palmcrestrealty.com", stage="Qualified", estimated_value=2500.0, notes="Interested in transaction protection review."),
            Lead(client_name="Harbor Point Commercial", contact_name="David Lin", email="dlin@harborpointcre.com", stage="Discovery Call", estimated_value=3500.0, notes="Concerned about vendor access and document exposure."),
        ])
    db.session.commit()

with app.app_context():
    ensure_default_data()

if __name__ == "__main__":
    app.run(debug=True)
