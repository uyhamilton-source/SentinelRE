
import io, json, sqlite3
from datetime import datetime, date
from pathlib import Path
import pandas as pd
import streamlit as st

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
    REPORTLAB_AVAILABLE = True
except Exception:
    REPORTLAB_AVAILABLE = False

APP_DIR = Path(__file__).resolve().parent
DB_PATH = APP_DIR / "sentinelre_demo.db"
LOGO_PATH = APP_DIR / "assets" / "srcg_logo.png"

BRAND = {"company":"Sentinel Risk Compliance Group","product":"SentinelRE™","primary":"#0B122B","gold":"#C99A2E","danger":"#D92D20","warning":"#F59E0B","success":"#16A34A"}
DEFAULT_USERS = [("admin","Admin123!","Administrator"),("advisor","Advisor123!","Advisor")]

QUESTIONS = [
    {"id":"email_protection","category":"Transaction Protection","question":"How well are transaction emails, wiring instructions, and closing communications protected?","simple":"This checks email fraud and fake wiring instruction risk."},
    {"id":"mfa","category":"Access Security","question":"How consistently is multi-factor authentication used on business accounts and systems?","simple":"This checks extra login protection."},
    {"id":"shared_accounts","category":"Access Security","question":"How well does the firm avoid shared logins and control who can access sensitive information?","simple":"This checks whether access is limited."},
    {"id":"client_data","category":"Data Protection","question":"How securely is buyer, seller, tenant, or investor information stored and shared?","simple":"This checks how client data is protected."},
    {"id":"vendor_risk","category":"Third-Party Risk","question":"How well are title companies, lenders, transaction coordinators, and vendors managed from a security standpoint?","simple":"This checks whether outside partners create risk."},
    {"id":"incident_plan","category":"Response Readiness","question":"How prepared is the firm to respond if a transaction is compromised or client data is exposed?","simple":"This checks if there is a plan for incidents."},
    {"id":"backup_recovery","category":"Recovery","question":"How strong are backup and recovery practices for important files, systems, and transaction records?","simple":"This checks whether the business can recover quickly."},
    {"id":"device_security","category":"Device Protection","question":"How well are laptops, mobile devices, and other business devices protected?","simple":"This checks device security for daily operations."}
]
SCORE_MAP = {"Strong":1,"Moderate":2,"Limited":3,"Unknown":3}
LEVEL_MAP = {1:"Low",2:"Moderate",3:"High"}
FRAMEWORK_MAP = {
    "Transaction Protection":["NIST CSF: Protect","Florida data protection readiness"],
    "Access Security":["NIST CSF: Protect"],
    "Data Protection":["NIST CSF: Protect","FIPA considerations"],
    "Third-Party Risk":["NIST CSF: Identify / Govern"],
    "Response Readiness":["NIST CSF: Respond","FIPA breach response considerations"],
    "Recovery":["NIST CSF: Recover"],
    "Device Protection":["NIST CSF: Protect"],
}

SAMPLE_LEADS = [
    ("Palm Crest Realty","Residential Brokerage","Elena Morris","elena@palmcrestrealty.com","954-555-1201","Qualified",2500.0,"advisor","Interested in transaction protection review."),
    ("Harbor Point Commercial","Commercial Real Estate","David Lin","dlin@harborpointcre.com","305-555-8891","Discovery Call",3500.0,"advisor","Concerned about vendor access and document exposure."),
    ("Summit Property Group","Property Management","Marsha Cole","mcole@summitpg.com","561-555-3321","Proposal Sent",3000.0,"advisor","Needs data protection and incident response clarity."),
]

SAMPLE_ASSESSMENTS = [
    {"client_name":"Palm Crest Realty","company_type":"Residential Brokerage","advisor":"advisor","state":"Florida","company_size":"11–25","annual_transactions":40,"avg_transaction_value":325000.0,"revenue_per_day":12000.0,"downtime_days":2,"overall_level":"Moderate","overall_score":2.00,"exposure":48750.0,"downtime_loss":24000.0,"recommended_tier":"SentinelRE™ Core","answers":{"email_protection":"Moderate","mfa":"Strong","shared_accounts":"Moderate","client_data":"Moderate","vendor_risk":"Moderate","incident_plan":"Limited","backup_recovery":"Strong","device_security":"Moderate"}},
    {"client_name":"Harbor Point Commercial","company_type":"Commercial Real Estate","advisor":"advisor","state":"Florida","company_size":"26–75","annual_transactions":90,"avg_transaction_value":850000.0,"revenue_per_day":35000.0,"downtime_days":3,"overall_level":"High","overall_score":2.63,"exposure":255000.0,"downtime_loss":105000.0,"recommended_tier":"SentinelRE™ Advance","answers":{"email_protection":"Limited","mfa":"Moderate","shared_accounts":"Limited","client_data":"Moderate","vendor_risk":"Limited","incident_plan":"Limited","backup_recovery":"Moderate","device_security":"Moderate"}},
    {"client_name":"Summit Property Group","company_type":"Property Management","advisor":"advisor","state":"Florida","company_size":"76–200","annual_transactions":150,"avg_transaction_value":450000.0,"revenue_per_day":28000.0,"downtime_days":4,"overall_level":"High","overall_score":2.50,"exposure":135000.0,"downtime_loss":112000.0,"recommended_tier":"SentinelRE™ Advance","answers":{"email_protection":"Moderate","mfa":"Moderate","shared_accounts":"Moderate","client_data":"Limited","vendor_risk":"Limited","incident_plan":"Limited","backup_recovery":"Moderate","device_security":"Limited"}}
]

def get_conn():
    return sqlite3.connect(DB_PATH, check_same_thread=False)

def findings_from_answers(client_name, company_type, answers, annual_transactions, avg_transaction_value):
    rows = []
    for q in QUESTIONS:
        response = answers.get(q["id"], "Unknown")
        score = SCORE_MAP.get(response, 3)
        rows.append({
            "Category": q["category"], "Question": q["question"], "Response": response,
            "Risk Score": score, "Risk Level": LEVEL_MAP[min(max(score,1),3)],
            "Framework Alignment": ", ".join(FRAMEWORK_MAP.get(q["category"], [])),
            "Org Name": client_name, "Industry": company_type,
            "Average Transaction Value": avg_transaction_value, "Annual Transactions": annual_transactions,
        })
    return rows

def init_db():
    conn = get_conn(); cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT NOT NULL, role TEXT NOT NULL, created_at TEXT NOT NULL)")
    cur.execute("CREATE TABLE IF NOT EXISTS crm_leads (id INTEGER PRIMARY KEY AUTOINCREMENT, client_name TEXT, company_type TEXT, contact_name TEXT, email TEXT, phone TEXT, stage TEXT, estimated_value REAL, owner TEXT, notes TEXT, created_at TEXT, updated_at TEXT)")
    cur.execute("CREATE TABLE IF NOT EXISTS assessments (id INTEGER PRIMARY KEY AUTOINCREMENT, client_name TEXT, company_type TEXT, advisor TEXT, state TEXT, company_size TEXT, annual_transactions INTEGER, avg_transaction_value REAL, revenue_per_day REAL, downtime_days REAL, overall_level TEXT, overall_score REAL, exposure REAL, downtime_loss REAL, recommended_tier TEXT, answers_json TEXT, findings_json TEXT, created_at TEXT)")
    cur.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        now = datetime.now().isoformat()
        cur.executemany("INSERT INTO users (username, password, role, created_at) VALUES (?, ?, ?, ?)", [(u,p,r,now) for u,p,r in DEFAULT_USERS])
    cur.execute("SELECT COUNT(*) FROM crm_leads")
    if cur.fetchone()[0] == 0:
        now = datetime.now().isoformat()
        cur.executemany("INSERT INTO crm_leads (client_name, company_type, contact_name, email, phone, stage, estimated_value, owner, notes, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", [(a,b,c,d,e,f,g,h,i,now,now) for a,b,c,d,e,f,g,h,i in SAMPLE_LEADS])
    cur.execute("SELECT COUNT(*) FROM assessments")
    if cur.fetchone()[0] == 0:
        now = datetime.now().isoformat()
        for item in SAMPLE_ASSESSMENTS:
            findings = findings_from_answers(item["client_name"], item["company_type"], item["answers"], item["annual_transactions"], item["avg_transaction_value"])
            cur.execute("INSERT INTO assessments (client_name, company_type, advisor, state, company_size, annual_transactions, avg_transaction_value, revenue_per_day, downtime_days, overall_level, overall_score, exposure, downtime_loss, recommended_tier, answers_json, findings_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (item["client_name"], item["company_type"], item["advisor"], item["state"], item["company_size"], item["annual_transactions"], item["avg_transaction_value"], item["revenue_per_day"], item["downtime_days"], item["overall_level"], item["overall_score"], item["exposure"], item["downtime_loss"], item["recommended_tier"], json.dumps(item["answers"]), json.dumps(findings), now))
    conn.commit(); conn.close()

def verify_user(username, password):
    conn = get_conn(); cur = conn.cursor()
    cur.execute("SELECT username, role FROM users WHERE username=? AND password=?", (username, password))
    row = cur.fetchone(); conn.close(); return row

def fetch_users():
    conn = get_conn(); df = pd.read_sql_query("SELECT username, role, created_at FROM users ORDER BY username", conn); conn.close(); return df
def add_user(username, password, role):
    conn = get_conn(); cur = conn.cursor()
    cur.execute("INSERT INTO users (username, password, role, created_at) VALUES (?, ?, ?, ?)", (username, password, role, datetime.now().isoformat()))
    conn.commit(); conn.close()
def fetch_leads():
    conn = get_conn(); df = pd.read_sql_query("SELECT * FROM crm_leads ORDER BY updated_at DESC, created_at DESC", conn); conn.close(); return df
def add_lead(client_name, company_type, contact_name, email, phone, stage, estimated_value, owner, notes):
    now = datetime.now().isoformat(); conn = get_conn(); cur = conn.cursor()
    cur.execute("INSERT INTO crm_leads (client_name, company_type, contact_name, email, phone, stage, estimated_value, owner, notes, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (client_name, company_type, contact_name, email, phone, stage, estimated_value, owner, notes, now, now))
    conn.commit(); conn.close()
def fetch_assessments():
    conn = get_conn()
    df = pd.read_sql_query("SELECT id, client_name, company_type, advisor, overall_level, overall_score, exposure, downtime_loss, recommended_tier, created_at FROM assessments ORDER BY created_at DESC", conn)
    conn.close(); return df

def risk_color(level):
    return {"Low":BRAND["success"],"Moderate":BRAND["warning"],"High":BRAND["danger"]}.get(level, BRAND["warning"])
def overall_from_df(df):
    score = float(df["Risk Score"].mean())
    if score >= 2.4: return "High", score
    if score >= 1.8: return "Moderate", score
    return "Low", score
def recommend_tier(score):
    if score >= 2.4: return "SentinelRE™ Advance"
    if score >= 1.8: return "SentinelRE™ Core"
    return "SentinelRE™ Advisory"
def estimated_exposure(avg_transaction_value, level):
    if avg_transaction_value <= 0: return 0.0
    return avg_transaction_value * {"Low":0.05,"Moderate":0.15,"High":0.30}[level]
def estimated_downtime_loss(revenue_per_day, downtime_days):
    return max(revenue_per_day,0) * max(downtime_days,0)
def generate_action_plan(level):
    if level == "High":
        return ["Weeks 1–2: Tighten MFA across email and file storage.","Weeks 1–2: Review wiring verification procedures.","Weeks 3–4: Restrict access to sensitive transaction data.","Weeks 3–4: Review vendor and partner access.","Month 2: Document incident response for transaction fraud or data exposure."]
    if level == "Moderate":
        return ["Weeks 1–2: Confirm MFA usage for critical systems.","Weeks 3–4: Review data sharing practices.","Month 2: Improve incident response and backup validation."]
    return ["Maintain strong controls and review transaction communication regularly.","Review vendor access quarterly.","Test response and recovery at least annually."]
def build_summary_df(org_name, vertical, answers, annual_transactions, avg_transaction_value):
    return pd.DataFrame(findings_from_answers(org_name, vertical, answers, annual_transactions, avg_transaction_value))

def inject_css():
    st.markdown("""
    <style>
    .stApp {background: linear-gradient(180deg, #ffffff 0%, #f8f7fb 100%);}
    .metric-box {background:white;border:1px solid #ebe8f2;border-radius:16px;padding:1rem;text-align:center;box-shadow:0 8px 22px rgba(11,18,43,0.05);}
    .section-box {background:white;border:1px solid #ebe8f2;border-radius:16px;padding:1rem 1.1rem;box-shadow:0 8px 22px rgba(11,18,43,0.05);}
    .small-note {color:#616161;font-size:0.9rem;}
    </style>
    """, unsafe_allow_html=True)

def render_brand_header():
    cols = st.columns([1,5])
    with cols[0]:
        if LOGO_PATH.exists():
            st.image(str(LOGO_PATH), width=110)
    with cols[1]:
        st.markdown(f"""
        <div style="background: linear-gradient(135deg, {BRAND['primary']} 0%, #171f45 100%); border-radius:18px; padding:1.2rem 1.4rem; color:white; border:1px solid rgba(201,154,46,0.25); box-shadow:0 10px 30px rgba(11,18,43,0.15);">
        <div style="font-size:2rem; font-weight:700;">{BRAND['product']} | Enterprise Real Estate Platform</div>
        <div style="color:#ebeaf5; margin-top:0.25rem;">Protect transactions, strengthen client data security, manage leads, and generate branded reports.</div>
        </div>
        """, unsafe_allow_html=True)

def pdf_report_bytes(client_name, advisor, summary_df, overall_level, overall_score, exposure, downtime_loss, actions):
    if not REPORTLAB_AVAILABLE: return None
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=36, bottomMargin=36, leftMargin=36, rightMargin=36)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("TitleStyle", parent=styles["Title"], textColor=colors.HexColor(BRAND["primary"]), fontSize=18, leading=22)
    sub_style = ParagraphStyle("SubStyle", parent=styles["Normal"], textColor=colors.HexColor(BRAND["gold"]), fontSize=10, spaceAfter=8)
    head_style = ParagraphStyle("HeadStyle", parent=styles["Heading2"], textColor=colors.HexColor(BRAND["primary"]), fontSize=13, spaceBefore=10)
    normal = styles["BodyText"]
    story = []
    if LOGO_PATH.exists(): story.append(Image(str(LOGO_PATH), width=70, height=70))
    story.append(Paragraph(BRAND["company"], title_style))
    story.append(Paragraph("SentinelRE™ Branded Assessment Report", sub_style))
    story.append(Paragraph(f"Client: {client_name} | Advisor: {advisor} | Date: {date.today().isoformat()}", normal))
    story.append(Spacer(1, 10))
    story.append(Paragraph("Executive Summary", head_style))
    story.append(Paragraph(f"This report provides a business-focused review of transaction risk, client data protection, third-party exposure, and response readiness. The current overall risk level is <b>{overall_level}</b> with an average risk score of <b>{overall_score:.2f}</b>.", normal))
    story.append(Paragraph(f"Estimated exposure per compromised transaction: <b>${exposure:,.0f}</b>. Estimated downtime loss based on provided assumptions: <b>${downtime_loss:,.0f}</b>.", normal))
    story.append(Spacer(1, 10))
    story.append(Paragraph("Assessment Findings", head_style))
    table_data = [["Category","Response","Risk Level","Framework Alignment"]]
    for _, row in summary_df.iterrows():
        table_data.append([row["Category"], row["Response"], row["Risk Level"], row["Framework Alignment"]])
    table = Table(table_data, repeatRows=1, colWidths=[95,70,60,220])
    table.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor(BRAND["primary"])),("TEXTCOLOR",(0,0),(-1,0),colors.white),("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,-1),8),("GRID",(0,0),(-1,-1),0.3,colors.HexColor("#D7D7E0")),("VALIGN",(0,0),(-1,-1),"TOP"),("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white, colors.HexColor("#F7F5FB")])]))
    story.append(table); story.append(Spacer(1,10))
    story.append(Paragraph("30–60 Day Action Plan", head_style))
    for idx, item in enumerate(actions, start=1):
        story.append(Paragraph(f"{idx}. {item}", normal))
    story.append(Spacer(1,10))
    story.append(Paragraph("Disclaimer", head_style))
    story.append(Paragraph("This assessment is a strategic business review based on provided information. It is not a technical audit, legal opinion, or certification of compliance.", normal))
    doc.build(story); buffer.seek(0); return buffer.getvalue()

def login_view():
    st.title("Secure Sign In")
    st.caption("Use the default credentials from the README.")
    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Sign In")
    if submitted:
        user = verify_user(username, password)
        if user:
            st.session_state["auth"] = True
            st.session_state["username"] = user[0]
            st.session_state["role"] = user[1]
            st.rerun()
        else:
            st.error("Invalid username or password.")

def logout():
    for key in ["auth","username","role","latest_assessment"]:
        if key in st.session_state: del st.session_state[key]
    st.rerun()

def assessment_view():
    st.subheader("Real Estate Risk Assessment")
    a,b,c = st.columns(3)
    with a:
        client_name = st.text_input("Firm name")
        state = st.selectbox("Primary state", ["Florida","Other"], index=0)
    with b:
        company_size = st.selectbox("Firm size", ["1–10","11–25","26–75","76–200","200+"], index=1)
        annual_transactions = st.number_input("Approx. annual transactions", min_value=0, value=50)
    with c:
        avg_transaction_value = st.number_input("Average transaction value ($)", min_value=0.0, value=350000.0, step=10000.0)
        revenue_per_day = st.number_input("Estimated revenue per day ($)", min_value=0.0, value=15000.0, step=1000.0)
    vertical = st.selectbox("Business type", ["Residential Brokerage","Commercial Real Estate","Property Management","Title / Closing Support","Mixed Real Estate Operations"])
    answers = {}
    st.markdown("#### Business Risk Review")
    for q in QUESTIONS:
        with st.container(border=True):
            st.markdown(f"**{q['category']}**")
            st.write(q["question"]); st.caption(q["simple"])
            answers[q["id"]] = st.radio("Current state", ["Strong","Moderate","Limited","Unknown"], horizontal=True, key=q["id"])
    downtime_days = st.slider("If a serious issue disrupted operations, how many days of downtime would be most concerning?", 1, 10, 3)
    if st.button("Run Assessment", type="primary"):
        df = build_summary_df(client_name, vertical, answers, annual_transactions, avg_transaction_value)
        overall_level, overall_score = overall_from_df(df)
        exposure = estimated_exposure(avg_transaction_value, overall_level)
        downtime_loss = estimated_downtime_loss(revenue_per_day, downtime_days)
        recommended_tier = recommend_tier(overall_score)
        actions = generate_action_plan(overall_level)
        findings = df[["Category","Response","Risk Level","Framework Alignment"]].to_dict("records")
        payload = {"client_name":client_name,"company_type":vertical,"advisor":st.session_state.get("username","advisor"),"state":state,"company_size":company_size,"annual_transactions":annual_transactions,"avg_transaction_value":avg_transaction_value,"revenue_per_day":revenue_per_day,"downtime_days":downtime_days,"overall_level":overall_level,"overall_score":overall_score,"exposure":exposure,"downtime_loss":downtime_loss,"recommended_tier":recommended_tier,"answers":answers,"findings":findings}
        save_assessment(payload); st.session_state["latest_assessment"] = payload; st.success("Assessment completed and saved.")

def latest_results_view():
    st.subheader("Latest Assessment Results")
    payload = st.session_state.get("latest_assessment")
    if not payload:
        st.info("Run an assessment first, or use the demo data in Admin Dashboard and CRM.")
        return
    c1,c2,c3,c4 = st.columns(4)
    metrics = [("Overall Risk",payload["overall_level"]),("Average Score",f'{payload["overall_score"]:.2f}'),("Exposure / Transaction",f'${payload["exposure"]:,.0f}'),("Estimated Downtime Loss",f'${payload["downtime_loss"]:,.0f}')]
    for col,(label,val) in zip([c1,c2,c3,c4], metrics):
        with col:
            st.markdown(f'<div class="metric-box"><div class="small-note">{label}</div><div style="font-size:1.35rem;font-weight:700;color:{risk_color(payload["overall_level"])}">{val}</div></div>', unsafe_allow_html=True)
    st.markdown("#### Recommended Engagement")
    st.markdown(f'<div class="section-box"><strong>{payload["recommended_tier"]}</strong><br><span class="small-note">Recommended based on the current business risk profile.</span></div>', unsafe_allow_html=True)
    df = pd.DataFrame(payload["findings"]); st.dataframe(df, use_container_width=True, hide_index=True)
    st.markdown("#### 30–60 Day Action Plan")
    for i, action in enumerate(generate_action_plan(payload["overall_level"]), start=1):
        st.write(f"{i}. {action}")
    report_data = pdf_report_bytes(payload["client_name"], payload["advisor"], df, payload["overall_level"], payload["overall_score"], payload["exposure"], payload["downtime_loss"], generate_action_plan(payload["overall_level"]))
    if report_data:
        st.download_button("Download Branded PDF Report", data=report_data, file_name="SentinelRE_Report.pdf", mime="application/pdf")

def crm_view():
    st.subheader("CRM Tracking")
    with st.expander("Add New Lead"):
        with st.form("lead_form"):
            a,b = st.columns(2)
            with a:
                client_name = st.text_input("Company / Lead Name")
                company_type = st.selectbox("Type", ["Residential Brokerage","Commercial Real Estate","Property Management","Title / Closing Support","Mixed Real Estate Operations"])
                contact_name = st.text_input("Contact Name")
                email = st.text_input("Email")
            with b:
                phone = st.text_input("Phone")
                stage = st.selectbox("Stage", ["Lead","Qualified","Discovery Call","Proposal Sent","Assessment","Advisory"])
                estimated_value = st.number_input("Estimated Value ($)", min_value=0.0, value=2500.0, step=500.0)
                notes = st.text_area("Notes")
            submitted = st.form_submit_button("Save Lead")
            if submitted:
                add_lead(client_name, company_type, contact_name, email, phone, stage, estimated_value, st.session_state.get("username","advisor"), notes)
                st.success("Lead saved."); st.rerun()
    leads = fetch_leads()
    if leads.empty: st.info("No leads yet.")
    else: st.dataframe(leads, use_container_width=True, hide_index=True)

def admin_dashboard():
    st.subheader("Multi-User Admin Dashboard")
    leads = fetch_leads(); assessments = fetch_assessments(); users = fetch_users()
    a1,a2,a3,a4 = st.columns(4)
    pipeline_value = 0.0 if leads.empty else float(leads["estimated_value"].fillna(0).sum())
    cards = [("Users",len(users),BRAND["primary"]),("Leads",len(leads),BRAND["primary"]),("Assessments",len(assessments),BRAND["primary"]),("Pipeline Value",f'${pipeline_value:,.0f}',BRAND["gold"])]
    for col,(label,val,color) in zip([a1,a2,a3,a4], cards):
        with col:
            st.markdown(f'<div class="metric-box"><div class="small-note">{label}</div><div style="font-size:1.35rem;font-weight:700;color:{color}">{val}</div></div>', unsafe_allow_html=True)
    st.markdown("#### User Management"); st.dataframe(users, use_container_width=True, hide_index=True)
    with st.expander("Add New User"):
        with st.form("user_form"):
            username = st.text_input("Username")
            password = st.text_input("Temporary password", type="password")
            role = st.selectbox("Role", ["Advisor","Administrator"])
            submitted = st.form_submit_button("Create User")
            if submitted:
                try:
                    add_user(username, password, role); st.success("User created."); st.rerun()
                except Exception as e:
                    st.error(f"Could not create user: {e}")
    st.markdown("#### Assessment History")
    if assessments.empty: st.info("No assessments yet.")
    else:
        st.dataframe(assessments, use_container_width=True, hide_index=True)
        csv_data = assessments.to_csv(index=False).encode("utf-8")
        st.download_button("Download Assessment History CSV", data=csv_data, file_name="assessment_history.csv", mime="text/csv")

st.set_page_config(page_title="SentinelRE Enterprise Demo", page_icon="🏡", layout="wide")
init_db(); inject_css()
if "auth" not in st.session_state: st.session_state["auth"] = False
render_brand_header()
if not st.session_state["auth"]:
    login_view()
else:
    topbar = st.columns([4,1])
    with topbar[0]:
        st.caption(f"Signed in as **{st.session_state.get('username')}** | Role: **{st.session_state.get('role')}**")
    with topbar[1]:
        if st.button("Sign Out"): logout()
    menu = ["Assessment","Latest Results","CRM"]
    if st.session_state.get("role") == "Administrator": menu.append("Admin Dashboard")
    selected = st.sidebar.radio("Navigation", menu)
    st.sidebar.markdown("### Demo Status")
    st.sidebar.write("Sample leads loaded")
    st.sidebar.write("Sample assessments loaded")
    st.sidebar.write("Ready for client demos")
    if selected == "Assessment": assessment_view()
    elif selected == "Latest Results": latest_results_view()
    elif selected == "CRM": crm_view()
    elif selected == "Admin Dashboard": admin_dashboard()
