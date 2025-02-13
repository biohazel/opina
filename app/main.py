import os
import re
import requests
import stripe

from fastapi import FastAPI, Request, Form, HTTPException, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.responses import PlainTextResponse

# SQLAlchemy
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.orm import sessionmaker, declarative_base
from datetime import datetime

# Passlib p/ bcrypt
from passlib.hash import bcrypt

# Authlib p/ Google OAuth
from authlib.integrations.starlette_client import OAuth
from starlette.config import Config

########################
# FASTAPI e STATIC
########################

app = FastAPI()
app.mount("/static", StaticFiles(directory="app/static"), name="static")

########################
# ENV Vars
########################

WHATSAPP_VERIFY_TOKEN = os.getenv("WHATSAPP_VERIFY_TOKEN", "")
ACCESS_TOKEN = os.getenv("WHATSAPP_ACCESS_TOKEN", "")
PHONE_NUMBER_ID = os.getenv("PHONE_NUMBER_ID", "")

STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")
DOMAIN_URL = os.getenv("DOMAIN_URL", "http://localhost:8000")

DATABASE_URL = os.getenv("DATABASE_URL", "")

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")

stripe.api_key = STRIPE_SECRET_KEY

########################
# DB Setup
########################

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL not set")

engine = create_engine(DATABASE_URL, echo=False)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class TempIdCounter(Base):
    __tablename__ = "temp_id_counter"
    id = Column(Integer, primary_key=True, index=True)   # fixo = 1
    current_value = Column(Integer, default=0)

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)

    # Inteiro que mapeia p/ metadata do Stripe
    temp_id = Column(Integer, unique=True, index=True, nullable=True)

    full_name = Column(String)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    doc_number = Column(String)

    cep = Column(String)
    rua = Column(String)
    numero = Column(String)
    complemento = Column(String)
    bairro = Column(String)
    cidade = Column(String)
    estado = Column(String)
    pais = Column(String)

    whatsapp_phone = Column(String)
    plan = Column(String, default="free")
    created_at = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)

# garante que exista 1 registro no temp_id_counter
db_init = SessionLocal()
ctr = db_init.query(TempIdCounter).first()
if not ctr:
    db_init.add(TempIdCounter(id=1, current_value=0))
    db_init.commit()
db_init.close()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

########################
# Função p/ gerar temp_id
########################

def get_and_increment_temp_id(db):
    row = db.query(TempIdCounter).filter(TempIdCounter.id==1).first()
    row.current_value += 1
    db.commit()
    return row.current_value

########################
# Helper p/ renderizar HTML
########################

def render_page(file_name: str, context: dict=None):
    path = os.path.join("app", "templates", file_name)
    with open(path, "r", encoding="utf-8") as f:
        html = f.read()
    if context:
        for k,v in context.items():
            html = html.replace(f"{{{{{k}}}}}", v)
    return HTMLResponse(html)

########################
# GOOGLE OAUTH
########################

config = Config(environ={
    "GOOGLE_CLIENT_ID": GOOGLE_CLIENT_ID,
    "GOOGLE_CLIENT_SECRET": GOOGLE_CLIENT_SECRET
})
oauth = OAuth(config)
oauth.register(
    name="google",
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)

@app.get("/login/google")
async def login_google(request: Request):
    redirect_uri = f"{DOMAIN_URL}/auth/google/callback"
    return await oauth.google.authorize_redirect(request, redirect_uri)

@app.get("/auth/google/callback")
async def google_callback(request: Request):
    token = await oauth.google.authorize_access_token(request)
    userinfo = token.get("userinfo", {})
    email = userinfo.get("email", "")
    name = userinfo.get("name", "")

    # redireciona p/ onboarding com plan=free ou algo
    return RedirectResponse(f"/onboarding?plan=free&google_email={email}&google_name={name}")

########################
# HOME + CHECKOUT
########################

@app.get("/")
def home():
    return render_page("home.html")

@app.get("/checkout/{plan}")
def checkout(plan: str, db=Depends(get_db)):
    if plan=="pro":
        amount_cents=24900
        product_name="Plano Pro"
    elif plan=="enterprise":
        amount_cents=99900
        product_name="Plano Enterprise"
    else:
        raise HTTPException(400, "Plano inválido")

    temp_id = get_and_increment_temp_id(db)

    try:
        session_data = stripe.checkout.Session.create(
            payment_method_types=["card"],
            line_items=[{
                "price_data": {
                    "currency":"brl",
                    "product_data":{"name":product_name},
                    "unit_amount": amount_cents
                },
                "quantity":1
            }],
            mode="payment",
            success_url=f"{DOMAIN_URL}/onboarding?plan={plan}&temp_id={temp_id}&session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=f"{DOMAIN_URL}/cancel",
            metadata={
                "temp_id": str(temp_id),
                "plan": plan
            }
        )
        return RedirectResponse(session_data.url)
    except Exception as e:
        raise HTTPException(400, str(e))

@app.get("/cancel")
def payment_cancel():
    return HTMLResponse("Pagamento cancelado. Tente novamente ou escolha outro plano.")

########################
# ONBOARDING
########################

@app.get("/onboarding")
def onboarding_get(
    plan:str="free",
    temp_id:str="",
    session_id:str="",
    google_email:str="",
    google_name:str=""
):
    context = {
        "PLAN": plan,
        "TEMP_ID": temp_id,
        "SESSION_ID": session_id,
        "GOOGLE_EMAIL": google_email,
        "GOOGLE_NAME": google_name
    }
    return render_page("onboarding.html", context)

@app.post("/onboarding")
def onboarding_post(
    full_name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    doc_number: str = Form(""),

    cep: str = Form(""),
    rua: str = Form(""),
    numero: str = Form(""),
    complemento: str = Form(""),
    bairro: str = Form(""),
    cidade: str = Form(""),
    estado: str = Form(""),
    pais: str = Form(""),

    whatsapp_phone: str = Form(""),
    plan: str = Form("free"),
    temp_id: str = Form(""),
    session_id: str = Form(""),

    db=Depends(get_db)
):
    # limpa doc_number
    doc_clean = re.sub(r"\D","", doc_number)
    phone_clean = re.sub(r"\D","", whatsapp_phone)
    cep_clean = re.sub(r"\D","", cep)

    # hasheia a senha
    hashed_pw = bcrypt.hash(password)

    # convert temp_id
    try:
        tid = int(temp_id)
    except:
        tid = None

    user = User(
        temp_id=tid,
        full_name=full_name,
        email=email,
        password_hash=hashed_pw,
        doc_number=doc_clean,
        cep=cep_clean,
        rua=rua,
        numero=numero,
        complemento=complemento,
        bairro=bairro,
        cidade=cidade,
        estado=estado,
        pais=pais,
        whatsapp_phone=phone_clean,
        plan=plan
    )
    db.add(user)
    db.commit()

    return RedirectResponse("/dashboard", 302)

@app.get("/dashboard")
def dashboard():
    return HTMLResponse("Bem-vindo ao Dashboard! (Implemente login e exiba dados do user se quiser).")

########################
# STRIPE WEBHOOK
########################

@app.post("/stripe-webhook")
async def stripe_webhook(request: Request):
    if not STRIPE_WEBHOOK_SECRET:
        return {"status":"webhook not secure"}

    payload = await request.body()
    sig_header = request.headers.get("stripe-signature")
    try:
        event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
    except (ValueError, stripe.error.SignatureVerificationError):
        raise HTTPException(400,"Invalid signature")

    if event["type"]=="checkout.session.completed":
        sess = event["data"]["object"]
        meta = sess.get("metadata",{})
        print(f"[Stripe] Payment done. temp_id={meta.get('temp_id')} plan={meta.get('plan')}")
    return {"status":"ok"}

########################
# WHATSAPP WEBHOOK
########################

@app.get("/webhook")
def verify_whatsapp(
    hub_mode:str=None,
    hub_challenge:str=None,
    hub_verify_token:str=None
):
    if hub_verify_token==WHATSAPP_VERIFY_TOKEN:
        return PlainTextResponse(hub_challenge or "")
    raise HTTPException(403,"Invalid verify token")

@app.post("/webhook")
async def receive_whatsapp(request: Request):
    return {"status":"ok"}
