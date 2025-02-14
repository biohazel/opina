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

# Stripe
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
    id = Column(Integer, primary_key=True, index=True)  # fixo = 1
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
    """ Carrega o HTML do templates/file_name e faz replace de chaves {{...}} se existirem. """
    path = os.path.join("app", "templates", file_name)
    with open(path, "r", encoding="utf-8") as f:
        html = f.read()
    if context:
        for k,v in context.items():
            if v is None:
                v = ""
            html = html.replace(f"{{{{{k}}}}}", str(v))
    return HTMLResponse(html)

########################
# HOME + CHECKOUT
########################

@app.get("/")
def home():
    return render_page("home.html")

@app.get("/checkout/{plan}")
def checkout(plan: str, db=Depends(get_db)):
    """
    Cria sessão de checkout no Stripe e redireciona para lá.
    Ao retornar, iremos p/ /onboarding com plan e temp_id, ou /cancel se não deu certo.
    """
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
                    "product_data": {"name": product_name},
                    "unit_amount": amount_cents
                },
                "quantity": 1
            }],
            mode="payment",
            success_url=f"{DOMAIN_URL}/onboarding?plan={plan}&temp_id={temp_id}&session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=f"{DOMAIN_URL}/cancel",
            client_reference_id=str(temp_id)  # mapeamos pro metadata
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
    plan: str = "free",
    temp_id: str = "",
    session_id: str = ""
):
    """
    Se plan=free, não precisa Stripe.
    Se plan=pro/enterprise, teoricamente veio do Stripe success, com temp_id gerado.
    """
    context = {
        "PLAN": plan,
        "TEMP_ID": temp_id,
        "SESSION_ID": session_id
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
    # limpa doc_number e cep e phone, removendo caracteres não numéricos
    doc_clean = re.sub(r"\D", "", doc_number)
    cep_clean = re.sub(r"\D", "", cep)
    phone_clean = re.sub(r"\D", "", whatsapp_phone)

    hashed_pw = bcrypt.hash(password)

    try:
        tid = int(temp_id)
    except:
        tid = None

    user = User(
        temp_id = tid,
        full_name = full_name.strip(),
        email = email.strip().lower(),
        password_hash = hashed_pw,
        doc_number = doc_clean,
        cep = cep_clean,
        rua = rua.strip(),
        numero = numero.strip(),
        complemento = complemento.strip(),
        bairro = bairro.strip(),
        cidade = cidade.strip(),
        estado = estado.strip(),
        pais = pais.strip(),
        whatsapp_phone = phone_clean,
        plan = plan
    )
    db.add(user)
    db.commit()

    return RedirectResponse("/dashboard", status_code=302)

########################
# LOGIN
########################
@app.get("/login")
def login_get():
    return render_page("login.html")

@app.post("/login")
def login_post(
    email: str = Form(...),
    password: str = Form(...),
    db=Depends(get_db)
):
    user = db.query(User).filter(User.email == email.strip().lower()).first()
    if not user:
        return HTMLResponse("Usuário não encontrado.", status_code=400)

    if not bcrypt.verify(password, user.password_hash):
        return HTMLResponse("Senha incorreta.", status_code=400)

    # Se sucesso, redireciona p/ dashboard
    # (No futuro: setar session cookie, etc.)
    return RedirectResponse("/dashboard", status_code=302)

########################
# DASHBOARD
########################
@app.get("/dashboard")
def dashboard():
    # placeholder
    return HTMLResponse("<h1>Bem-vindo ao Dashboard!</h1><p>Aqui ficarão os insights e análises.</p>")

########################
# TERMOS & POLÍTICA
########################

@app.get("/termos")
def termos_de_uso():
    """
    Renderiza a página de Termos de Uso.
    Você pode editar o arquivo templates/termos.html para incluir mais detalhes.
    """
    return render_page("termos.html")

@app.get("/privacidade")
def politica_privacidade():
    """
    Renderiza a página de Política de Privacidade.
    Edite templates/privacidade.html conforme necessidade.
    """
    return render_page("privacidade.html")

########################
# STRIPE WEBHOOK
########################

@app.post("/stripe-webhook")
async def stripe_webhook(request: Request, db=Depends(get_db)):
    if not STRIPE_WEBHOOK_SECRET:
        return {"status": "webhook not secure"}

    payload = await request.body()
    sig_header = request.headers.get("stripe-signature")
    try:
        event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
    except (ValueError, stripe.error.SignatureVerificationError):
        raise HTTPException(400, "Invalid signature")

    if event["type"] == "checkout.session.completed":
        sess = event["data"]["object"]
        temp_id_str = sess.get("client_reference_id")
        plan = sess.get("metadata", {}).get("plan", "")  # se tiver metadata
        print(f"[Stripe] Payment done. temp_id={temp_id_str} plan={plan}")

        if temp_id_str:
            try:
                temp_id_val = int(temp_id_str)
                # Buscar user no banco com esse temp_id
                existing_user = db.query(User).filter(User.temp_id == temp_id_val).first()
                if existing_user:
                    # Se o user já existir, podemos garantir que user.plan = plan
                    existing_user.plan = plan or existing_user.plan
                    db.commit()
                else:
                    # Caso não exista, significa que a pessoa pagou
                    # mas ainda não preencheu o onboarding
                    # -> futuro: mandar email lembrando de concluir cadastro
                    pass
            except:
                pass

    return {"status": "ok"}

########################
# WHATSAPP WEBHOOK
########################

@app.get("/webhook")
def verify_whatsapp(
    hub_mode: str = None,
    hub_challenge: str = None,
    hub_verify_token: str = None
):
    if hub_verify_token == WHATSAPP_VERIFY_TOKEN:
        return PlainTextResponse(hub_challenge or "")
    raise HTTPException(403, "Invalid verify token")

@app.post("/webhook")
async def receive_whatsapp(request: Request):
    return {"status": "ok"}
