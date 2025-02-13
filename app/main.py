import os
import requests
import stripe

from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.responses import PlainTextResponse

# ====== SQLAlchemy ======
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.orm import sessionmaker, declarative_base
from datetime import datetime

# ====== Hash de Senhas (bcrypt via passlib) ======
from passlib.hash import bcrypt

########################
#   FASTAPI CONFIG
########################

app = FastAPI()

# Monta /static para servir arquivos do diretório app/static
app.mount("/static", StaticFiles(directory="app/static"), name="static")

########################
#   ENV VARS
########################

WHATSAPP_VERIFY_TOKEN = os.getenv("WHATSAPP_VERIFY_TOKEN", "")
ACCESS_TOKEN = os.getenv("WHATSAPP_ACCESS_TOKEN", "")
PHONE_NUMBER_ID = os.getenv("PHONE_NUMBER_ID", "")

STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")
DOMAIN_URL = os.getenv("DOMAIN_URL", "http://localhost:8000")

DATABASE_URL = os.getenv("DATABASE_URL", "")

# Configura Stripe
stripe.api_key = STRIPE_SECRET_KEY

########################
#   BANCO DE DADOS
########################

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL not set. Configure your Postgres in Render or .env")

engine = create_engine(DATABASE_URL, echo=False)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)  # Senha hashed (bcrypt)
    plan = Column(String, default="free")
    created_at = Column(DateTime, default=datetime.utcnow)

# Cria tabelas se não existirem
Base.metadata.create_all(bind=engine)

########################
# RENDER PAGE HELPER
########################

def render_page(html_name: str, context: dict = None) -> HTMLResponse:
    file_path = os.path.join("app", "templates", html_name)
    with open(file_path, "r", encoding="utf-8") as f:
        html_content = f.read()
    if context:
        for key, val in context.items():
            placeholder = f"{{{{{key}}}}}"
            html_content = html_content.replace(placeholder, val)
    return HTMLResponse(content=html_content)

########################
# DB SESSION HELPER
########################

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

########################
#   VAR GERAL DE SESSÃO
########################

current_user_email = None  # Exemplo simples. Em produção, use tokens/cookies

########################
#     ROTAS PRINCIPAIS
########################

@app.get("/")
def home():
    return render_page("home.html")

@app.get("/login")
def login_form():
    return render_page("login.html")

@app.post("/login")
def do_login(email: str = Form(...), password: str = Form(...)):
    """
    Se user não existir, cria com plan=free. 
    Se existir, compara a senha (bcrypt).
    """
    global current_user_email
    db = SessionLocal()
    user = db.query(User).filter(User.email == email).first()
    if user:
        # Verifica senha
        if bcrypt.verify(password, user.password_hash):
            current_user_email = user.email
            return RedirectResponse("/dashboard", status_code=302)
        else:
            return "Senha incorreta"
    else:
        # Cria user (free)
        hashed_pw = bcrypt.hash(password)
        new_user = User(email=email, password_hash=hashed_pw, plan="free")
        db.add(new_user)
        db.commit()
        current_user_email = new_user.email
        return RedirectResponse("/dashboard", status_code=302)

@app.get("/dashboard")
def dashboard():
    global current_user_email
    if not current_user_email:
        return RedirectResponse("/login", status_code=302)

    db = SessionLocal()
    user = db.query(User).filter(User.email == current_user_email).first()
    if not user:
        return "Usuário não encontrado. Faça login novamente."

    # Exemplo de feedbacks:
    feedbacks = [
        {"from_phone": "+551199999999", "transcript": "Excelente serviço!", "sentiment": "positivo"},
        {"from_phone": "+551188888888", "transcript": "Não gostei do atraso", "sentiment": "negativo"}
    ]
    feedbacks_html = ""
    for f in feedbacks:
        feedbacks_html += f"<li>De {f['from_phone']}: {f['transcript']} (Sentimento: {f['sentiment']})</li>"

    context = {
        "USER_EMAIL": user.email,
        "PLAN": user.plan,
        "FEEDBACKS_LIST": feedbacks_html
    }
    return render_page("dashboard.html", context=context)

########################
#  ASSINATURA FREE
########################

@app.post("/subscribe_free")
def subscribe_free():
    """
    Se user quiser plano free (sem stripe).
    """
    global current_user_email
    if not current_user_email:
        return RedirectResponse("/login", status_code=302)

    db = SessionLocal()
    user = db.query(User).filter(User.email == current_user_email).first()
    if user:
        user.plan = "free"
        db.commit()
    return RedirectResponse("/dashboard", status_code=302)

########################
#   STRIPE CHECKOUT
########################

@app.get("/checkout/{plan}")
def create_checkout_session(plan: str):
    """
    Cria sessão de checkout para Pro ou Enterprise. 
    Salva user_id e plan no metadata, para atualizar via webhook.
    """
    global current_user_email
    if not current_user_email:
        return RedirectResponse("/login", status_code=302)

    db = SessionLocal()
    user = db.query(User).filter(User.email == current_user_email).first()
    if not user:
        return "Usuário não encontrado. Faça login novamente."

    if plan == "pro":
        amount_cents = 24900
        product_name = "Plano Pro"
    elif plan == "enterprise":
        amount_cents = 99900
        product_name = "Plano Enterprise"
    else:
        raise HTTPException(status_code=400, detail="Plano inválido")

    try:
        session = stripe.checkout.Session.create(
            payment_method_types=["card", "pix"],
            line_items=[{
                "price_data": {
                    "currency": "brl",
                    "product_data": {"name": product_name},
                    "unit_amount": amount_cents
                },
                "quantity": 1
            }],
            mode="payment",
            success_url=f"{DOMAIN_URL}/success",
            cancel_url=f"{DOMAIN_URL}/cancel",
            metadata={
                "user_id": str(user.id),
                "plan": plan
            }
        )
        return RedirectResponse(session.url)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/success")
def payment_success():
    """
    Mensagem simples de sucesso. 
    O webhook faz a atualização do plan no DB.
    """
    return HTMLResponse("Pagamento concluído com sucesso! Retorne ao /dashboard.")

@app.get("/cancel")
def payment_cancel():
    return HTMLResponse("Pagamento cancelado. Tente novamente ou escolha outro plano.")

########################
#   STRIPE WEBHOOK
########################

@app.post("/stripe-webhook")
async def stripe_webhook(request: Request):
    """
    Recebe 'checkout.session.completed' contendo user_id e plan no metadata,
    atualiza user.plan no DB.
    """
    if not STRIPE_WEBHOOK_SECRET:
        return {"status": "webhook not secure - set STRIPE_WEBHOOK_SECRET"}

    payload = await request.body()
    sig_header = request.headers.get("stripe-signature")
    try:
        event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
    except (ValueError, stripe.error.SignatureVerificationError):
        raise HTTPException(status_code=400, detail="Invalid signature")

    if event["type"] == "checkout.session.completed":
        session_obj = event["data"]["object"]
        user_id = session_obj["metadata"].get("user_id")
        plan = session_obj["metadata"].get("plan")
        if user_id and plan:
            db = SessionLocal()
            user = db.query(User).filter(User.id == int(user_id)).first()
            if user:
                user.plan = plan
                db.commit()
                print(f"[Stripe Hook] User {user.email} => plan={plan}")
            db.close()

    return {"status": "ok"}

########################
#  WHATSAPP WEBHOOK
########################

@app.get("/webhook")
def verify_whatsapp(hub_mode: str = None,
                    hub_challenge: str = None,
                    hub_verify_token: str = None):
    if hub_verify_token == WHATSAPP_VERIFY_TOKEN:
        return PlainTextResponse(hub_challenge or "")
    raise HTTPException(status_code=403, detail="Invalid verify token")

@app.post("/webhook")
async def receive_whatsapp(request: Request):
    body = await request.json()
    entry = body.get("entry", [])
    if entry:
        changes = entry[0].get("changes", [])
        if changes:
            value = changes[0].get("value", {})
            messages = value.get("messages", [])
            if messages:
                msg = messages[0]
                from_phone = msg.get("from")
                msg_type = msg.get("type")
                if msg_type == "text":
                    text_body = msg["text"]["body"]
                    send_whatsapp_message(from_phone, f"Recebido: {text_body}")
                elif msg_type == "audio":
                    audio_id = msg["audio"]["id"]
                    audio_url = get_media_url(audio_id, ACCESS_TOKEN)
                    audio_file = download_file(audio_url, ACCESS_TOKEN)
                    send_whatsapp_message(from_phone, "Seu áudio foi processado!")
    return {"status": "ok"}

def get_media_url(media_id, token):
    url = f"https://graph.facebook.com/v16.0/{media_id}"
    headers = {"Authorization": f"Bearer {token}"}
    resp = requests.get(url, headers=headers).json()
    return resp["url"]

def download_file(file_url, token):
    resp = requests.get(file_url, headers={"Authorization": f"Bearer {token}"})
    filename = "audio.ogg"
    with open(filename, "wb") as f:
        f.write(resp.content)
    return filename

def send_whatsapp_message(to, text):
    url = f"https://graph.facebook.com/v16.0/{PHONE_NUMBER_ID}/messages"
    headers = {
        "Authorization": f"Bearer {ACCESS_TOKEN}",
        "Content-Type": "application/json"
    }
    payload = {
        "messaging_product": "whatsapp",
        "to": to,
        "text": {"body": text}
    }
    r = requests.post(url, json=payload, headers=headers)
    if r.status_code != 200:
        print("Erro ao enviar mensagem:", r.text)
