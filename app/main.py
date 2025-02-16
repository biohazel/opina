import os
import re
import requests
import stripe
import secrets
import unicodedata

from fastapi import FastAPI, Request, Form, HTTPException, Depends, BackgroundTasks, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.responses import PlainTextResponse
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request
from typing import Optional
from datetime import datetime, timedelta

# SQLAlchemy
from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.orm import sessionmaker, declarative_base
from passlib.hash import bcrypt

########################
# FASTAPI + SESSION
########################

app = FastAPI()

SESSION_SECRET_KEY = os.getenv("SESSION_SECRET_KEY", "CHAVE_SUPER_SECRETA_OPINA")
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET_KEY,
    session_cookie="opina_session",
    max_age=60 * 60 * 24 * 7,  # 7 dias
    https_only=False,
    same_site="strict"
)

app.mount("/static", StaticFiles(directory="app/static"), name="static")

########################
# ENV Vars
########################

WHATSAPP_VERIFY_TOKEN = os.getenv("WHATSAPP_VERIFY_TOKEN", "")
ACCESS_TOKEN = os.getenv("WHATSAPP_ACCESS_TOKEN", "")
PHONE_NUMBER_ID = os.getenv("PHONE_NUMBER_ID", "")

STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")
DOMAIN_URL = os.getenv("DOMAIN_URL", "https://opina.live")

DATABASE_URL = os.getenv("DATABASE_URL", "")

# Stripe
stripe.api_key = STRIPE_SECRET_KEY

########################
# DB Setup
########################

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL not set")

engine = create_engine(DATABASE_URL, echo=False, future=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

########################
# MODELS
########################

class TempIdCounter(Base):
    __tablename__ = "temp_id_counter"
    id = Column(Integer, primary_key=True, index=True)
    current_value = Column(Integer, default=0)

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)

    temp_id = Column(Integer, unique=True, index=True, nullable=True)  # Stripe metadata

    full_name = Column(String)      # Nome da pessoa
    company_name = Column(String)   # Nome da empresa
    segment = Column(String)        # Segmento de atuação (ex: oficinas, clínicas)
    company_slug = Column(String, unique=True, index=True)  # slug p/ /fb/{slug}

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

class Feedback(Base):
    __tablename__ = "feedbacks"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    sender_phone = Column(String)
    audio_url = Column(String)
    transcript = Column(String)
    sentiment = Column(String)
    status = Column(String, default="pending")
    created_at = Column(DateTime, default=datetime.utcnow)
    processed_at = Column(DateTime, nullable=True)

# (Opcional) Tabela p/ mapear phone->slug ao receber msgs
class PhoneCodeMap(Base):
    __tablename__ = "phone_code_map"
    id = Column(Integer, primary_key=True)
    phone = Column(String, index=True)
    slug = Column(String)
    valid_until = Column(DateTime)

Base.metadata.create_all(bind=engine)

########################
# INIT TempIdCounter
########################

db_init = SessionLocal()
ctr = db_init.query(TempIdCounter).first()
if not ctr:
    db_init.add(TempIdCounter(id=1, current_value=0))
    db_init.commit()
db_init.close()

########################
# Helpers
########################

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_and_increment_temp_id(db):
    row = db.query(TempIdCounter).filter(TempIdCounter.id == 1).first()
    row.current_value += 1
    db.commit()
    return row.current_value

def slugify(value: str) -> str:
    """
    Converte o nome da empresa em um slug URL-friendly:
    - remove acentos
    - remove caracteres especiais
    - troca espaços por '-'
    """
    value = value.strip().lower()
    value = unicodedata.normalize('NFKD', value)
    value = value.encode('ascii', 'ignore').decode('ascii')
    value = re.sub(r'[^a-z0-9]+', '-', value)
    # remove hifens duplicados
    value = re.sub(r'-+', '-', value)
    value = value.strip('-')
    return value or "empresa"

def generate_unique_slug(db, base_name: str) -> str:
    """
    Gera slug único no DB. Se já existir, adiciona sufixo.
    """
    base_slug = slugify(base_name)
    candidate = base_slug
    i = 1
    while True:
        # verifica se slug está disponível
        existing = db.query(User).filter(User.company_slug == candidate).first()
        if not existing:
            return candidate
        i += 1
        candidate = f"{base_slug}-{i}"

def store_phone_slug(db, phone: str, slug: str):
    """
    Armazena mapeamento phone->slug com validade de 10min, substitui se já existir
    """
    db.query(PhoneCodeMap).filter(PhoneCodeMap.phone == phone).delete()
    entry = PhoneCodeMap(
        phone=phone,
        slug=slug,
        valid_until=datetime.utcnow() + timedelta(minutes=10)
    )
    db.add(entry)
    db.commit()

def get_slug_by_phone(db, phone: str) -> Optional[str]:
    entry = db.query(PhoneCodeMap).filter(PhoneCodeMap.phone == phone).first()
    if entry:
        if entry.valid_until > datetime.utcnow():
            return entry.slug
        else:
            db.delete(entry)
            db.commit()
    return None

def render_page(file_name: str, context: dict = None):
    path = os.path.join("app", "templates", file_name)
    if not os.path.isfile(path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Template {file_name} não encontrado."
        )
    with open(path, "r", encoding="utf-8") as f:
        html = f.read()
    if context:
        for k, v in context.items():
            if v is None:
                v = ""
            html = html.replace(f"{{{{{k}}}}}", str(v))
    return HTMLResponse(html)

########################
# ROTAS PRINCIPAIS
########################

@app.get("/")
def home():
    return render_page("home.html")

########################
# CHECKOUT
########################

@app.get("/checkout/{plan}")
def checkout(plan: str, db=Depends(get_db)):
    if plan == "pro":
        amount_cents = 24900
        product_name = "Plano Pro"
    elif plan == "enterprise":
        amount_cents = 99900
        product_name = "Plano Enterprise"
    else:
        raise HTTPException(400, "Plano inválido")

    temp_id = get_and_increment_temp_id(db)

    try:
        session_data = stripe.checkout.Session.create(
            payment_method_types=["card"],
            line_items=[{
                "price_data": {
                    "currency": "brl",
                    "product_data": {"name": product_name},
                    "unit_amount": amount_cents
                },
                "quantity": 1
            }],
            mode="payment",
            success_url=f"{DOMAIN_URL}/onboarding?plan={plan}&temp_id={temp_id}&session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=f"{DOMAIN_URL}/cancel",
            client_reference_id=str(temp_id)
        )
        return RedirectResponse(session_data.url)
    except Exception as e:
        print("[ERROR] Checkout creation failed:", e)
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
    context = {
        "PLAN": plan,
        "TEMP_ID": temp_id,
        "SESSION_ID": session_id
    }
    return render_page("onboarding.html", context)

@app.post("/onboarding")
def onboarding_post(
    request: Request,
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

    # Campos adicionais
    company_name: str = Form(""),      # Nome da empresa
    segment: str = Form(""),           # Segmento de atuação

    db=Depends(get_db)
):
    print(f"[INFO] Onboarding user email={email}, plan={plan}")

    doc_clean = re.sub(r"\D", "", doc_number)
    cep_clean = re.sub(r"\D", "", cep)
    phone_clean = re.sub(r"\D", "", whatsapp_phone)

    hashed_pw = bcrypt.hash(password)

    try:
        tid = int(temp_id)
    except:
        tid = None

    # Gera slug único baseado no company_name
    slug = generate_unique_slug(db, company_name or "MinhaEmpresa")

    user = User(
        temp_id=tid,
        full_name=full_name.strip(),
        company_name=company_name.strip(),
        segment=segment.strip(),
        company_slug=slug,

        email=email.strip().lower(),
        password_hash=hashed_pw,
        doc_number=doc_clean,

        cep=cep_clean,
        rua=rua.strip(),
        numero=numero.strip(),
        complemento=complemento.strip(),
        bairro=bairro.strip(),
        cidade=cidade.strip(),
        estado=estado.strip(),
        pais=pais.strip(),

        whatsapp_phone=phone_clean,
        plan=plan,
        created_at=datetime.utcnow()
    )
    db.add(user)
    db.commit()

    request.session["user_id"] = user.id
    return RedirectResponse("/dashboard", status_code=302)

########################
# LOGIN / LOGOUT
########################

@app.get("/login")
def login_get():
    return render_page("login.html")

@app.post("/login")
def login_post(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db=Depends(get_db)
):
    user = db.query(User).filter(User.email == email.strip().lower()).first()
    if not user:
        return HTMLResponse("Usuário não encontrado.", status_code=400)

    if not bcrypt.verify(password, user.password_hash):
        return HTMLResponse("Senha incorreta.", status_code=400)

    request.session["user_id"] = user.id
    return RedirectResponse("/dashboard", status_code=302)

@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/")

########################
# DASHBOARD
########################

@app.get("/dashboard")
def dashboard(request: Request, db=Depends(get_db)):
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse("/login")

    current_user = db.query(User).filter(User.id == user_id).first()
    if not current_user:
        request.session.clear()
        return RedirectResponse("/login")

    feedbacks = db.query(Feedback).filter(Feedback.user_id == current_user.id).all()

    total = len(feedbacks)
    positives = sum(1 for f in feedbacks if f.sentiment == "positive")
    negatives = sum(1 for f in feedbacks if f.sentiment == "negative")

    if total > 0:
        pos_percent = round((positives / total) * 100, 1)
        neg_percent = round((negatives / total) * 100, 1)
    else:
        pos_percent = 0
        neg_percent = 0

    feedback_html = ""
    for fb in feedbacks:
        feedback_html += f"""
        <div class="feedback-item">
          <p><strong>De:</strong> {fb.sender_phone or '-'} |
             <strong>Sentimento:</strong> {fb.sentiment or '(pendente)'}
          </p>
          <p>Transcrição: {fb.transcript or '(aguardando)'} </p>
          <hr/>
        </div>
        """

    # Montar link de feedback
    # Ex: https://opina.live/fb/<slug>
    feedback_link = f"{DOMAIN_URL}/fb/{current_user.company_slug}"

    context = {
        "USER_NAME": current_user.full_name,
        "PLAN": current_user.plan,
        "TOTAL_FEEDBACKS": str(total),
        "POSITIVE_PERCENT": str(pos_percent),
        "NEGATIVE_PERCENT": str(neg_percent),
        "FEEDBACK_LIST": feedback_html,
        # Caso queira exibir no HTML
        "FEEDBACK_LINK": feedback_link
    }
    # Se for usando template, inserir {{FEEDBACK_LINK}} no HTML
    html = render_page("dashboard.html", context)
    # ou inserir manualmente no HTML, p.ex.:
    # Adicionar um input de exibição do link
    insert_str = f"""
    <p>Link de Feedback (WhatsApp): 
       <input type="text" readonly value="{feedback_link}" style="width:100%; max-width:400px;">
    </p>
    """
    # injeta antes do <h3>Feedbacks Recebidos
    html = html.replace("<h3>Feedbacks Recebidos</h3>", insert_str + "<h3>Feedbacks Recebidos</h3>")

    return HTMLResponse(html)

########################
# TERMOS E POLÍTICA
########################

@app.get("/termos")
def termos_de_uso():
    return render_page("termos.html")

@app.get("/privacidade")
def politica_privacidade():
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
        print("[ERROR] Invalid Stripe signature")
        raise HTTPException(400, "Invalid signature")

    if event["type"] == "checkout.session.completed":
        sess = event["data"]["object"]
        temp_id_str = sess.get("client_reference_id")
        plan = sess.get("metadata", {}).get("plan", "")
        print(f"[Stripe] Payment done. temp_id={temp_id_str} plan={plan}")

        if temp_id_str:
            try:
                temp_id_val = int(temp_id_str)
                existing_user = db.query(User).filter(User.temp_id == temp_id_val).first()
                if existing_user:
                    existing_user.plan = plan or existing_user.plan
                    db.commit()
            except Exception as e:
                print("[ERROR] Finalizing webhook Stripe:", e)

    return {"status": "ok"}

########################
# WHATSAPP FLOW
########################

@app.get("/fb/{slug}")
def whatsapp_feedback_redirect(slug: str, db=Depends(get_db)):
    """
    Redireciona para o link do WhatsApp com mensagem. 
    Exemplo: 
    "Olá! Obrigada por ser cliente da Caramurucar! Você pode mandar áudio?"
    """
    user = db.query(User).filter(User.company_slug == slug).first()
    if not user:
        return HTMLResponse("Empresa não encontrada.", status_code=404)

    from urllib.parse import quote_plus

    numero_opina = "5599999999999"  # seu numero sem pontuação
    mensagem = f"Olá! Obrigada por ser cliente da {user.company_name}! Envie seu áudio de feedback :)"

    # Se quiser mapear phone->slug p/ associar áudio
    # Precisamos que o usuário final envie um TEXT contendo esse slug?
    # Pra simplificar, iremos só exibir o nome da empresa no msg
    url = f"https://wa.me/{numero_opina}?text={quote_plus(mensagem)}"

    return RedirectResponse(url)

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
async def receive_whatsapp(request: Request, background_tasks: BackgroundTasks, db=Depends(get_db)):
    data = await request.json()
    try:
        entry = data["entry"][0]
        changes = entry["changes"][0]
        value = changes["value"]
        messages = value.get("messages", [])

        for msg in messages:
            sender = msg.get("from")  # ex: "559999999999"
            msg_type = msg.get("type")

            if msg_type == "text":
                text_body = msg["text"]["body"].lower()
                # Tenta achar alguma substring que identifique a empresa
                # Exemplo: se user.company_name in text_body
                # ou guardamos phone->slug
                # Aqui é só exemplo: se "caramurucar" estiver no texto, guardamos
                all_users = db.query(User).all()
                matched_user = None
                for u in all_users:
                    if u.company_name and u.company_name.lower() in text_body:
                        matched_user = u
                        break
                if matched_user:
                    store_phone_slug(db, sender, matched_user.company_slug)

            elif msg_type == "audio":
                media_id = msg["audio"]["id"]
                # Ver se phone->slug está no DB
                slug_for_phone = get_slug_by_phone(db, sender)
                user = None
                if slug_for_phone:
                    user = db.query(User).filter(User.company_slug == slug_for_phone).first()

                # Se não achou user, fallback p/ user_id=1
                if not user:
                    # LOG: fallback
                    user_id = 1
                else:
                    user_id = user.id

                new_fb = Feedback(
                    user_id=user_id,
                    sender_phone=sender,
                    audio_url=f"(media_id={media_id})",
                    status="pending",
                    created_at=datetime.utcnow()
                )
                db.add(new_fb)
                db.commit()
                db.refresh(new_fb)

                background_tasks.add_task(process_feedback, new_fb.id)

    except Exception as e:
        print("[ERROR] WhatsApp webhook:", e)

    return {"status": "ok"}

def process_feedback(feedback_id: int):
    db_sess = SessionLocal()
    try:
        fb = db_sess.query(Feedback).filter(Feedback.id == feedback_id).first()
        if not fb:
            return
        # Exemplo de transcrição e sentimento
        fb.transcript = "Exemplo de transcrição feita pela IA"
        fb.sentiment = "positive"
        fb.status = "done"
        fb.processed_at = datetime.utcnow()
        db_sess.commit()
    except Exception as err:
        print("[ERROR] process_feedback:", err)
    finally:
        db_sess.close()
