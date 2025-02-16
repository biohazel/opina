import os
import re
import requests
import secrets
import unicodedata
import stripe

from fastapi import FastAPI, Request, Form, HTTPException, Depends, BackgroundTasks, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.responses import PlainTextResponse
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request
from typing import Optional
from datetime import datetime, timedelta

# SQLAlchemy
from sqlalchemy import create_engine, Column, String, DateTime, ForeignKey, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import sessionmaker, declarative_base
from passlib.hash import bcrypt

###############
# FASTAPI + SESSION
###############

app = FastAPI()

SESSION_SECRET_KEY = os.getenv("SESSION_SECRET_KEY", "CHAVE_SUPER_SECRETA_OPINA")
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET_KEY,
    session_cookie="opina_session",
    max_age=60 * 60 * 24 * 7,
    https_only=False,
    same_site="strict"
)

# Monta /static
app.mount("/static", StaticFiles(directory="app/static"), name="static")

###############
# ENV Vars
###############

WHATSAPP_VERIFY_TOKEN = os.getenv("WHATSAPP_VERIFY_TOKEN", "")
ACCESS_TOKEN = os.getenv("WHATSAPP_ACCESS_TOKEN", "")
PHONE_NUMBER_ID = os.getenv("PHONE_NUMBER_ID", "")

STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")
DOMAIN_URL = os.getenv("DOMAIN_URL", "https://opina.live")

DATABASE_URL = os.getenv("DATABASE_URL", "")
stripe.api_key = STRIPE_SECRET_KEY

###############
# DB Setup
###############

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL not set")

engine = create_engine(DATABASE_URL, echo=False, future=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

###############
# MODELS
###############
#
# Tabela principal: "tenant"
# - Guarda dados cadastrais do cliente (plano, nome, doc_number etc.)
# - Usando UUID como ID principal
#
# Tabela "feedback" relaciona-se a tenant_id (UUID).
# Você criou via script "multi_tenant_schema.sql", mas
# definimos a classe ORM para consultas com SQLAlchemy.

from sqlalchemy import BigInteger

class Tenant(Base):
    __tablename__ = "tenant"
    # O script .sql cria algo como:
    #   id UUID PRIMARY KEY DEFAULT gen_random_uuid()
    # Mas para não conflitar, definimos assim:
    id = Column(UUID(as_uuid=True), primary_key=True)
    nome = Column(String, unique=True)        # Ex: "Caramurucar"
    plano = Column(String)                    # "free", "pro", "enterprise"

    # Campos adicionais
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
    email = Column(String, unique=True, index=True)
    password_hash = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)

class Feedback(Base):
    __tablename__ = "feedback"
    # O script .sql cria:
    #   id BIGSERIAL PRIMARY KEY,
    #   tenant_id UUID REFERENCES tenant(id),
    #   ...
    id = Column(BigInteger, primary_key=True)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenant.id"))
    usuario_final = Column(String(20))
    audio_url = Column(String)
    transcript = Column(String)
    sentimento = Column(String)
    resumo = Column(String)
    criado_em = Column(DateTime)

# Tabela de Auditoria se quiser manipular via ORM
class AuditLog(Base):
    __tablename__ = "audit_log"
    id = Column(BigInteger, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    usuario = Column(String)
    tenant_id = Column(UUID(as_uuid=True))
    acao = Column(String)
    detalhe = Column(String)

# Observação: Base.metadata.create_all() NÃO criará as tabelas se elas já existem via script. 
# Mas não faz mal deixá-lo aqui, pois não faz nada se a tabela já existe.
Base.metadata.create_all(bind=engine)

###############
# Helpers
###############

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def render_page(file_name: str, context: dict = None):
    import os
    from fastapi import status
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

###############
# ROTAS
###############

@app.get("/")
def home():
    return render_page("home.html")

#################
# CHECKOUT
#################

import stripe
from fastapi.responses import RedirectResponse

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

    # Exemplo: geramos um temp "customer_id" = seg?
    # Aqui, só geramos algo estático, mas poderia mapear
    # a um tenant existente. Simplificação:
    import random
    random_id = random.randint(10000, 999999)

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
            success_url=f"{DOMAIN_URL}/onboarding?plan={plan}&temp_id={random_id}&session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=f"{DOMAIN_URL}/cancel",
            client_reference_id=str(random_id)
        )
        return RedirectResponse(session_data.url)
    except Exception as e:
        print("[ERROR] Checkout creation failed:", e)
        raise HTTPException(400, str(e))

@app.get("/cancel")
def payment_cancel():
    return HTMLResponse("Pagamento cancelado. Tente novamente ou escolha outro plano.")

#################
# ONBOARDING
#################

from fastapi import Form

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
    db=Depends(get_db),
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
    temp_id: str = Form(""),  # gerado no checkout
    session_id: str = Form(""),
):
    """
    Cria um tenant no DB. 
    Observação: Esse fluxo supõe que no final, "nome" do tenant é 'full_name' etc.
    """
    from passlib.hash import bcrypt

    hashed_pw = bcrypt.hash(password)
    # Insert no tenant
    sql = text("""
    INSERT INTO tenant (nome, plano, doc_number, cep, rua, numero, complemento, bairro,
                        cidade, estado, pais, whatsapp_phone, email, password_hash)
    VALUES (:nome, :plano, :doc_number, :cep, :rua, :numero, :complemento, :bairro,
            :cidade, :estado, :pais, :whatsapp_phone, :email, :password_hash)
    RETURNING id
    """)

    result = db.execute(sql, {
        "nome": full_name.strip(),  # ou se preferir "company_name"
        "plano": plan,
        "doc_number": doc_number.strip(),
        "cep": cep.strip(),
        "rua": rua.strip(),
        "numero": numero.strip(),
        "complemento": complemento.strip(),
        "bairro": bairro.strip(),
        "cidade": cidade.strip(),
        "estado": estado.strip(),
        "pais": pais.strip(),
        "whatsapp_phone": whatsapp_phone.strip(),
        "email": email.strip().lower(),
        "password_hash": hashed_pw
    })
    new_tenant_id = result.fetchone()[0]
    db.commit()

    # Armazena na sessão o ID do tenant
    request.session["tenant_id"] = str(new_tenant_id)

    return RedirectResponse("/dashboard", status_code=302)

#################
# LOGIN
#################

@app.get("/login")
def login_get():
    return render_page("login.html")

@app.post("/login")
def login_post(
    request: Request,
    db=Depends(get_db),
    email: str = Form(...),
    password: str = Form(...)
):
    # Carrega tenant
    # se tiverem muitos, seria melhor filtrar exato
    sql = text("SELECT id, password_hash FROM tenant WHERE email = :email")
    result = db.execute(sql, {"email": email.strip().lower()}).fetchone()

    if not result:
        return HTMLResponse("Usuário não encontrado", status_code=400)

    tenant_id, password_hash = result
    if not bcrypt.verify(password, password_hash):
        return HTMLResponse("Senha incorreta", status_code=400)

    request.session["tenant_id"] = str(tenant_id)
    return RedirectResponse("/dashboard", status_code=302)

@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/")

#################
# DASHBOARD
#################

@app.get("/dashboard")
def dashboard(request: Request, db=Depends(get_db)):
    tenant_id = request.session.get("tenant_id")
    if not tenant_id:
        return RedirectResponse("/login")

    # Carrega dados do tenant
    tenant_sql = text("SELECT id, nome, plano FROM tenant WHERE id = :tid")
    tenant_row = db.execute(tenant_sql, {"tid": tenant_id}).fetchone()
    if not tenant_row:
        request.session.clear()
        return RedirectResponse("/login")

    # Carrega feedbacks
    # Lembrando que a tabela 'feedback' tem: id, tenant_id, usuario_final, ...
    feedback_sql = text("""
    SELECT id, usuario_final, audio_url, transcript, sentimento, resumo
    FROM feedback
    WHERE tenant_id = :tid
    ORDER BY id DESC
    """)
    feedbacks = db.execute(feedback_sql, {"tid": tenant_id}).fetchall()

    total = len(feedbacks)
    positives = sum(1 for f in feedbacks if f.sentimento == "positivo")
    negatives = sum(1 for f in feedbacks if f.sentimento == "negativo")

    if total > 0:
        pos_percent = round((positives / total) * 100, 1)
        neg_percent = round((negatives / total) * 100, 1)
    else:
        pos_percent = 0
        neg_percent = 0

    feedback_html = ""
    for row in feedbacks:
        feedback_html += f"""
        <div class="feedback-item">
          <p><strong>De:</strong> {row.usuario_final or '-'} |
             <strong>Sentimento:</strong> {row.sentimento or '(pendente)'}
          </p>
          <p>Transcrição: {row.transcript or '(aguardando)'} </p>
          <hr/>
        </div>
        """

    # Montar link de feedback no WhatsApp
    # Se você quiser algo como /fb/<slug>, 
    # você precisa ter um "slug" no tenant ou outro campo
    # mas no script temos apenas "nome". Vamos usar 'nome' como base
    from urllib.parse import quote_plus
    # Exemplo: "Olá, obrigado..."
    msg = f"Olá, obrigado por ser cliente da {tenant_row.nome}! Envie seu áudio."
    link_whatsapp = f"https://wa.me/5599999999999?text={quote_plus(msg)}"

    # Monta HTML
    context = {
        "USER_NAME": tenant_row.nome,
        "PLAN": tenant_row.plano,
        "TOTAL_FEEDBACKS": str(total),
        "POSITIVE_PERCENT": str(pos_percent),
        "NEGATIVE_PERCENT": str(neg_percent),
        "FEEDBACK_LIST": feedback_html
    }
    html = render_page("dashboard.html", context)

    insert_str = f"""
    <p>Link de Feedback (WhatsApp):
       <input type="text" readonly value="{link_whatsapp}" style="width:100%; max-width:400px;">
    </p>
    """
    html = html.replace("<h3>Feedbacks Recebidos</h3>", insert_str + "<h3>Feedbacks Recebidos</h3>")

    return HTMLResponse(html)

#################
# TERMOS/POLÍTICA
#################

@app.get("/termos")
def termos_de_uso():
    return render_page("termos.html")

@app.get("/privacidade")
def politica_privacidade():
    return render_page("privacidade.html")

#################
# STRIPE WEBHOOK
#################

@app.post("/stripe-webhook")
async def stripe_webhook(request: Request, db=Depends(get_db)):
    if not STRIPE_WEBHOOK_SECRET:
        return {"status": "webhook not secure"}

    payload = await request.body()
    sig_header = request.headers.get("stripe-signature")
    import stripe
    try:
        event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
    except (ValueError, stripe.error.SignatureVerificationError) as e:
        print("[ERROR] Invalid Stripe signature", e)
        raise HTTPException(400, "Invalid signature")

    if event["type"] == "checkout.session.completed":
        sess = event["data"]["object"]
        temp_id_str = sess.get("client_reference_id")
        plan_str = sess.get("metadata", {}).get("plan", "")
        # Caso: se você quiser mapear "temp_id_str" p/ tenant, faça
        # ex.: "UPDATE tenant SET plano=? WHERE ???"
        # ou algo do tipo. Exemplo:
        print(f"[Stripe] Payment done. temp_id={temp_id_str}, plan={plan_str}")

    return {"status": "ok"}

#################
# WHATSAPP FLOW
#################

@app.get("/fb/{some_slug}")
def whatsapp_feedback_redirect(some_slug: str, db=Depends(get_db)):
    """
    Exemplo de rota se quiser usar /fb/<slug> para redirecionar.
    Mas seu schema "tenant" não tem 'slug' por default,
    a não ser que você adicione. Exemplo:
      CREATE TABLE tenant (..., slug TEXT UNIQUE, ...)
    """
    return HTMLResponse("Exemplo. Precisaria mapear slug -> tenant.")


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
async def receive_whatsapp(
    request: Request,
    background_tasks: BackgroundTasks,
    db=Depends(get_db)
):
    """
    Exemplo simplificado: se o user mandar audio, criamos feedback
    atrelado a um tenant fixo?
    Você ainda precisa descobrir 'qual tenant' esse audio pertence,
    possivelmente via RLS ou via match de texto, etc.
    """
    data = await request.json()
    print("[WhatsApp webhook]", data)
    try:
        # Exemplo: você poderia analisar 'messages' e ver se
        # eles contêm 'tenant' ou algo
        entry = data["entry"][0]
        changes = entry["changes"][0]
        value = changes["value"]
        messages = value.get("messages", [])

        for msg in messages:
            if msg.get("type") == "audio":
                media_id = msg["audio"]["id"]
                sender = msg["from"] or "???"

                # Necessário descobrir tenant_id. Supondo que
                # você tenha 1 tenant fixo ou algo do tipo:
                # ou procure pelo 'nome' do tenant no texto anterior.
                tenant_id = "SEU-UUID"  # substitua caso encontre do flux real.

                # Insere feedback
                sql = text("""
                INSERT INTO feedback (tenant_id, usuario_final, audio_url, sentimento, resumo, criado_em)
                VALUES (:tid, :usuario_final, :audio_url, 'pendente', '', now())
                RETURNING id
                """)
                result = db.execute(sql, {
                    "tid": tenant_id,
                    "usuario_final": sender,
                    "audio_url": f"(media_id={media_id})"
                })
                new_id = result.fetchone()[0]
                db.commit()

                # Optionally process in background
                background_tasks.add_task(process_feedback, new_id)

    except Exception as e:
        print("[ERROR] WhatsApp webhook exception:", e)

    return {"status": "ok"}

def process_feedback(feedback_id: int):
    """
    Exemplo de transcrição e análise
    """
    db_sess = SessionLocal()
    try:
        # Carregar feedback
        sql = text("SELECT id FROM feedback WHERE id=:fid")
        r = db_sess.execute(sql, {"fid": feedback_id}).fetchone()
        if not r:
            return

        # ex: transcrever e analisar
        # para simplificar
        upd = text("""
        UPDATE feedback
        SET transcript='Exemplo de transcrição', 
            sentimento='positivo', 
            resumo='resumo IA', 
            criado_em=now()
        WHERE id=:fid
        """)
        db_sess.execute(upd, {"fid": feedback_id})
        db_sess.commit()

    except Exception as err:
        print("[ERROR process_feedback]", err)
    finally:
        db_sess.close()
