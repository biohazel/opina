import os
import re
import secrets
import unicodedata
import random
import stripe

from fastapi import FastAPI, Request, Form, HTTPException, Depends, BackgroundTasks, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.responses import PlainTextResponse
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request
from typing import Optional
from datetime import datetime, timedelta

from sqlalchemy import create_engine, text, BigInteger
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.dialects.postgresql import UUID
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

# Stripe
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
# Se quiser classes ORM, defina aqui (Tenant, Feedback...) 
# ou use queries text() direto
###############

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def render_page(file_name: str, context: dict = None) -> str:
    """
    Carrega o template HTML e faz substituição manual de {{CHAVE}}.
    Retorna a string pura (SEM ser HTMLResponse ainda).
    """
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
            html = html.replace(f"{{{{{k}}}}}", str(v if v else ""))
    return html  # devolve string normal

###############
# Rotas
###############

@app.get("/")
def home():
    html_str = render_page("home.html")
    return HTMLResponse(html_str)

###############
# Checkout
###############

@app.get("/checkout/{plan}")
def checkout(plan: str):
    if plan == "pro":
        amount_cents = 24900
        product_name = "Plano Pro"
    elif plan == "enterprise":
        amount_cents = 99900
        product_name = "Plano Enterprise"
    else:
        raise HTTPException(400, "Plano inválido")

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
    return HTMLResponse("Pagamento cancelado. Tente novamente.")

###############
# Onboarding
###############

@app.get("/onboarding")
def onboarding_get(plan: str = "free", temp_id: str = "", session_id: str = ""):
    context = {
        "PLAN": plan,
        "TEMP_ID": temp_id,
        "SESSION_ID": session_id
    }
    html_str = render_page("onboarding.html", context)
    return HTMLResponse(html_str)

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
    temp_id: str = Form(""),
    session_id: str = Form("")
):
    hashed_pw = bcrypt.hash(password)

    # Insert no tenant
    from sqlalchemy import text
    sql = text("""
    INSERT INTO tenant (
      nome, plano, doc_number, cep, rua, numero, complemento, bairro,
      cidade, estado, pais, whatsapp_phone, email, password_hash
    )
    VALUES (
      :nome, :plano, :doc_number, :cep, :rua, :numero, :complemento, :bairro,
      :cidade, :estado, :pais, :whatsapp_phone, :email, :password_hash
    )
    RETURNING id
    """)

    result = db.execute(sql, {
        "nome": full_name.strip(),
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
    new_id = result.fetchone()[0]
    db.commit()

    request.session["tenant_id"] = str(new_id)
    return RedirectResponse("/dashboard", status_code=302)

###############
# Login
###############

@app.get("/login")
def login_get():
    html_str = render_page("login.html")
    return HTMLResponse(html_str)

@app.post("/login")
def login_post(
    request: Request,
    db=Depends(get_db),
    email: str = Form(...),
    password: str = Form(...)
):
    from sqlalchemy import text
    sql = text("SELECT id, password_hash FROM tenant WHERE email=:email")
    row = db.execute(sql, {"email": email.strip().lower()}).fetchone()

    if not row:
        return HTMLResponse("Usuário não encontrado.", status_code=400)

    tenant_id, pass_hash = row
    if not bcrypt.verify(password, pass_hash):
        return HTMLResponse("Senha incorreta.", status_code=400)

    request.session["tenant_id"] = str(tenant_id)
    return RedirectResponse("/dashboard", status_code=302)

@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/")

###############
# Dashboard
###############

@app.get("/dashboard")
def dashboard(request: Request, db=Depends(get_db)):
    tenant_id = request.session.get("tenant_id")
    if not tenant_id:
        return RedirectResponse("/login")

    from sqlalchemy import text
    # Carrega tenant
    sql_tenant = text("SELECT id, nome, plano FROM tenant WHERE id = :tid")
    tenant_row = db.execute(sql_tenant, {"tid": tenant_id}).fetchone()
    if not tenant_row:
        request.session.clear()
        return RedirectResponse("/login")

    # Carrega feedback
    sql_fb = text("""
    SELECT id, usuario_final, audio_url, transcript, sentimento, resumo
    FROM feedback
    WHERE tenant_id = :tid
    ORDER BY id DESC
    """)
    feedbacks = db.execute(sql_fb, {"tid": tenant_id}).fetchall()

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
    for f in feedbacks:
        feedback_html += f"""
        <div class="feedback-item">
          <p><strong>De:</strong> {f.usuario_final or '-'} |
             <strong>Sentimento:</strong> {f.sentimento or '(pendente)'}
          </p>
          <p>Transcrição: {f.transcript or '(aguardando)'} </p>
          <hr/>
        </div>
        """

    context = {
        "USER_NAME": tenant_row.nome,
        "PLAN": tenant_row.plano,
        "TOTAL_FEEDBACKS": str(total),
        "POSITIVE_PERCENT": str(pos_percent),
        "NEGATIVE_PERCENT": str(neg_percent),
        "FEEDBACK_LIST": feedback_html
    }
    html_str = render_page("dashboard.html", context)

    # Adiciona link p/ WhatsApp
    from urllib.parse import quote_plus
    msg = f"Olá, obrigado por ser cliente da {tenant_row.nome}! Envie seu áudio."
    link_whatsapp = f"https://wa.me/5599999999999?text={quote_plus(msg)}"

    insert_str = f"""
    <p>Link de Feedback (WhatsApp):
       <input type="text" readonly value="{link_whatsapp}" style="width:100%; max-width:400px;">
    </p>
    """
    # Manipular a string
    html_str = html_str.replace("<h3>Feedbacks Recebidos</h3>", insert_str + "<h3>Feedbacks Recebidos</h3>")

    return HTMLResponse(html_str)

###############
# Termos / Privacidade
###############

@app.get("/termos")
def termos_de_uso():
    html_str = render_page("termos.html")
    return HTMLResponse(html_str)

@app.get("/privacidade")
def politica_privacidade():
    html_str = render_page("privacidade.html")
    return HTMLResponse(html_str)

###############
# Stripe Webhook
###############

@app.post("/stripe-webhook")
async def stripe_webhook(request: Request):
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
        plan = sess.get("metadata", {}).get("plan", "")
        print(f"[Stripe] Payment done. temp_id={temp_id_str} plan={plan}")
        # Ajustar se quiser atualizar tenant etc.

    return {"status": "ok"}

###############
# WhatsApp
###############

@app.get("/webhook")
def verify_whatsapp(hub_mode: str = None, hub_challenge: str = None, hub_verify_token: str = None):
    if hub_verify_token == WHATSAPP_VERIFY_TOKEN:
        return PlainTextResponse(hub_challenge or "")
    raise HTTPException(403, "Invalid verify token")

@app.post("/webhook")
async def receive_whatsapp(request: Request, background_tasks: BackgroundTasks, db=Depends(get_db)):
    data = await request.json()
    print("[WhatsApp webhook]", data)
    try:
        entry = data["entry"][0]
        changes = entry["changes"][0]
        value = changes["value"]
        messages = value.get("messages", [])

        for msg in messages:
            if msg.get("type") == "audio":
                media_id = msg["audio"]["id"]
                sender = msg["from"] or "???"

                # Necessário descobrir tenant_id de fato
                # Exemplo fixo:
                tenant_id = "MEU-UUID"  # Ajuste
                sql_insert = text("""
                INSERT INTO feedback (tenant_id, usuario_final, audio_url, sentimento, resumo, criado_em)
                VALUES (:tid, :usr_final, :audio_url, 'pendente', '', now())
                RETURNING id
                """)
                result = db.execute(sql_insert, {
                    "tid": tenant_id,
                    "usr_final": sender,
                    "audio_url": f"(media_id={media_id})"
                })
                new_id = result.fetchone()[0]
                db.commit()

                background_tasks.add_task(process_feedback, new_id)

    except Exception as e:
        print("[ERROR] WhatsApp webhook:", e)

    return {"status": "ok"}

def process_feedback(feedback_id: int):
    db_sess = SessionLocal()
    try:
        sql_sel = text("SELECT id FROM feedback WHERE id=:fid")
        row = db_sess.execute(sql_sel, {"fid": feedback_id}).fetchone()
        if not row:
            return

        # Exemplo: analisando
        sql_up = text("""
        UPDATE feedback
        SET transcript='Exemplo de transcrição via IA',
            sentimento='positivo',
            resumo='resumo da IA',
            criado_em=now()
        WHERE id=:fid
        """)
        db_sess.execute(sql_up, {"fid": feedback_id})
        db_sess.commit()

    except Exception as err:
        print("[ERROR process_feedback]", err)
    finally:
        db_sess.close()
