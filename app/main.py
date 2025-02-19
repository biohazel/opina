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
# Helpers
###############

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def render_page(file_name: str, context: dict = None) -> str:
    """
    Carrega o template HTML (ex: dashboard.html) e faz substituição manual de {{CHAVE}}.
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
    return html

###############
# Rotas Principais
###############

@app.get("/")
def home():
    html_str = render_page("home.html")
    return HTMLResponse(html_str)

###############
# CHECKOUT
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
    return HTMLResponse("Pagamento cancelado. Tente novamente ou escolha outro plano.")

###############
# ONBOARDING
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
# LOGIN / LOGOUT
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
# DASHBOARD
###############

@app.get("/dashboard")
def dashboard(request: Request, db=Depends(get_db)):
    """
    Dashboard multi-nível:
      - FREE: exibe teaser, sem gráficos
      - PRO: exibe minigráfico e insight
      - ENTERPRISE: exibe tudo do Pro + algo extra (ex: Nuvem de Palavras)
    """
    tenant_id = request.session.get("tenant_id")
    if not tenant_id:
        return RedirectResponse("/login")

    from sqlalchemy import text
    # Carrega tenant (nome, plano)
    sql_tenant = text("SELECT id, nome, plano FROM tenant WHERE id = :tid")
    row_tenant = db.execute(sql_tenant, {"tid": tenant_id}).fetchone()
    if not row_tenant:
        request.session.clear()
        return RedirectResponse("/login")

    tenant_name = row_tenant.nome
    plan = row_tenant.plano

    # Carrega feedbacks
    sql_fb = text("""
    SELECT usuario_final, sentimento
    FROM feedback
    WHERE tenant_id = :tid
    """)
    fb_rows = db.execute(sql_fb, {"tid": tenant_id}).fetchall()

    total = len(fb_rows)
    positives = sum(1 for r in fb_rows if r.sentimento == "positivo")
    negatives = sum(1 for r in fb_rows if r.sentimento == "negativo")

    if total > 0:
        pos_percent = round((positives / total) * 100, 1)
        neg_percent = round((negatives / total) * 100, 1)
    else:
        pos_percent = 0
        neg_percent = 0

    # Classes CSS para cor
    pos_class = "positive" if pos_percent >= 50 else ""
    neg_class = "negative" if neg_percent >= 50 else ""

    # Monta listagem feedback
    feedback_html = ""
    for r in fb_rows:
        feedback_html += f"<p>{r.usuario_final or '-'} => {r.sentimento or '(pendente)'}</p>"

    # Monta link de feedback via WhatsApp
    from urllib.parse import quote_plus
    msg = f"Olá, obrigado por ser cliente da {tenant_name}! Envie seu áudio..."
    link_whatsapp = f"https://wa.me/5599999999999?text={quote_plus(msg)}"

    # SEÇÕES adicionais, dependendo do plano
    free_section = ""
    pro_section = ""
    enterprise_section = ""

    if plan == "free":
        free_section = """
          <p style="color:#666; font-style:italic;">
            Você está no plano Free. Atualize para Pro ou Enterprise para ver estatísticas detalhadas 
            e nuvem de palavras.
          </p>
        """
    elif plan == "pro":
        # Exemplo de um mini-gráfico (de barras) de sentimento + insights
        bar_pos = int(pos_percent * 2)  # escala de 2 px
        bar_neg = int(neg_percent * 2)
        pro_section = f"""
          <div style="border:1px solid #ddd; padding:1rem; margin:1rem 0; background:#f9f9f9;">
            <h3>Insights de IA (Plano Pro)</h3>
            <p>Abaixo um pequeno gráfico de sentimento:</p>
            <div style="display:flex; gap:1rem; align-items:flex-end;">
              <div style="width:30px; height:{bar_pos}px; background:green;"></div>
              <div style="width:30px; height:{bar_neg}px; background:red;"></div>
            </div>
            <p>Verde = % Positivo, Vermelho = % Negativo</p>
          </div>
        """
    elif plan == "enterprise":
        bar_pos = int(pos_percent * 2)
        bar_neg = int(neg_percent * 2)
        pro_section = f"""
          <div style="border:1px solid #ddd; padding:1rem; margin:1rem 0; background:#f9f9f9;">
            <h3>Insights de IA (Plano Enterprise)</h3>
            <p>Gráfico de barras do sentimento:</p>
            <div style="display:flex; gap:1rem; align-items:flex-end;">
              <div style="width:30px; height:{bar_pos}px; background:green;"></div>
              <div style="width:30px; height:{bar_neg}px; background:red;"></div>
            </div>
            <p>Verde = % positivo, Vermelho = % negativo</p>
          </div>
        """
        # Algo extra no enterprise, ex: wordcloud
        enterprise_section = """
          <div style="border:1px solid #ddd; padding:1rem; margin:1rem 0; background:#eef;">
            <h3>Nuvem de Palavras Avançada</h3>
            <img src="/static/wordcloud_example.png" alt="Nuvem de Palavras" style="max-width:300px;">
            <p>Aqui exibimos a Nuvem de Palavras gerada pela IA, destacando termos-chave 
               que aparecem nos feedbacks.</p>
          </div>
        """

    # Monta HTML base (ver dashboard.html)
    html_str = render_page("dashboard.html", {
        "USER_NAME": tenant_name,
        "PLAN": plan,
        "TOTAL_FEEDBACKS": str(total),
        "POSITIVE_PERCENT": str(pos_percent),
        "NEGATIVE_PERCENT": str(neg_percent),
        "POS_CLASS": pos_class,
        "NEG_CLASS": neg_class,
        "FEEDBACK_LIST": feedback_html,
        "WHATSAPP_LINK": link_whatsapp
    })

    # Injeta seções
    html_str = html_str.replace("{{FREE_SECTION}}", free_section)
    html_str = html_str.replace("{{PRO_SECTION}}", pro_section)
    html_str = html_str.replace("{{ENTERPRISE_SECTION}}", enterprise_section)

    # Classes CSS p/ cor no dashboard
    # (Se seu dashboard.html usa algo como <span class="{{POS_CLASS}}">, 
    #  as classes .positive {color:green} e .negative {color:red} podem estar no styles.css)

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
# STRIPE WEBHOOK
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

                tenant_id = "MEU-UUID"  # Ajuste a forma de encontrar tenant.
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
