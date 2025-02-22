import os
import re
import secrets
import unicodedata
import random
import stripe
import requests
import openai
import logging

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
# CONFIGURAÇÕES
###############

logging.basicConfig(level=logging.INFO)

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

# VARIÁVEIS DE AMBIENTE
WHATSAPP_VERIFY_TOKEN = os.getenv("WHATSAPP_VERIFY_TOKEN", "")
ACCESS_TOKEN = os.getenv("WHATSAPP_ACCESS_TOKEN", "")
PHONE_NUMBER_ID = os.getenv("PHONE_NUMBER_ID", "")  # ex: "500117826528082"

STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")
DOMAIN_URL = os.getenv("DOMAIN_URL", "https://opina.live")

DATABASE_URL = os.getenv("DATABASE_URL", "")

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
openai.api_key = OPENAI_API_KEY

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

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

###############
# Funções Auxiliares (Templates, Download, IA, Render)
###############

def render_page(file_name: str, context: dict = None) -> str:
    """
    Carrega o template HTML (ex: dashboard.html) e faz substituição manual de {{CHAVE}}.
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

def send_whatsapp_template(to_number: str, tenant_name: str):
    """
    Envia o template de mensagem do WhatsApp (ex: 'template_opina') que pede feedback.
    Substitui a variável {{1}} pelo nome da empresa.
    """
    if not (ACCESS_TOKEN and PHONE_NUMBER_ID):
        logging.warning("Faltam credenciais de WhatsApp. Não foi possível enviar template.")
        return

    url = f"https://graph.facebook.com/v16.0/{PHONE_NUMBER_ID}/messages"
    headers = {
        "Authorization": f"Bearer {ACCESS_TOKEN}",
        "Content-Type": "application/json"
    }
    payload = {
        "messaging_product": "whatsapp",
        "to": to_number,  # E.g. "5511999999999"
        "type": "template",
        "template": {
            "name": "template_opina",  # Ajuste para o nome do seu template
            "language": {"code": "pt_BR"},
            "components": [
                {
                    "type": "body",
                    "parameters": [
                        {
                            "type": "text",
                            "text": tenant_name  # isso preenche {{1}} no corpo
                        }
                    ]
                }
            ]
        }
    }
    try:
        resp = requests.post(url, json=payload, headers=headers, timeout=10)
        resp.raise_for_status()
        logging.info(f"Enviado template_opina para {to_number} (empresa: {tenant_name}).")
    except Exception as e:
        logging.error(f"Erro ao enviar template_opina -> {e}")

def download_whatsapp_media(media_id: str) -> bytes:
    """
    Dado um media_id do WhatsApp, retorna o conteúdo binário do áudio.
    """
    if not ACCESS_TOKEN:
        raise RuntimeError("ACCESS_TOKEN não configurado.")
    info_url = f"https://graph.facebook.com/v16.0/{media_id}"
    headers = {"Authorization": f"Bearer {ACCESS_TOKEN}"}

    # 1) Obter URL do arquivo
    resp_meta = requests.get(info_url, headers=headers, timeout=10)
    resp_meta.raise_for_status()
    info_json = resp_meta.json()
    file_url = info_json["url"]

    # 2) Baixar o arquivo binário
    file_resp = requests.get(file_url, headers=headers, timeout=30)
    file_resp.raise_for_status()
    return file_resp.content

def transcrever_audio_openai(audio_bytes: bytes) -> str:
    """
    Exemplo de transcrição usando a API Whisper da OpenAI.
    Se preferir Whisper local, substitua aqui.
    """
    import io
    audio_file = io.BytesIO(audio_bytes)
    audio_file.name = "arquivo.mp3"  # Nome fictício

    try:
        transcript_resp = openai.Audio.transcribe(
            model="whisper-1",
            file=audio_file,
            language="pt"
        )
        return transcript_resp["text"]
    except Exception as e:
        logging.error(f"[OpenAI Whisper] Erro na transcrição: {e}")
        return ""

def analisar_sentimento_chatgpt(texto: str) -> dict:
    """
    Exemplo de análise de sentimento e resumo com ChatGPT.
    Retorna {sentimento: "positivo/negativo/...", resumo: "..."}.
    """
    prompt = f"""
    1) Classifique o sentimento do feedback abaixo (positivo, negativo ou neutro).
    2) Resuma em 1 frase o ponto principal.

    Feedback: {texto}
    """
    try:
        resp = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": prompt}],
            temperature=0
        )
        content = resp.choices[0].message.content.strip()
        # Ex: "Sentimento: Positivo\nResumo: Cliente gostou muito..."
        sentimento = "desconhecido"
        resumo = ""

        for line in content.split("\n"):
            if "sentimento" in line.lower():
                sentimento = line.split(":")[-1].strip().lower()
            if "resumo" in line.lower():
                resumo = line.split(":")[-1].strip()

        return {"sentimento": sentimento, "resumo": resumo}
    except Exception as e:
        logging.error(f"[ChatGPT] Erro na análise: {e}")
        return {"sentimento": "erro", "resumo": ""}

###############
# Rotas Principais / Checkout / Onboarding
###############

@app.get("/")
def home():
    html_str = render_page("home.html")
    return HTMLResponse(html_str)

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
        logging.error(f"[ERROR] Checkout creation failed: {e}")
        raise HTTPException(400, str(e))

@app.get("/cancel")
def payment_cancel():
    return HTMLResponse("Pagamento cancelado. Tente novamente ou escolha outro plano.")

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

    # Salva ID do tenant na sessão
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
    Exibe as métricas e o link de WhatsApp para coleta de feedback.
    """
    tenant_id = request.session.get("tenant_id")
    if not tenant_id:
        return RedirectResponse("/login")

    # Carrega tenant
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
    # (Para simplificar, exibindo só usuario_final e sentimento)
    feedback_html = ""
    for r in fb_rows:
        feedback_html += f"<div class='feedback-item'>"
        feedback_html += f"<p><strong>{r.usuario_final or '-'}</strong> => {r.sentimento or '(pendente)'}</p>"
        feedback_html += "</div>"

    # Gerar link WhatsApp contendo "FEEDBACK_{tenant_id}"
    # Para identificar o tenant lá no webhook, quando o cliente mandar mensagem
    from urllib.parse import quote_plus
    # Ajuste seu número oficial do bot
    official_bot_number = "5566999999999"  # ex.: +5566999999999 (sem +)
    text_param = f"FEEDBACK_{tenant_id}"
    link_whatsapp = f"https://wa.me/{official_bot_number}?text={quote_plus(text_param)}"

    # Render
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

    # Seções FREE, PRO, ENTERPRISE
    free_section = ""
    pro_section = ""
    enterprise_section = ""
    if plan == "free":
        free_section = """
            <p style="color:#666; font-style:italic;">
              Você está no plano Free. Atualize para Pro ou Enterprise para ver estatísticas detalhadas e nuvem de palavras.
            </p>
        """
    elif plan == "pro":
        bar_pos = int(pos_percent * 2)
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
        enterprise_section = """
          <div style="border:1px solid #ddd; padding:1rem; margin:1rem 0; background:#eef;">
            <h3>Nuvem de Palavras Avançada</h3>
            <img src="/static/wordcloud_example.png" alt="Nuvem de Palavras" style="max-width:300px;">
            <p>Aqui exibimos a Nuvem de Palavras gerada pela IA, destacando termos-chave 
               que aparecem nos feedbacks.</p>
          </div>
        """

    # Injeta as seções no HTML
    html_str = html_str.replace("{{FREE_SECTION}}", free_section)
    html_str = html_str.replace("{{PRO_SECTION}}", pro_section)
    html_str = html_str.replace("{{ENTERPRISE_SECTION}}", enterprise_section)

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
        logging.info(f"[Stripe] Payment done. temp_id={temp_id_str} plan={plan}")
        # Ajustar se quiser atualizar tenant etc.

    return {"status": "ok"}

###############
# WHATSAPP WEBHOOK (Recebe Mensagens)
###############

@app.get("/webhook")
def verify_whatsapp(
    hub_mode: str = None,
    hub_challenge: str = None,
    hub_verify_token: str = None
):
    """
    Verifica a assinatura do webhook do WhatsApp.
    """
    if hub_verify_token == WHATSAPP_VERIFY_TOKEN:
        return PlainTextResponse(hub_challenge or "")
    raise HTTPException(403, "Invalid verify token")

@app.post("/webhook")
async def receive_whatsapp(request: Request, background_tasks: BackgroundTasks, db=Depends(get_db)):
    """
    Recebe mensagens de WhatsApp. Se detecta "FEEDBACK_{tenant_id}" em msg de texto,
    envia template de pedido de áudio. Se recebe áudio, processa.
    """
    data = await request.json()
    logging.info(f"[WhatsApp webhook] {data}")

    try:
        entry = data["entry"][0]
        changes = entry["changes"][0]
        value = changes["value"]
        messages = value.get("messages", [])

        for msg in messages:
            from_number = msg.get("from")  # Ex.: "5566999888777"
            msg_type = msg.get("type")

            # Se for texto, checa se é "FEEDBACK_{tenant_id}"
            if msg_type == "text":
                text_body = msg["text"]["body"]
                match = re.search(r"FEEDBACK_([0-9a-fA-F\-]{36})", text_body)  # ID UUID
                if match:
                    found_tenant_id = match.group(1)

                    # Carrega tenant
                    row_tenant = db.execute(
                        text("SELECT id, nome FROM tenant WHERE id = :tid"),
                        {"tid": found_tenant_id}
                    ).fetchone()
                    if row_tenant:
                        # Envia template com a variável = nome do tenant
                        send_whatsapp_template(from_number, row_tenant.nome)

                        # Opcional: guardar "phone -> tenant" numa tabela, p/ usarmos quando chegar áudio
                        db.execute(
                            text("INSERT INTO phone_map (phone, tenant_id) VALUES (:p, :t)")
                            .on_conflict_do_nothing(index_elements=["phone"]),
                            {"p": from_number, "t": found_tenant_id}
                        )
                        db.commit()

            # Se for áudio, processa
            elif msg_type == "audio":
                media_id = msg["audio"]["id"]

                # Descobrir tenant_id a partir do "phone_map"
                row_map = db.execute(
                    text("SELECT tenant_id FROM phone_map WHERE phone = :p"),
                    {"p": from_number}
                ).fetchone()
                tenant_id = None
                if row_map:
                    tenant_id = row_map.tenant_id

                if not tenant_id:
                    logging.warning(f"Nenhum tenant vinculado ao phone={from_number}, usando fallback.")
                    tenant_id = "MEU-UUID-FIXO"  # Ajuste se quiser um fallback

                # Inserir feedback pendente
                sql_insert = text("""
                INSERT INTO feedback (tenant_id, usuario_final, audio_url, sentimento, resumo, criado_em)
                VALUES (:tid, :usr_final, :audio_url, 'pendente', '', now())
                RETURNING id
                """)
                result = db.execute(sql_insert, {
                    "tid": tenant_id,
                    "usr_final": from_number,
                    "audio_url": f"media_id={media_id}"
                })
                new_id = result.fetchone()[0]
                db.commit()

                # Processar em background
                background_tasks.add_task(process_feedback_pipeline, new_id)

    except Exception as e:
        logging.error(f"[WhatsApp webhook error] {e}")

    return {"status": "ok"}

def process_feedback_pipeline(feedback_id: int):
    """
    Pipeline para:
      - Baixar áudio do WhatsApp
      - Transcrever com Whisper (OpenAI)
      - Analisar com ChatGPT
      - Atualizar DB
    """
    db_sess = SessionLocal()
    try:
        # Carrega info do feedback
        row = db_sess.execute(
            text("SELECT id, audio_url FROM feedback WHERE id=:fid"),
            {"fid": feedback_id}
        ).fetchone()
        if not row:
            return

        audio_info = row.audio_url  # ex: "media_id=XXXXXXXX"
        match = re.search(r"media_id=(\w+)", audio_info)
        if not match:
            logging.warning(f"media_id não encontrado em audio_url: {audio_info}")
            return

        media_id = match.group(1)

        # 1) Baixar áudio
        audio_bytes = download_whatsapp_media(media_id)
        if not audio_bytes:
            logging.warning("Falha ao baixar mídia do WhatsApp.")
            return

        # 2) Transcrever
        transcript = transcrever_audio_openai(audio_bytes)

        # 3) Analisar sentimento
        analysis = analisar_sentimento_chatgpt(transcript)
        sentimento = analysis["sentimento"]
        resumo = analysis["resumo"]

        # 4) Atualizar feedback
        db_sess.execute(
            text("""
                UPDATE feedback
                SET transcript=:t, sentimento=:s, resumo=:r
                WHERE id=:fid
            """),
            {"t": transcript, "s": sentimento, "r": resumo, "fid": feedback_id}
        )
        db_sess.commit()

        logging.info(f"[Feedback {feedback_id}] Processado. Sentimento={sentimento}.")

    except Exception as err:
        logging.error(f"[process_feedback_pipeline] {err}")
    finally:
        db_sess.close()
