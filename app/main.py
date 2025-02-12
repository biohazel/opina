import os
import requests
import stripe

from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.responses import PlainTextResponse

########################
#   CONFIGURAÇÃO FASTAPI
########################

app = FastAPI()

# Monta /static para servir arquivos do diretório app/static
app.mount("/static", StaticFiles(directory="app/static"), name="static")

# Variáveis de ambiente
WHATSAPP_VERIFY_TOKEN = os.getenv("WHATSAPP_VERIFY_TOKEN", "test")
ACCESS_TOKEN = os.getenv("WHATSAPP_ACCESS_TOKEN", "")
PHONE_NUMBER_ID = os.getenv("PHONE_NUMBER_ID", "")

STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")
DOMAIN_URL = os.getenv("DOMAIN_URL", "http://localhost:8000")

stripe.api_key = STRIPE_SECRET_KEY

# Sessão e dados fictícios
fake_users = {
    "user@example.com": {
        "password": "1234",
        "plan": "free"
    }
}
current_user = None  # Em produção, usar DB e tokens de autenticação

########################
#   FUNÇÃO DE RENDER
########################

def render_page(html_name: str, context: dict = None) -> HTMLResponse:
    """
    Lê um arquivo HTML de /app/templates/ e faz substituição de placeholders.
    Placeholder no HTML: {{CHAVE}}
    """
    file_path = os.path.join("app", "templates", html_name)
    with open(file_path, "r", encoding="utf-8") as f:
        html = f.read()
    if context:
        for key, val in context.items():
            # Substitui {{CHAVE}} pelo valor no HTML
            placeholder = f"{{{{{key}}}}}"  # vira '{{CHAVE}}'
            html = html.replace(placeholder, val)
    return HTMLResponse(content=html)

########################
#   ROTAS PRINCIPAIS
########################

@app.get("/")
def home():
    # home.html é estático, sem placeholders
    return render_page("home.html")

@app.post("/")
def do_subscribe(plan_id: str = Form(...)):
    global current_user
    if not current_user:
        return RedirectResponse("/login", status_code=302)
    fake_users[current_user]["plan"] = plan_id
    return RedirectResponse("/dashboard", status_code=302)

@app.get("/login")
def login_form():
    return render_page("login.html")

@app.post("/login")
def login(email: str = Form(...), password: str = Form(...)):
    global current_user
    user = fake_users.get(email)
    if user and user["password"] == password:
        current_user = email
        return RedirectResponse("/dashboard", status_code=302)
    return "Credenciais inválidas"

@app.get("/dashboard")
def dashboard():
    global current_user
    if not current_user:
        return RedirectResponse("/login", status_code=302)

    # Cria lista HTML
    feedbacks = [
        {"from_phone": "+551199999999", "transcript": "Excelente serviço!", "sentiment": "positivo"},
        {"from_phone": "+551188888888", "transcript": "Não gostei do atraso", "sentiment": "negativo"}
    ]
    feedbacks_html = ""
    for f in feedbacks:
        feedbacks_html += f"<li>De {f['from_phone']}: {f['transcript']} (Sentimento: {f['sentiment']})</li>"

    context = {
        "USER_EMAIL": current_user,
        "FEEDBACKS_LIST": feedbacks_html
    }
    return render_page("dashboard.html", context=context)

########################
#   STRIPE CHECKOUT
########################

@app.get("/checkout/{plan}")
def create_checkout_session(plan: str):
    if plan == "pro":
        amount_cents = 24900
        product_name = "Plano Pro"
    elif plan == "enterprise":
        amount_cents = 99900
        product_name = "Plano Enterprise"
    else:
        amount_cents = 0
        product_name = "Plano Free"

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
            success_url=f"{DOMAIN_URL}/success?session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=f"{DOMAIN_URL}/cancel",
        )
        return RedirectResponse(session.url)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/success")
def payment_success():
    return HTMLResponse("Pagamento concluído com sucesso! Volte ao /dashboard.")

@app.get("/cancel")
def payment_cancel():
    return HTMLResponse("Pagamento cancelado ou falhou. Tente novamente.")

@app.post("/stripe-webhook")
async def stripe_webhook(request: Request):
    if not STRIPE_WEBHOOK_SECRET:
        return {"status": "webhook not secure - set STRIPE_WEBHOOK_SECRET"}

    payload = await request.body()
    sig_header = request.headers.get("stripe-signature")

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid payload")
    except stripe.error.SignatureVerificationError:
        raise HTTPException(status_code=400, detail="Invalid signature")

    if event["type"] == "checkout.session.completed":
        session_obj = event["data"]["object"]
        print(f"Pagamento Stripe concluído. Sessão: {session_obj['id']}")
    return {"status": "ok"}

########################
#   WHATSAPP WEBHOOK
########################

@app.get("/webhook")
def verify_whatsapp(hub_mode: str = None, hub_challenge: str = None, hub_verify_token: str = None):
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
