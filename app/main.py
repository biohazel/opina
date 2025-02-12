import os
import requests
import stripe

from fastapi import FastAPI, Request, Form, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.responses import PlainTextResponse

# ====== INICIALIZAÇÃO FASTAPI E TEMPLATES ======
app = FastAPI()
templates = Jinja2Templates(directory="app/templates")

# ====== CHAVES DE CONFIGURAÇÃO ======
VERIFY_TOKEN = os.getenv("WHATSAPP_VERIFY_TOKEN", "test")
ACCESS_TOKEN = os.getenv("WHATSAPP_ACCESS_TOKEN", "")
PHONE_NUMBER_ID = os.getenv("PHONE_NUMBER_ID", "")

# Stripe
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "")  # ex.: "sk_test_..."
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")  # gerado no painel
stripe.api_key = STRIPE_SECRET_KEY

# Simulação de sessão do usuário
fake_users = {"user@example.com": {"password": "1234", "plan": "free"}}
current_user = None  # Em produção, usar DB e tokens/jwt etc.


# =====================================================
#                   ROTAS PRINCIPAIS
# =====================================================

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    """Renderiza a página inicial (hero + planos)."""
    return templates.TemplateResponse("home.html", {"request": request})

@app.post("/", response_class=HTMLResponse)
def do_subscribe(plan_id: str = Form(...)):
    """
    Trata a escolha de plano via POST na mesma rota "/".
    Se o usuário não estiver logado, redireciona para /login.
    Se estiver logado, atualiza o plano e redireciona para /dashboard.
    """
    global current_user
    if not current_user:
        return RedirectResponse("/login", status_code=302)
    fake_users[current_user]["plan"] = plan_id
    return RedirectResponse("/dashboard", status_code=302)


@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login")
def login(email: str = Form(...), password: str = Form(...)):
    global current_user
    user = fake_users.get(email)
    if user and user["password"] == password:
        current_user = email
        return RedirectResponse("/dashboard", status_code=302)
    return "Credenciais inválidas"


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    global current_user
    if not current_user:
        return RedirectResponse("/login", status_code=302)
    # Exemplo de "feedbacks" fictícios
    feedbacks = [
        {"from_phone": "+551199999999", "transcript": "Excelente serviço!", "sentiment": "positivo"},
        {"from_phone": "+551188888888", "transcript": "Não gostei do atraso", "sentiment": "negativo"}
    ]
    return templates.TemplateResponse(
        "dashboard.html",
        {"request": request, "feedbacks": feedbacks, "user_email": current_user}
    )


# =====================================================
#                STRIPE CHECKOUT E WEBHOOK
# =====================================================

@app.get("/checkout/{plan}", response_class=HTMLResponse)
def create_checkout_session(plan: str):
    """
    Cria uma sessão de checkout no Stripe para o 'plan' especificado.
    Exemplo: /checkout/pro ou /checkout/enterprise
    Permite cartão de crédito e Pix.
    """
    # Defina valores em centavos (R$249 => 24900)
    if plan == "pro":
        amount_cents = 24900
        product_name = "Plano Pro"
    elif plan == "enterprise":
        amount_cents = 99900
        product_name = "Plano Enterprise"
    else:
        amount_cents = 0
        product_name = "Plano Free"

    # Ajuste para o seu domínio real ou para "http://localhost:8000"
    domain = os.getenv("DOMAIN_URL", "http://localhost:8000")

    try:
        session = stripe.checkout.Session.create(
            payment_method_types=["card", "pix"],  # Aceita cartão e Pix
            line_items=[{
                "price_data": {
                    "currency": "brl",
                    "product_data": {
                        "name": product_name
                    },
                    "unit_amount": amount_cents
                },
                "quantity": 1,
            }],
            mode="payment",
            success_url=f"{domain}/success?session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=f"{domain}/cancel",
        )
        return RedirectResponse(session.url)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/success", response_class=HTMLResponse)
def payment_success(request: Request):
    """
    Rota de retorno quando o pagamento for concluído (Stripe success_url).
    Normalmente você mostraria uma página "obrigado" e atualizaria o plano.
    """
    return "Pagamento concluído com sucesso! Você pode voltar ao /dashboard."


@app.get("/cancel", response_class=HTMLResponse)
def payment_cancel(request: Request):
    """Rota de retorno se o cliente cancelar ou falhar o pagamento."""
    return "Pagamento cancelado. Tente novamente ou escolha outro plano."


@app.post("/stripe-webhook")
async def stripe_webhook(request: Request):
    """
    Webhook que recebe notificações de pagamento do Stripe.
    Precisamos validar a assinatura e processar o evento.
    """
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature")

    if not STRIPE_WEBHOOK_SECRET:
        # Se não tivermos um webhook secret configurado,
        # só vamos retornar OK (não seguro em produção).
        return {"status": "webhook not secure - set STRIPE_WEBHOOK_SECRET"}

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, STRIPE_WEBHOOK_SECRET
        )
    except ValueError:
        # Invalid payload
        raise HTTPException(status_code=400, detail="Invalid payload")
    except stripe.error.SignatureVerificationError:
        # Invalid signature
        raise HTTPException(status_code=400, detail="Invalid signature")

    # Processar o evento
    if event["type"] == "checkout.session.completed":
        session = event["data"]["object"]
        payment_status = session.get("payment_status")  # 'paid'
        # Aqui você pode atualizar seu banco para registrar que o user pagou,
        # caso você tenha guardado user_id no 'metadata' da Session.
        print(f"Pagamento Stripe concluído. ID da sessão: {session['id']}. Status: {payment_status}")

    return {"status": "ok"}


# =====================================================
#         WHATSAPP WEBHOOK (META / AUDIO ETC.)
# =====================================================

@app.get("/webhook")
def verify_whatsapp(
    hub_mode: str = None, 
    hub_challenge: str = None,
    hub_verify_token: str = None
):
    if hub_verify_token == VERIFY_TOKEN:
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
                    # (chamar whisper, LLM, etc.)
                    send_whatsapp_message(from_phone, "Seu áudio foi processado!")
    return {"status": "ok"}


# ========== FUNÇÕES AUXILIARES WHATSAPP ==========

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
