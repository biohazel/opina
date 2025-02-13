import os
import requests
import stripe

from fastapi import FastAPI, Request, Form, HTTPException, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.responses import PlainTextResponse

# === SQLAlchemy Imports ===
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.orm import sessionmaker, declarative_base
from datetime import datetime

# === Passlib (bcrypt) ===
from passlib.hash import bcrypt

########################
# FASTAPI + STATIC
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

# Configura Stripe
stripe.api_key = STRIPE_SECRET_KEY

########################
# DB Setup
########################

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is not set")

engine = create_engine(DATABASE_URL, echo=False)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    plan = Column(String, default="free")
    created_at = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

########################
# Render Page Helper
########################

from fastapi.responses import HTMLResponse

def render_page(html_name: str, context: dict = None) -> HTMLResponse:
    path = os.path.join("app", "templates", html_name)
    with open(path, "r", encoding="utf-8") as f:
        html_content = f.read()
    if context:
        for key, val in context.items():
            placeholder = f"{{{{{key}}}}}"
            html_content = html_content.replace(placeholder, val)
    return HTMLResponse(content=html_content)

########################
# ROTAS
########################

@app.get("/")
def home():
    return render_page("home.html")

########################
# CHECKOUT: PRO / ENTERPRISE
########################

@app.get("/checkout/{plan}")
def create_checkout_session(plan: str):
    """
    Cria sessão do Stripe sem exigir login.
    Ao concluir, redireciona /onboarding?plan=pro&session_id=xxx
    """
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
            success_url=f"{DOMAIN_URL}/onboarding?plan={plan}&session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=f"{DOMAIN_URL}/cancel",
            metadata={
                "plan": plan
            }
        )
        return RedirectResponse(session.url)
    except Exception as e:
        raise HTTPException(400, str(e))

@app.get("/cancel")
def payment_cancel():
    return HTMLResponse("Pagamento cancelado. Tente novamente ou escolha outro plano.")

########################
# ONBOARDING
########################

@app.get("/onboarding")
def get_onboarding(plan: str = "free", session_id: str = ""):
    """
    Mostra formulário para criar user. 
    Ex.: /onboarding?plan=pro&session_id=cs_test_123...
    """
    context = {
        "PLAN": plan,
        "SESSION_ID": session_id
    }
    return render_page("onboarding.html", context)

@app.post("/onboarding")
def post_onboarding(
    plan: str = Form(...),
    session_id: str = Form(""),
    email: str = Form(...),
    password: str = Form(...),
    db=Depends(get_db)
):
    """
    Cria user no DB com 'plan' (que o user pagou).
    """
    # Hashea a senha
    hashed_pw = bcrypt.hash(password)
    # Cria e salva no DB
    new_user = User(email=email, password_hash=hashed_pw, plan=plan)
    db.add(new_user)
    db.commit()

    return RedirectResponse("/dashboard", status_code=302)

########################
# DASHBOARD
########################

@app.get("/dashboard")
def dashboard():
    return HTMLResponse(
        "Bem-vindo ao Dashboard! (Em produção, use login e associar user.)"
    )

########################
# STRIPE WEBHOOK
########################

@app.post("/stripe-webhook")
async def stripe_webhook(request: Request):
    """
    Se quiser usar o webhook p/ algo extra. 
    Aqui não atualizamos user porque criamos user depois do pagamento (onboarding).
    Mas se você quiser, use metadata e associe.
    """
    if not STRIPE_WEBHOOK_SECRET:
        return {"status": "webhook not secure"}

    payload = await request.body()
    sig_header = request.headers.get("stripe-signature")
    try:
        event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
    except (ValueError, stripe.error.SignatureVerificationError):
        raise HTTPException(400, "Invalid signature")

    if event["type"] == "checkout.session.completed":
        # Se quiser algo extra
        session_obj = event["data"]["object"]
        plan = session_obj["metadata"].get("plan")
        print(f"[StripeWebhook] Payment completed. Plan = {plan}")
    return {"status": "ok"}

########################
# (Opcional) FREE
########################

@app.get("/onboarding_free")
def onboarding_free():
    """
    Ou você pode mandar /onboarding?plan=free
    e no form 'plan=free'.
    """
    return "Implementar se quiser"

########################
#  WHATSAPP WEBHOOK (Opcional)
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
    body = await request.json()
    # ...
    return {"status": "ok"}
