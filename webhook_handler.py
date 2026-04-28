"""
webhook_handler.py — Gumroad Ping receiver + Zoho SMTP welcome email
Mounts as: POST /webhook/gumroad

Required .env additions:
    ZOHO_SMTP_PASSWORD=your_zoho_app_password
    GUMROAD_SELLER_ID=4vvocap48GCTH3gv50FY1A==
    ZOHO_SMTP_HOST=smtp.zoho.in        # default for India accounts
"""

import logging
import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from fastapi import Request, Response
from fastapi.routing import APIRouter

log = logging.getLogger("medscribe.webhook")

router = APIRouter()

ZOHO_FROM = "contact@medscribepro.in"
ZOHO_SMTP_HOST = os.getenv("ZOHO_SMTP_HOST", "smtp.zoho.in")
ZOHO_SMTP_PORT = 465
ZOHO_SMTP_PASSWORD = os.getenv("ZOHO_SMTP_PASSWORD", "")
GUMROAD_SELLER_ID = os.getenv("GUMROAD_SELLER_ID", "")

EMAIL_SUBJECT = "Your MedScribe RCM-MCP Access — Setup Instructions"

EMAIL_BODY = """\
Hi {buyer_name},

Thank you for subscribing to MedScribe RCM-MCP. Your access is being prepared.

Your personal JWT token will be emailed to you within 24 hours at the address \
you used to purchase.

While you wait:
- Bookmark your server: https://mcp.medscribepro.in/health
- Questions? Reply to this email or write to contact@medscribepro.in

────────────────────────────────
CONNECT TO CLAUDE DESKTOP
────────────────────────────────
Once you receive your token, add this to your Claude Desktop config file:

  Windows : %APPDATA%\\Claude\\claude_desktop_config.json
  Mac     : ~/Library/Application Support/Claude/claude_desktop_config.json

Add inside "mcpServers":

  "medscribe-rcm": {{
    "url": "https://mcp.medscribepro.in/mcp",
    "headers": {{
      "Authorization": "Bearer YOUR_TOKEN_HERE"
    }}
  }}

Restart Claude Desktop and you will see all 4 RCM tools ready to use.

────────────────────────────────
SUPPORT
────────────────────────────────
Email   : contact@medscribepro.in
Response: within 24 hours

We are glad to have you.

A. Joel Enoch
MedScribe Professional Resources
Warangal, Telangana, India
https://mcp.medscribepro.in
"""


def _send_welcome_email(to_address: str, buyer_name: str) -> None:
    """Send welcome email via Zoho SMTP (SSL, port 465)."""
    msg = MIMEMultipart("alternative")
    msg["Subject"] = EMAIL_SUBJECT
    msg["From"] = ZOHO_FROM
    msg["To"] = to_address
    msg.attach(MIMEText(EMAIL_BODY.format(buyer_name=buyer_name), "plain"))

    with smtplib.SMTP_SSL(ZOHO_SMTP_HOST, ZOHO_SMTP_PORT) as smtp:
        smtp.login(ZOHO_FROM, ZOHO_SMTP_PASSWORD)
        smtp.sendmail(ZOHO_FROM, to_address, msg.as_string())

    log.info("welcome_email_sent to=%s", to_address)


@router.post("/webhook/gumroad")
async def gumroad_ping(request: Request) -> Response:
    """
    Receives Gumroad Ping (application/x-www-form-urlencoded or JSON).
    Validates seller_id, then sends welcome email to the buyer.
    """
    content_type = request.headers.get("content-type", "")

    if "application/json" in content_type:
        data = await request.json()
    else:
        form = await request.form()
        data = dict(form)

    # Validate this ping is genuinely from our Gumroad account
    if not GUMROAD_SELLER_ID:
        log.error("GUMROAD_SELLER_ID not set — rejecting ping")
        return Response(status_code=500)

    seller_id = data.get("seller_id", "")
    if seller_id != GUMROAD_SELLER_ID:
        log.warning("ping_rejected invalid seller_id=%s", seller_id)
        return Response(status_code=403)

    buyer_email = data.get("email", "")
    buyer_name = data.get("full_name") or data.get("purchaser_id", "Customer")

    if not buyer_email:
        log.warning("ping_missing_email data=%s", list(data.keys()))
        return Response(status_code=400)

    if not ZOHO_SMTP_PASSWORD:
        log.error("ZOHO_SMTP_PASSWORD not set — cannot send email")
        return Response(status_code=500)

    try:
        _send_welcome_email(buyer_email, buyer_name)
    except Exception as exc:
        log.exception("welcome_email_failed to=%s error=%s", buyer_email, exc)
        return Response(status_code=500)

    return Response(status_code=200)