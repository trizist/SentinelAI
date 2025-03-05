from typing import List, Dict, Any
import aiosmtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from jinja2 import Environment, PackageLoader, select_autoescape
from app.core.config import settings
import logging

logger = logging.getLogger(__name__)

class EmailService:
    def __init__(self):
        self.jinja_env = Environment(
            loader=PackageLoader('app', 'templates/email'),
            autoescape=select_autoescape(['html', 'xml'])
        )

    async def send_email(
        self,
        email_to: str,
        subject: str,
        template_name: str,
        template_data: Dict[str, Any]
    ) -> bool:
        """Send an email using the specified template"""
        try:
            # Create message
            message = MIMEMultipart()
            message["From"] = f"{settings.EMAILS_FROM_NAME} <{settings.EMAILS_FROM_EMAIL}>"
            message["To"] = email_to
            message["Subject"] = subject

            # Render template
            template = self.jinja_env.get_template(f"{template_name}.html")
            html_content = template.render(**template_data)
            message.attach(MIMEText(html_content, "html"))

            # Send email
            await aiosmtplib.send(
                message,
                hostname=settings.SMTP_HOST,
                port=settings.SMTP_PORT,
                username=settings.SMTP_USER,
                password=settings.SMTP_PASSWORD,
                use_tls=settings.SMTP_TLS,
            )
            
            logger.info(f"Email sent successfully to {email_to}")
            return True
        except Exception as e:
            logger.error(f"Failed to send email to {email_to}: {str(e)}")
            return False

    async def send_threat_alert(
        self,
        email_to: str,
        threat_data: Dict[str, Any]
    ) -> bool:
        """Send a threat alert email"""
        return await self.send_email(
            email_to=email_to,
            subject=f"Security Alert: {threat_data['severity']} Threat Detected",
            template_name="threat_alert",
            template_data=threat_data
        )

    async def send_incident_report(
        self,
        email_to: str,
        incident_data: Dict[str, Any]
    ) -> bool:
        """Send an incident report email"""
        return await self.send_email(
            email_to=email_to,
            subject=f"Incident Report: {incident_data['id']}",
            template_name="incident_report",
            template_data=incident_data
        )
