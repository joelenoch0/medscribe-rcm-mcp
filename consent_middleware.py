# consent_middleware.py
import os

# Demo tokens — only active when MEDSCRIBE_ENV != "production"
_DEMO_TOKENS = {"TEST001", "DEMO001"}

class ConsentMiddleware:
    """
    Checks that user consent exists before allowing tool access.
    Simulates 42 CFR Part 2 privacy enforcement.
    """

    async def before_request(self, context: dict):
        # Allow demo tokens in non-production environments
        if os.getenv("MEDSCRIBE_ENV", "production") != "production":
            token = context.get("patient_token", "")
            if token in _DEMO_TOKENS:
                return  # bypass consent gate for demo/testing

        if not context.get("consent", False):
            # Simply raise RuntimeError if consent is missing
            raise RuntimeError("User consent not found. Access denied.")