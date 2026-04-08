# consent_middleware.py
class ConsentMiddleware:
    """
    Checks that user consent exists before allowing tool access.
    Simulates 42 CFR Part 2 privacy enforcement.
    """

    async def before_request(self, context: dict):
        if not context.get("consent", False):
            # Simply raise RuntimeError if consent is missing
            raise RuntimeError("User consent not found. Access denied.")