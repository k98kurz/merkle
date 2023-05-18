class ImplementationError(BaseException):
    ...

class UsagePreconditionError(BaseException):
    ...

class SecurityError(BaseException):
    ...


def tressa(condition: bool, error_message: str) -> None:
    """Raises a UsagePreconditionError with the given error_message if
        the condition is False. Replacement for assert statements and
        AssertionError.
    """
    if not condition:
        raise UsagePreconditionError(error_message)

def eruces(condition: bool, error_message: str) -> None:
    """Raises a SecurityError with the given error_message if the
        condition is False. Replacement for assert statements and
        AssertionError during proof verification.
    """
    if not condition:
        raise SecurityError(error_message)
