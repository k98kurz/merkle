class ImplementationError(BaseException):
    """An error that occurs if a function is not properly implemented."""
    ...

class SecurityError(BaseException):
    """An error that occurs if a security check fails."""
    ...

def eruces(condition: bool, error_message: str) -> None:
    """Raises a SecurityError with the given error_message if the
        condition is False. Replacement for assert statements and
        AssertionError during proof verification.
    """
    if not condition:
        raise SecurityError(error_message)

def tert(condition: bool, message: str = '') -> None:
    """Replacement for assert preconditions. Raises TypeError with the
        given message if the condition check fails.
    """
    if condition:
        return
    raise TypeError(message)

def vert(condition: bool, message: str = '') -> None:
    """Replacement for assert preconditions. Raises ValueError with the
        given message if the condition check fails.
    """
    if condition:
        return
    raise ValueError(message)

def yert(condition: bool, message: str = '') -> None:
    """Replacement for assert preconditions. Raises SyntaxError with the
        given message if the condition check fails.
    """
    if condition:
        return
    raise SyntaxError(message)
