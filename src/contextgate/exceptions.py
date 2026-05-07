class ContextGateError(Exception):
    pass


class UnsupportedFormatError(ContextGateError):
    pass


class FileTooLargeError(ContextGateError):
    pass


class ExtractionError(ContextGateError):
    pass
