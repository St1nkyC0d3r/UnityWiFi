class APIException(Exception):
    """
    Custom exception class for handling API errors.
    """
    def __init__(self, message, status_code):
        super().__init__(message)
        self.message = message
        self.status_code = status_code

    def to_dict(self):
        return {"message": self.message}
    
class DatabaseError(Exception):
    """
    Custom exception class for handling database errors.
    """
    def __init__(self, message="A database error occurred"):
        super().__init__(message)
        self.message = message

