# Function to generate standardized error responses
def error_response(message, status_code):
    """
    Generates a standardized error response.
    """
    return {"error": {"message": message, "code": status_code}}
