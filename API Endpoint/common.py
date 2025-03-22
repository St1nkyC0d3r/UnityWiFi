import datetime
import calendar

# Function to generate standardized error responses
def error_response(message, status_code):
    """
    Generates a standardized error response.
    """
    return {"error": {"message": message, "code": status_code}}


def one_month_ago_exactly():
    """
    Returns the timestamp of exactly one month ago
    """
    now = datetime.datetime.now()
    current_year = now.year
    current_month = now.month
    current_day = now.day
    current_hour = now.hour
    current_minute = now.minute
    current_second = now.second

    if current_month == 1:
        previous_month = 12
        previous_year = current_year - 1
    else: 
        previous_month = current_month -1
        previous_year = current_year
    
    days_in_previous_month = calendar.monthrange(previous_year,previous_month)[1]
    previous_day = min(current_day, days_in_previous_month)
    previous_datetime = datetime.datetime(
        previous_year,
        previous_month,
        previous_day,
        current_hour,
        current_minute,
        current_second
    )
    
    return previous_datetime.strftime("%Y-%m-%d %H:%M:%S")
