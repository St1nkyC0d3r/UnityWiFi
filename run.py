from app import app, init_db_connection_pool

if __name__ == "__main__":
    init_db_connection_pool()  # Initialize the database connection pool
    app.run(debug=True, host="0.0.0.0")