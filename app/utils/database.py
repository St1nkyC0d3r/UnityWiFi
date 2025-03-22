from flask import g
from psycopg2 import connect, extras
import psycopg2
from app import app  # Import the Flask app instance
from .exceptions import DatabaseError # Import custom exception
from typing import Tuple, Any

# Get connection from the pool
def get_db_connection() -> Tuple[connect, extras.DictCursor]:
    """
    Retrieves a connection from the connection pool and returns the connection and cursor.
    """
    try:
        conn = app.pool.getconn()
        cursor = conn.cursor(cursor_factory=extras.DictCursor)
        return conn, cursor
    except Exception as e:
        print(f"Error getting connection from pool: {e}")
        raise

# Put connection back to the pool
def put_db_connection(conn: connect):
    """
    Puts a connection back into the connection pool.
    """
    if conn:
        app.pool.putconn(conn)

def execute_query(query: str, params: tuple = None, fetchone: bool = False, commit: bool = True) -> Any:
    """
    Executes a database query and handles connection management.

    Args:
        query (str): The SQL query to execute.
        params (tuple, optional): Parameters to pass to the query. Defaults to None.
        fetchone (bool, optional): Whether to fetch one result or all. Defaults to False.
        commit (bool, optional): Whether to commit the transaction. Defaults to True.

    Returns:
        Any: The result of the query (None, one row, or all rows).

    Raises:
        DatabaseError: If a database error occurs.
    """
    conn, cursor = get_db_connection()
    try:
        cursor.execute(query, params)
        if fetchone:
            result = cursor.fetchone()
        else:
            result = cursor.fetchall()
        if commit:
            conn.commit()
        return result
    except psycopg2.Error as e:
        conn.rollback()
        print(f"Database error: {e}")
        raise DatabaseError() from e  # Preserve original exception as context
    finally:
        put_db_connection(conn)