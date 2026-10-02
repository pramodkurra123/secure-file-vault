import os
import psycopg
from psycopg.rows import tuple_row
from werkzeug.security import generate_password_hash


DATABASE_URL = os.environ.get("DATABASE_URL")


def get_connection():

    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL environment variable is not set.")

    return psycopg.connect(
        DATABASE_URL,
        row_factory=tuple_row
    )


def create_database():

    connection = get_connection()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        )
    """)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS login_attempts (
            id SERIAL PRIMARY KEY,
            username TEXT,
            ip_address TEXT,
            timestamp TIMESTAMP,
            status TEXT
        )
    """)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id SERIAL PRIMARY KEY,
            ip_address TEXT,
            message TEXT,
            timestamp TIMESTAMP
        )
    """)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS file_access_logs (
            id SERIAL PRIMARY KEY,
            username TEXT,
            ip_address TEXT,
            filename TEXT,
            timestamp TIMESTAMP
        )
    """)

    admin_username = os.environ.get("ADMIN_USERNAME")
    admin_password = os.environ.get("ADMIN_PASSWORD")

    if not admin_username or not admin_password:
        raise RuntimeError(
            "ADMIN_USERNAME and ADMIN_PASSWORD environment variables are required."
        )

    existing_user = connection.execute(
        """
        SELECT id
        FROM users
        WHERE username = %s
        """,
        (admin_username,)
    ).fetchone()

    if existing_user is None:

        password_hash = generate_password_hash(admin_password)

        connection.execute(
            """
            INSERT INTO users
            (username, password, role)
            VALUES (%s, %s, %s)
            """,
            (
                admin_username,
                password_hash,
                "admin"
            )
        )

    connection.commit()
    connection.close()