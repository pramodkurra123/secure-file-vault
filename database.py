import os
import psycopg
from psycopg.rows import tuple_row
from werkzeug.security import generate_password_hash


DATABASE_URL = os.environ.get("DATABASE_URL")


def get_connection():

    if not DATABASE_URL:
        raise RuntimeError(
            "DATABASE_URL environment variable is not set."
        )

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
            role TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL
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

    connection.execute("""
        CREATE TABLE IF NOT EXISTS stored_files (
            id SERIAL PRIMARY KEY,
            username TEXT NOT NULL,
            filename TEXT NOT NULL,
            file_data BYTEA NOT NULL,
            file_size BIGINT NOT NULL,
            uploaded_at TIMESTAMP NOT NULL
        )
    """)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS otp_codes (
            id SERIAL PRIMARY KEY,
            username TEXT NOT NULL,
            otp_hash TEXT NOT NULL,
            created_at TIMESTAMP NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            used BOOLEAN NOT NULL DEFAULT FALSE
        )
    """)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS pro_vault_files (
            id SERIAL PRIMARY KEY,
            username TEXT NOT NULL,
            stored_name TEXT NOT NULL,
            original_name TEXT NOT NULL,
            file_data BYTEA NOT NULL,
            file_size BIGINT NOT NULL,
            uploaded_at TIMESTAMP NOT NULL
        )
    """)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS vault_keys (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            recovery_data BYTEA NOT NULL,
            created_at TIMESTAMP NOT NULL,
            updated_at TIMESTAMP NOT NULL
        )
    """)

    connection.commit()

    admin_username = os.environ.get("ADMIN_USERNAME")
    admin_password = os.environ.get("ADMIN_PASSWORD")
    admin_email = os.environ.get("ADMIN_EMAIL")

    if not admin_username or not admin_password or not admin_email:
        connection.close()

        raise RuntimeError(
            "ADMIN_USERNAME, ADMIN_PASSWORD and "
            "ADMIN_EMAIL environment variables are required."
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

        password_hash = generate_password_hash(
            admin_password
        )

        connection.execute(
            """
            INSERT INTO users
            (
                username,
                password,
                role,
                email
            )
            VALUES (%s, %s, %s, %s)
            """,
            (
                admin_username,
                password_hash,
                "admin",
                admin_email
            )
        )

        connection.commit()

    else:

        connection.execute(
            """
            ALTER TABLE users
            ADD COLUMN IF NOT EXISTS email TEXT
            """
        )

        connection.execute(
            """
            UPDATE users
            SET email = %s
            WHERE username = %s
            AND (email IS NULL OR email = '')
            """,
            (
                admin_email,
                admin_username
            )
        )

        connection.commit()

    connection.close()
