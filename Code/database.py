import sys
import os
import sqlalchemy
from sqlalchemy import text
from sqlalchemy.orm import Session  # Import the Session class
import pandas as pd
import Code.configuration as cf

from dotenv import load_dotenv
load_dotenv('.env')

session = None  # Initialize the session variable


def create_session():
    """
    Create a SQLAlchemy Session to manage database transactions.
    """
    try:
        db_url = f'postgresql://{os.getenv("POSTGRES_USER")}:{os.getenv("POSTGRES_PASSWORD")}@{os.getenv("DB_HOST")}:{os.getenv("POSTGRES_PORT")}/{os.getenv("POSTGRES_DB")}'
        # print("Database URL:", db_url)  # Debugging
        engine = sqlalchemy.create_engine(db_url)
        return Session(engine)  # Create a Session using the engine
    except Exception as e:
        cf.logger.critical(e)
        sys.exit(1)


def table_exists(table_name):
    """
    Checks whether the table exists or not.
    Returns boolean (True if the table exists, False otherwise)
    """
    session = create_session()
    # Check if the table exists in the database using SQLAlchemy's schema and inspector
    inspector = sqlalchemy.inspect(session.get_bind())
    status = table_name in inspector.get_table_names()
    return status


def fetchone_query(session, table_name, col, value):
    """
    Checks whether a row with the given value exists in the table.
    Returns boolean (True if a matching row exists, False otherwise).
    """
    try:
        # Use the session to execute the query
        query = f"SELECT {col} FROM {table_name} WHERE repo_url = :value"
        result = session.execute(query, {"value": value})
        return result.fetchone() is not None
    except Exception as e:
        cf.logger.error(f"Error executing query: {e}")
        return False


def table_rows_count(table_name):
    session3 = create_session()
    conn3 = session3.connection()
    sql = text(f'SELECT COUNT(*) FROM {table_name}')
    result = conn3.execute(sql)
    count = result.scalar()
    return count


def get_query(query):
    session, conn = None, None
    try:
        session = create_session()
        conn = session.connection()
        results = conn.execute(text(query))
        results = [dict(zip(results.keys(), row)) for row in results]
        return results
    finally:
        conn.close()
        session.close()


def get_one_query(query):
    session2, conn2 = None, None
    try:
        session2 = create_session()
        conn2 = session2.connection()
        results = conn2.execute(text(query))
        if results.rowcount == 0:
            return False
        return dict(zip(results.keys(), list(results)[0]))
    finally:
        conn2.close()
        session2.close()


def exec_query(query):
    session1, conn1 = None, None
    try:
        session1 = create_session()
        conn1 = session1.connection()
        conn1.execute(text(query))
        conn1.commit()
    finally:
        conn1.close()
        session1.close()


if not session:
    session = create_session()
    conn = session  # temporary fix for tests
