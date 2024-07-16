from Code.database import create_session
from sqlalchemy import text
from Code.database import table_exists


def create_cve_mapper_table(conn):
    try:
        # Get the connection from the session
        # connection = session.connection()

        # Create the table using SQLAlchemy's text() function to declare the SQL as text
        sql = text('''
            CREATE TABLE IF NOT EXISTS cve_project (
                id SERIAL PRIMARY KEY,
                cve VARCHAR(30) NOT NULL ,
                project_url VARCHAR(500) NOT NULL,
                rel_type VARCHAR(255),
                checked  VARCHAR(255) DEFAULT 'False',
                UNIQUE (cve, project_url)
            );
        ''')
        # CONSTRAINT unique_cve_project UNIQUE (cve, project_url)

        # Execute the SQL
        conn.execute(sql)
        conn.commit()

        print("Table cve_project created successfully.")

    except Exception as e:
        print(f"Error: {e}")


def create_cpe_project_table(session):
    connection = session.connection()
    if not table_exists('cpe_project'):
        sql = text('''
                CREATE TABLE IF NOT EXISTS cpe_project (
                    cpe_name VARCHAR(255) NOT NULL,
                    repo_url VARCHAR(512) NOT NULL,
                    rel_type VARCHAR(255) NOT NULL,
                    UNIQUE (cpe_name, repo_url)
                );
            ''')

        connection.execute(sql)
        session.commit()


def cve_cpe_mapper(conn):
    if not table_exists('cve_cpe_mapper'):
        sql = text('''
                CREATE TABLE IF NOT EXISTS cve_cpe_mapper (
                id SERIAL PRIMARY KEY,
                cve_id VARCHAR(30) NOT NULL,
                cpe_name text NOT NULL,
                UNIQUE (cve_id,cpe_name)
                );
            ''')
        conn.execute(sql)
        conn.commit()
        print("Table cve_cpe_mapper created successfully.")

