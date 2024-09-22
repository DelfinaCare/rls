# sync_setup.py
from engines import admin_engine as engine
from models import RlsBase

print("Setting up database")


def setup_database():
    # Create tables
    RlsBase.metadata.create_all(engine)


if __name__ == "__main__":
    setup_database()
