import os
from flask import Flask
from flask_restful import Api
from psycopg2.pool import ThreadedConnectionPool
from dotenv import load_dotenv
from flasgger import Swagger
import yaml

# Load environment variables
load_dotenv()

app = Flask(__name__)
api = Api(app)

# Swagger configuration
with open('app//docs//swagger_config.yml', 'r') as f:
    swagger_config = yaml.safe_load(f)
swagger = Swagger(app, config=swagger_config)

# Database connection details from environment variables
DB_HOST = os.environ.get("DB_HOST")
DB_NAME = os.environ.get("DB_NAME")
DB_USER = os.environ.get("DB_USER")
DB_PASSWORD = os.environ.get("DB_PASSWORD")
CONNECTION_POOL_SIZE = int(os.environ.get("CONNECTION_POOL_SIZE", 10))

# Configuration
app.config['CONNECTION_POOL_SIZE'] = CONNECTION_POOL_SIZE
app.config['JWT_ISSUER'] = 'unitywifi.com'
app.config['JWT_AUDIENCE'] = 'unitywifi.com'


# Initialize connection pool
def init_db_connection_pool():
    """Initializes the PostgreSQL connection pool."""
    try:
        app.pool = ThreadedConnectionPool(
            minconn=2,
            maxconn=app.config['CONNECTION_POOL_SIZE'],
            host=DB_HOST,
            database=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD,
        )
        print("Connection pool initialized successfully.")
    except Exception as e:
        print(f"Error initializing connection pool: {e}")
        raise

from app.resources import user, hotspot, data_usage, organization

# Add resources to the API
api.add_resource(user.UserRegister, "/register")
api.add_resource(user.UserLogin, "/login")
api.add_resource(hotspot.HotspotRegister, "/hotspot/register")
api.add_resource(hotspot.HotspotDetails, "/hotspot/<int:hotspot_id>")
api.add_resource(data_usage.DataCheck, "/data_check")
api.add_resource(data_usage.DataUsage, "/data_usage")
api.add_resource(organization.ProviderRegister, "/provider/register")
