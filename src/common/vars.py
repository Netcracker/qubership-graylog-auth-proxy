from jinja2 import Environment, FileSystemLoader, select_autoescape
from prometheus_client import Histogram

TEMPLATES_ENV = Environment(
    loader=FileSystemLoader("templates"),
    autoescape=select_autoescape()
)

# Default admin user
DEFAULT_ADMIN_USER = 'admin'

# Default roles
DEFAULT_ROLES = []

# Proxy container name
PROXY_CONTAINER_NAME = 'graylog_auth_proxy'

# Prometheus metrics
GET_REQUEST_DURATION = Histogram('get_requests_duration', 'GET requests response time in seconds')
POST_REQUEST_DURATION = Histogram('post_requests_duration', 'POST requests response time in seconds')
PUT_REQUEST_DURATION = Histogram('put_requests_duration', 'PUT requests response time in seconds')
DELETE_REQUEST_DURATION = Histogram('delete_requests_duration', 'DELETE requests response time in seconds')

# Graylog API endpoints
GRAYLOG_API_USERS = '/api/users/'
GRAYLOG_API_STREAMS = '/api/streams/'
GRAYLOG_API_USERS_ID = '/api/users/id/'

# Max age for CORS preflight requests
ACCESS_CONTROL_MAX_AGE = 86400  # 24 hours

# Max age for cookies
COOKIE_MAX_AGE = 86400  # 24 hours
COOKIE_EXPIRES_HOURS = 24  # 24 hours

# Session expiration time
SESSION_EXPIRATION_TIME = 86400  # 24 hours

# Priority for role and stream mapping
# Any random number bigger than 127 will do
PRIORITY_ROLE_MAX = 127
PRIORITY_STREAM_MAX = 127
