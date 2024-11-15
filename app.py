import os
import uuid
import time
import pymysql
from dotenv import load_dotenv
from flask import Flask, request, jsonify, make_response
from apscheduler.schedulers.background import BackgroundScheduler
from flask_cors import CORS
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager
from api.auth import user_blueprint
from api.bot import bot_blueprint
from api.knowledge import knowledge_blueprint
from api.chatlog import log_blueprint
from api.tickets import ticket_blueprint
from api.payment import payment_blueprint
from api.shopify import shopify_blueprint, sync_products
from api.mautic import delete_mautic_contact
from models import db
from datetime import timedelta
from utils.common import get_bucket_name
import cProfile
import pstats

load_dotenv()

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DB_URI")
# app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("SHOPIFY_DB_URI")
# app.config['SQLALCHEMY_BINDS'] = {
#    'shopify': os.getenv('SHOPIFY_DB_URI')
# }
# from sqlalchemy import create_engine

# engine = create_engine(os.getenv('DB_URI'), connect_args={'ssl': {'sslmode': 'REQUIRED'}})

# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db?check_same_thread=False&mode=WAL'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_POOL_SIZE'] = 20
app.config['UPLOAD_FOLDER'] = os.getenv('UPLOAD_FOLDER')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')

app.config['SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'legendarystar2160187@gmail.com'
app.config['MAIL_PASSWORD'] = 'pksv wzbh wahl atbw'
app.config['SCHEDULER_API_ENABLED'] = True

app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=15)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=3)

# app.config['JWT_TOKEN_LOCATION'] = ['cookies']
# app.config['JWT_COOKIE_SECURE'] = True  # Set to False if not using https
# app.config['JWT_COOKIE_CSRF_PROTECT'] = True  # CSRF protection
# Initialize JWTManager
jwt = JWTManager(app)

db.init_app(app)
migrate = Migrate(app, db)

def scheduled_task():
   with app.app_context():
      sync_products()

scheduler = BackgroundScheduler()
scheduler.add_job(func=scheduled_task, trigger="interval", minutes=60)
scheduler.start()
# CORS(app, supports_credentials=True, origins=['https://your-frontend-domain.com'])
CORS(app)

app.register_blueprint(user_blueprint, url_prefix='/api')
app.register_blueprint(bot_blueprint, url_prefix='/api')
app.register_blueprint(knowledge_blueprint, url_prefix='/api')
app.register_blueprint(log_blueprint, url_prefix='/api')
app.register_blueprint(ticket_blueprint, url_prefix='/api')
app.register_blueprint(shopify_blueprint, url_prefix='/api')
app.register_blueprint(payment_blueprint)

get_bucket_name()
@app.route("/")
def index():
   db.create_all()
   # db.create_all(bind_key='shopify')
   # db.drop_all()
   # del_all_records()
   # for i in range(13216, 13217):
   #    delete_mautic_contact(i)
   #    print("current number", i)
   # print('Deleted')
   # deleteIndex()
   return "This is APIs for CustomGPT!"

if __name__ == '__main__':
   # Start profiling
   profiler = cProfile.Profile()
   profiler.enable()

   app.run(debug=True)

   # Stop profiling and save the results
   profiler.disable()
   stats = pstats.Stats(profiler).sort_stats('cumulative')
   stats.print_stats()
