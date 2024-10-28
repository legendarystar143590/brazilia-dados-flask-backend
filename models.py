from flask_sqlalchemy import SQLAlchemy
from flask import current_app
from sqlalchemy.sql import func
from sqlalchemy import and_, not_, Numeric
from decimal import Decimal
from datetime import datetime
from uuid import uuid4
from utils.common import get_language_name

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True, nullable=False, autoincrement=True)
    index = db.Column(db.String(255), nullable = False)
    first_name = db.Column(db.String(255), nullable = True)
    last_name = db.Column(db.String(255), nullable = False)
    stripe_customer_id = db.Column(db.String(255), nullable = False)
    email = db.Column(db.String(255), unique = True, nullable = False)
    language = db.Column(db.String(255), unique = False, nullable = False)
    password = db.Column(db.String(255), nullable=False)
    mauticId = db.Column(db.String(255), nullable=False)
    botsActive = db.Column(db.String(255), nullable=False, default = 0)
    com_name = db.Column(db.String(255), nullable=False)
    com_vat = db.Column(db.String(255), nullable=False)
    com_street = db.Column(db.String(255), nullable=False)
    com_street_number = db.Column(db.String(255), nullable=False)
    com_city = db.Column(db.String(255), nullable=False)
    com_postal = db.Column(db.String(255), nullable=False)
    com_country = db.Column(db.String(255), nullable=False)
    com_website = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(255), nullable=False, default='user')
    status = db.Column(db.String(255), nullable=False, default='cancel')
    billing_plan = db.Column(db.String(255), nullable=False, default='aiana_try')
    last_login = db.Column(db.DateTime, nullable = True)
    created_at = db.Column(db.DateTime, nullable = False,  default=datetime.utcnow)
    isVerified = db.Column(db.Boolean, default=False)
    verification_token = db.Column(db.String(100))    
    def __init__(self, first_name, last_name, index, email, password, mauticId, botsActive, language, com_name, com_vat, com_street, com_street_number, com_city, com_postal, com_country, com_website, status, billing_plan, stripe_customer_id, isVerified, verification_token):
        self.first_name = first_name
        self.last_name = last_name
        self.stripe_customer_id = stripe_customer_id
        self.status = status
        self.email = email
        self.index = index
        self.password = password
        self.mauticId = mauticId
        self.botsActive = botsActive
        self.language = language
        self.com_name = com_name
        self.com_vat = com_vat
        self.com_street = com_street
        self.com_street_number = com_street_number
        self.com_city = com_city
        self.com_postal = com_postal
        self.com_country = com_country
        self.com_website = com_website
        self.billing_plan = billing_plan
        self.isVerified = isVerified
        self.verification_token = verification_token
    
    # Add an index to the id column
    __table_args__ = (
        db.Index('idx_user_id', 'id'),
    )

    def register_user_if_not_exist(self):        
        db_user = User.query.filter(User.email == self.email).all()
        if not db_user:
            db.session.add(self)
            db.session.commit()
            return True
        return False
    
    @staticmethod
    def get_all_users():
        return User.query.order_by(User.role).all()

    @staticmethod
    def update_login(mail):
        user = User.query.filter_by(email=mail).first()
        user.last_login = str(datetime.now())
        db.session.commit()
    
    def check_user_exist(email):
        db_user = User.query.filter_by(email=email).first()
        if db_user is None:
            return False
        else:
            return True
    
    def save(self):
        db.session.add(self)
        db.session.commit()

    def save_verification_token(email, verification_token):
        user = User.query.filter_by(email=email).first()
        user.verification_token=verification_token
        db.session.commit() 

    @staticmethod
    def get_by_userID(id):        
        db_user = User.query.filter_by(id=id).first()
        return db_user

    @staticmethod
    def get_billing_plan(email):        
        db_user = User.query.filter_by(email=email).first()
        return db_user.billing_plan

    @staticmethod
    def get_by_index(index):        
        db_user = User.query.filter_by(index=index).first()
        return db_user
    
    @staticmethod
    def update_billing_plan(email, plan):        
        db_user = User.query.filter_by(email=email).first()
        db_user.billing_plan = plan
        db.session.commit()
        return db_user

    @staticmethod
    def get_by_email(email):
        user = User.query.filter_by(email=email).first()
        return user

    @staticmethod
    def del_by_id(_id):
        user = User.get_by_userID(_id)
        db.session.delete(user)
        db.session.commit()

    def json(self):
        return {
            'id': self.id,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'status':self.status,
            'stripe_customer_id':self.stripe_customer_id,
            'email': self.email,
            'index': self.index,
            'mauticId': self.mauticId,
            'botsActive': self.botsActive,
            'language': get_language_name(self.language),
            'password': self.password,  # Note: It's generally not safe to include password information here.
            'com_name': self.com_name,
            'com_vat': self.com_vat,
            'com_street': self.com_street,
            'com_street_number': self.com_street_number,
            'com_city': self.com_city,
            'com_postal': self.com_postal,
            'com_country': self.com_country,
            'com_website': self.com_website,
            'role': self.role,
            'created_at':self.created_at,
            'last_login':self.last_login,
            'billing_plan':self.billing_plan,
            'isVerified':self.isVerified,
            'verification_token':self.verification_token,
        }

    def __repr__(self):
        return f"<User {self.first_name}>"

class Bot(db.Model):
    __tablename__ = 'bots'

    id = db.Column(db.Integer, primary_key=True, nullable=False, autoincrement=True)
    index = db.Column(db.String(255), nullable = False)
    user_id = db.Column(db.Integer, nullable=False)
    name = db.Column(db.String(255), nullable=True)
    avatar = db.Column(db.String(255), nullable=True)
    color = db.Column(db.String(255), nullable=False)
    active = db.Column(db.Integer, nullable=False)
    start_time = db.Column(db.String(255), nullable=False)
    end_time = db.Column(db.String(255), nullable=False)
    knowledge_base = db.Column(db.String(255), nullable=False)
    monthly_session_number = db.Column(db.Integer, nullable = False, default=0)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __init__(self, user_id, index, name, avatar, color, active, start_time, end_time, knowledge_base):
        self.user_id = user_id
        self.name = name
        self.index = index
        self.avatar = avatar
        self.color = color
        self.active = active
        self.start_time = start_time
        self.end_time = end_time
        self.knowledge_base = knowledge_base

    # Add an index to the name column
    __table_args__ = (
        db.Index('idx_bot_name', 'name'),
    )
    
    def save(self):
        db.session.add(self)
        db.session.commit()

    @staticmethod
    def get_by_id(bot_id):
        return Bot.query.filter_by(id=bot_id).first()

    @staticmethod
    def get_by_index(botIndex):
        return Bot.query.filter_by(index=botIndex).first()

    @staticmethod
    def del_by_id(_id):
        bot = Bot.get_by_id(_id)
        chatlogs = ChatLog.query.filter_by(bot_name=_id).all()
        for chatlog in chatlogs:
            db.session.delete(chatlog)
        db.session.delete(bot)
        db.session.commit()
    @staticmethod
    def get_bots_from_user_id(user_id):
        bots = Bot.query.filter_by(user_id=user_id).all()
        return bots
    @staticmethod
    def get_all_bots():
        return Bot.query.all()

    def json(self):
        return {
            'id': self.id,
            'name': self.name,
            'avatar': self.avatar,
            'color': self.color,
            'active': self.active == 1,
            'start_time': self.start_time,
            'end_time': self.end_time,
            'knowledge_base': self.knowledge_base,
            'index':self.index,
            'created_at': self.created_at.isoformat()  # or strftime('%Y-%m-%d %H:%M:%S') for a specific format
        }

    def __repr__(self):
        return f"<Bot {self.name}>"

class DocumentKnowledge(db.Model):
    __tablename__ = 'documents'

    id = db.Column(db.Integer, primary_key=True, nullable=False, autoincrement=True)
    type = db.Column(db.String(255), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    file_size = db.Column(db.String(255), nullable=False)
    file_size_mb = db.Column(db.Integer, nullable=False, default=0)
    unique_id = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __init__(self, type, filename, file_size, file_size_mb, unique_id):
        self.type = type
        self.filename = filename
        self.file_size = file_size
        self.file_size_mb = file_size_mb
        self.unique_id = unique_id
    
    def save(self):
        db.session.add(self)
        db.session.commit()

    @staticmethod
    def get_by_id(_id):
        return DocumentKnowledge.query.get(_id)

    @staticmethod
    def del_by_id(_id):
        document = DocumentKnowledge.get_by_id(_id)
        db.session.delete(document)
        db.session.commit()
        
    @staticmethod
    def get_all_documents():
        return DocumentKnowledge.query.all()

    def json(self):
        return {
            'id': self.id,
            'type': self.type,
            'filename': self.filename,
            'unique_id': self.unique_id,
            'file_size':self.file_size,
            'file_size_mb':self.file_size_mb,
            'created_at': self.created_at.isoformat()  # or strftime('%Y-%m-%d %H:%M:%S') for a specific format
        }

    def __repr__(self):
        return f"<DocumentKnowledge {self.name}>"

class Website(db.Model):
    __tablename__ = 'websites'
    id = db.Column(db.Integer, primary_key=True, nullable=False, autoincrement=True)
    url = db.Column(db.String(255), nullable=True)
    unique_id = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __init__(self, url, unique_id):
        self.url = url
        self.unique_id = unique_id
    
    def save(self):
        db.session.add(self)
        db.session.commit()

    @staticmethod
    def get_by_id(id):
        return Website.query.get(id)
    
    @staticmethod
    def del_by_id(_id):
        website = Website.get_by_id(_id)
        db.session.delete(website)
        db.session.commit()

    @staticmethod
    def get_all_websites():
        return Website.query.all()

    def json(self):
        return {
            'id': self.id,
            'url': self.url,
            'unique_id': self.unique_id,
            'created_at': self.created_at.isoformat()  # or strftime('%Y-%m-%d %H:%M:%S') for a specific format
        }

    def __repr__(self):
        return f"<Website {self.name}>"

class Text(db.Model):
    __tablename__ = 'texts'

    id = db.Column(db.Integer, primary_key=True, nullable=False, autoincrement=True)
    question = db.Column(db.Text(5000), nullable=True)
    answer = db.Column(db.String(5000), nullable=True)
    unique_id = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __init__(self, question, answer, unique_id):
        self.question = question
        self.answer = answer
        self.unique_id = unique_id
    
    def save(self):
        db.session.add(self)
        db.session.commit()

    @staticmethod
    def get_by_id(id):
        return Text.query.get(id)
    
    @staticmethod
    def del_by_id(_id):
        text = Text.get_by_id(_id)
        db.session.delete(text)
        db.session.commit()
    
    @staticmethod
    def get_all_texts():
        return Text.query.all()

    def json(self):
        return {
            'id': self.id,
            'question': self.question,
            'answer': self.answer,
            'unique_id': self.unique_id,
            'created_at': self.created_at.isoformat()  # or strftime('%Y-%m-%d %H:%M:%S') for a specific format
        }

    def __repr__(self):
        return f"<Text {self.name}>"

class KnowledgeBase(db.Model):
    __tablename__ = 'knowledgebases'

    id = db.Column(db.Integer, primary_key=True, nullable=False, autoincrement=True)
    name = db.Column(db.String(255), nullable=False)
    unique_id = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __init__(self, name, unique_id, user_id):
        self.name = name
        self.unique_id = unique_id
        self.user_id = user_id
        
    def save(self):
        db.session.add(self)
        db.session.commit()

    @staticmethod
    def get_by_id(id):
        return KnowledgeBase.query.get(id)
    
    @staticmethod
    def get_all_knowledgebases():
        return KnowledgeBase.query.all()
    @staticmethod
    def delete_by_id(knowledgebase_id):
        knowledgebase = KnowledgeBase.get_by_id(knowledgebase_id)
        if knowledgebase:
            db.session.delete(knowledgebase)
            db.session.commit()
            return True
        return False


    def json(self):
        return {
            'id': self.id,
            'name': self.name,
            'user_id': self.user_id,
            'unique_id': self.unique_id,
            'created_at': self.created_at.isoformat()  # or strftime('%Y-%m-%d %H:%M:%S') for a specific format
        }

    def __repr__(self):
        return f"<KnowledgeBase {self.name}>"

class Conversation(db.Model):
    __tablename__ = 'conversations'

    id = db.Column(db.Integer, primary_key=True, nullable=False, autoincrement=True)
    user_message = db.Column(db.String(255), nullable=False)
    response = db.Column(db.String(255), nullable=False)
    session_id = db.Column(db.String(255), nullable=False)
    bot_id = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.String(255), nullable=False, default=datetime.utcnow)

    def __init__(self, user_message, response, bot_id, session_id):
        self.user_message = user_message
        self.response = response
        self.bot_id = bot_id
        self.session_id = session_id
    
    def save(self):
        db.session.add(self)
        db.session.commit()

    @staticmethod
    def get_by_id(id):
        return Conversation.query.get(id)

    @staticmethod
    def get_latest_by_session(id):
        return Conversation.query.filter_by(session_id=id).order_by('created_at').limit(3).all()
    
    @staticmethod
    def get_by_session(id):
        return Conversation.query.filter_by(session_id=id).all()
    
    @staticmethod
    def get_all_texts():
        return Conversation.query.all()

    @classmethod
    def del_by_bot_id(cls, bot_id):
        """Deletes all conversations for a given bot_id"""
        try:
            num_rows_deleted = db.session.query(cls).filter(cls.bot_id == bot_id).delete()
            db.session.commit()
            return num_rows_deleted
        except Exception as e:
            db.session.rollback()
            raise e
    @classmethod
    def del_by_session_id(cls, session_id):
        """Deletes all conversations for a given bot_id"""
        try:
            num_rows_deleted = db.session.query(cls).filter(cls.session_id == session_id).delete()
            db.session.commit()
            return num_rows_deleted
        except Exception as e:
            db.session.rollback()
            raise e

    def json(self):
        return {
            'id': self.id,
            'user_message': self.user_message,
            'response': self.response,
            'session_id':self.session_id,
            'bot_id': self.bot_id,
            'created_at': self.created_at  # or strftime('%Y-%m-%d %H:%M:%S') for a specific format
        }

    def __repr__(self):
        return f"<Conversation {self.id}>"

class Order(db.Model):
    __tablename__ = 'orders'

    id = db.Column(db.Integer, primary_key=True, nullable=False, autoincrement=True)
    sessoin_id = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    website = db.Column(db.String(255), nullable=False, default='https://login.aiana.io')
    status = db.Column(db.String(255), nullable=False)
    content = db.Column(db.String(255), nullable=False)
    user_index = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    bot_name = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.String(255), nullable=False)

    def __init__(self, sessoin_id, user_id, website, user_index, bot_name, email, status, content, createdAt):
        self.sessoin_id = sessoin_id
        self.bot_name = bot_name
        self.user_id = user_id
        self.user_index = user_index
        self.website = website
        self.email = email
        self.status = status
        self.content = content
        self.created_at = createdAt
    
    def save(self):
        db.session.add(self)
        db.session.commit()

    @staticmethod
    def get_by_id(id):
        return Order.query.filter_by(id=id).first()
    


    @staticmethod
    def get_by_user(id):
        return Order.query.filter_by(user_id=id).all()
    
    @staticmethod
    def get_by_bot(name):
        return Order.query.filter_by(bot_name=name).all()
    
    @staticmethod
    def get_all_texts():
        return Order.query.all()

    @classmethod
    def del_by_user_id(cls, user_id):
        """Deletes all orders for a given user_id"""
        try:
            num_rows_deleted = db.session.query(cls).filter(cls.user_id == user_id).delete()
            db.session.commit()
            return num_rows_deleted
        except Exception as e:
            db.session.rollback()
            raise e
        
    @classmethod
    def del_by_id(cls, id):
        """Deletes all orders for a given id"""
        try:
            num_rows_deleted = db.session.query(cls).filter(cls.id == id).delete()
            db.session.commit()
            return num_rows_deleted
        except Exception as e:
            db.session.rollback()
            raise e

    def json(self):
        return {
            'id': self.id,
            'sessoin_id': self.sessoin_id,
            'email': self.email,
            'user_id': self.user_id,
            'user_index': self.user_index,
            'bot_name': self.bot_name,
            'website': self.website,
            'status': self.status,
            'content': self.content,
            'created_at': self.created_at # or strftime('%Y-%m-%d %H:%M:%S') for a specific format
        }

    def __repr__(self):
        return f"<Order {self.id}>"
    
class ChatLog(db.Model):
    __tablename__ = 'chatlogs'

    id = db.Column(db.Integer, primary_key=True, nullable=False, autoincrement=True)
    session_id = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.String(255), nullable=False)
    website = db.Column(db.String(255), nullable=False, default="https://login.aiana.io")
    bot_name = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.String(255), nullable=False, default=datetime.utcnow)
    ended_at = db.Column(db.String(255), nullable=False, default=datetime.utcnow)

    def __init__(self, user_id,  bot_name, website, session_id, created_at, ended_at):
        self.created_at = created_at
        self.ended_at = ended_at
        self.website = website
        self.bot_name = bot_name
        self.user_id = user_id
        self.session_id = session_id
    
    def save(self):
        db.session.add(self)
        db.session.commit()

    @staticmethod
    def get_by_id(id):
        return ChatLog.query.get(id)

    @staticmethod
    def get_by_session(id):
        return ChatLog.query.filter_by(session_id=id).first()
    
    @staticmethod
    def del_by_session(id):
        try:
            bot = ChatLog.get_by_session(id)
            db.session.delete(bot)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            raise e
    
    @staticmethod
    def get_by_user(id):
        return ChatLog.query.filter_by(user_id=id).all()
    
    @staticmethod
    def get_all_texts():
        return Conversation.query.all()
  
    @staticmethod
    def get_logs_by_bot_id(bot_id):
        return ChatLog.query.filter(
            and_(
                ChatLog.bot_name == bot_id,
                not_(ChatLog.website == 'https://login.aiana.io')
            )
        ).all()

    @classmethod
    def del_by_bot_id(cls, bot_id):
        """Deletes all conversations for a given bot_id"""
        try:
            num_rows_deleted = db.session.query(cls).filter(cls.bot_id == bot_id).delete()
            db.session.commit()
            return num_rows_deleted
        except Exception as e:
            db.session.rollback()
            raise e

    def json(self):
        return {
            'id': self.id,
            'bot_name': self.bot_name,
            'user_id': self.user_id,
            'website': self.website or "https://login.aiana.io",
            'session_id': self.session_id,
            'created_at': self.created_at,  # or strftime('%Y-%m-%d %H:%M:%S') for a specific format
            'ended_at': self.ended_at
        }

    def __repr__(self):
        return f"<ChatLog {self.id}>"

class BillingPlan(db.Model):
    __tablename__ = 'billing_plans'

    id = db.Column(db.Integer, primary_key=True, nullable=False, autoincrement=True)
    code = db.Column(db.String(255), nullable=False, default="aiana_try")
    max_parallel_bots = db.Column(db.Integer, nullable=False, default=1)
    max_sessions_per_month = db.Column(db.Integer, nullable=False, default=25)
    max_linked_websites = db.Column(db.Integer, nullable=False, default=1)
    max_storage = db.Column(db.Integer, nullable=False, default=50) # MB in unit
    updated_at = db.Column(db.String(255), nullable=False, default=datetime.utcnow)
    prod_id = db.Column(db.String(255), nullable=False)

    def __init__(self, code,  max_parallel_bots, max_sessions_per_month, max_linked_websites, max_storage, prod_id):
        self.max_linked_websites = max_linked_websites
        self.max_storage = max_storage
        self.max_parallel_bots = max_parallel_bots
        self.code = code
        self.max_sessions_per_month = max_sessions_per_month
        self.prod_id = prod_id
    
    def save(self):
        db.session.add(self)
        db.session.commit()

    @staticmethod
    def get_by_id(id):
        return BillingPlan.query.get(id)

    @staticmethod
    def get_by_code(code):
        return BillingPlan.query.filter_by(code=code).first()
   
    @staticmethod
    def del_by_code(code):
        try:
            plan = BillingPlan.get_by_session(code)
            db.session.delete(plan)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            raise e

    def json(self):
        return {
            'id': self.id,
            'code': self.code,
            'max_parallel_bots': self.max_parallel_bots,
            'max_sessions_per_month': self.max_sessions_per_month,
            'max_linked_websites': self.max_linked_websites,  # or strftime('%Y-%m-%d %H:%M:%S') for a specific format
            'max_storage': self.max_storage,
            'prod_id':self.prod_id,
            'updated_at':self.updated_at
        }

    def __repr__(self):
        return f"<BillingPlan {self.id}>"

class RegisteredWebsite(db.Model):
    __tablename__ = 'registered_websites'

    id = db.Column(db.Integer, primary_key=True, nullable=False, autoincrement=True)
    bot_id = db.Column(db.Integer, nullable=False, default=0)
    user_id = db.Column(db.Integer, nullable=False, default=0)
    index = db.Column(db.String(255), nullable=False)
    domain = db.Column(db.String(255), nullable=False, default="https://login.aiana.io")
    updated_at = db.Column(db.String(255), nullable=False, default=datetime.utcnow)

    def __init__(self, index, bot_id, user_id,  domain):
        self.index = index
        self.domain = domain
        self.bot_id = bot_id
        self.user_id = user_id
    
    def save(self):
        db.session.add(self)
        db.session.commit()

    @staticmethod
    def get_by_id(id):
        return RegisteredWebsite.query.get(id)

    @staticmethod
    def get_by_bot_id(bot_id):
        return RegisteredWebsite.query.filter_by(bot_id=bot_id).all()

    @staticmethod
    def get_by_user_id(user_id):
        return RegisteredWebsite.query.filter_by(user_id=user_id).all()
   
    @staticmethod
    def del_by_bot_id(bot_id):
        try:
            websites = RegisteredWebsite.get_by_bot_id(bot_id)
            for website in websites:
                db.session.delete(website)
                db.session.commit()
           
        except Exception as e:
            db.session.rollback()
            raise e

    @staticmethod
    def del_by_index(index):
        try:
            website = RegisteredWebsite.query.filter_by(index=index).first()
            db.session.delete(website)
            db.session.commit()
            
        except Exception as e:
            db.session.rollback()
            raise e

    def json(self):
        return {
            'id': self.id,
            'index': self.index,
            'user_id': self.user_id,
            'bot_id': self.bot_id,
            'domain': self.domain,
            'updated_at':self.updated_at
        }

    def __repr__(self):
        return f"<RegisteredWebsite {self.id}>"

class ShopInfo(db.Model):
    __bind_key__ = 'shopify'
    __tablename__="shop_info"

    id = db.Column(db.Integer, primary_key=True, nullable=False, autoincrement=True)
    shop = db.Column(db.String(255), nullable=False)
    state = db.Column(db.String(255), nullable=False)
    code = db.Column(db.String(255), nullable=True)
    shop_token = db.Column(db.String(255), nullable=True)
    shopify_token = db.Column(db.String(255), nullable=True)
    time_stamp = db.Column(db.String(255), nullable=True)
    hmac_header = db.Column(db.String(255), nullable=True)

    def __init__(self, shop, state, code):
        self.shop = shop
        self.state = state
        self.code = code

    def save(self):
        db.session.add(self)
        db.session.commit()

    def update_shop_info(shop, shop_token, shopify_token):
        db_shop = ShopInfo.query.filter_by(shop = shop).first()
        db_shop.shop_token = shop_token
        db_shop.shopify_token = shopify_token
        db.session.commit()

    @staticmethod
    def check_shop_exist(shop):
        db_shop = ShopInfo.query.filter_by(shop = shop).first()
        if db_shop is None:
            return False
        return True
    
    @staticmethod
    def get_by_shop(shop):
        db_shop = ShopInfo.query.filter_by(shop = shop).first()
        return db_shop

    def json(self):
        return{
            'id' :self.id,
            'shop':self.shop,
            'state':self.state,
            'code':self.code,
            'shop_token':self.shop_token,
            'shopify_token':self.shopify_token,
            'time_stamp':self.time_stamp,
            'hmac_header':self.hmac_header
        }
    
    def __repr__(self):
        return f"<ShopInfo {self.id}>"
    
class ProudctsTable(db.Model):
    __bind_key__ = 'shopify'
    __tablename__="shop_products"

    id = db.Column(db.Integer, primary_key=True, nullable=False, autoincrement=True)
    shop_id = db.Column(db.String(255), nullable=False)
    product_id = db.Column(db.String(255), nullable=False)
    product_type = db.Column(db.String(255), nullable=False)
    product_title = db.Column(db.String(255), nullable=False)
    product_price = db.Column(db.Numeric(10,2), nullable=False)
    created_at = db.Column(db.String(255), nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.String(255), nullable=True)
    
    def __init__(self, shop_id, product_id, product_type, product_title, product_price,):
        self.shop_id = shop_id
        self.product_id = product_id
        self.product_type = product_type
        self.product_title = product_title
        self.product_price = Decimal(product_price)

    def save(self):
        db.session.add(self)
        db.session.commit()

    @staticmethod
    def get_by_shop_id(shop_id):
        return ProudctsTable.query.filter_by(shop_id=shop_id).all()
    
    @staticmethod
    def clear_all_products():
        db.session.query(ProudctsTable).delete()
        db.session.commit()

    def json(self):
        return{
            'id' :self.id,
            'shop_id':self.shop_id,
            'product_id':self.product_id,
            'product_type':self.product_type,
            'product_title':self.product_title,
            'product_price':self.product_price,
            'created_at':self.created_at,
            'updated_at':self.updated_at
        }

    def __repr__(self):
        return f"<ProudctsTable {self.id}>"
