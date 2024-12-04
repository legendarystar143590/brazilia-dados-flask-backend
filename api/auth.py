from flask import Blueprint, request, jsonify, current_app, url_for
from flask_jwt_extended import  create_access_token, create_refresh_token,  jwt_required, get_jwt_identity, set_access_cookies
from werkzeug.security import check_password_hash, generate_password_hash
from flask_cors import cross_origin
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from validate_email import validate_email
from models import User, Bot, KnowledgeBase
import logging
import hashlib
import datetime
from api.mautic import get_access_token, create_mautic_user, update_mautic_user, login_mautic, mautic_reset_password, mautic_send_verfication_link, send_registration_mail
from utils.common import get_language_code
import uuid
from api.payment import create_customer_id
import secrets


user_blueprint = Blueprint('user_blueprint', __name__)

@user_blueprint.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or not data['email'] or not data['password']:
        return jsonify({'message': 'Could not verify', 'WWW-Authenticate': 'Basic realm="Login required!"'}), 401

    try:
        email = data['email']
        password = data['password']
        user = User.query.filter_by(email=email).first()
        login_datetime = datetime.datetime.now()
        if not user:
            return jsonify({'error': 'User not found.'}), 403

        # Debugging: Log the pulled user data and the provided password
        print(f"Pulled user data from DB: {user}")
        print(f"Provided password: {data['password']}")
        mautic_data = {}
        # Check if the provided password matches the stored password hash
        if check_password_hash(user.password, password):            
            total_bots = Bot.query.filter_by(user_id=user.id).count()
            active_bots = Bot.query.filter_by(user_id=user.id, active=1).count()
            mautic_data["language"] = user.language
            mautic_data["bots_active"] = active_bots
            mautic_data["bots_registered"] = total_bots
            mautic_data["aiana_status"]= "active"
            mautic_data["first_name"]= user.first_name
            mautic_data["last_name"]= user.last_name
            mautic_data["email"]= user.email
            mautic_data["com_name"]= user.com_name
            mautic_data["com_vat"]= user.com_vat
            mautic_data["com_street"]= user.com_street
            mautic_data["com_street_number"]=user.com_street_number
            mautic_data["com_postal"]=user.com_postal
            mautic_data["com_city"]=user.com_city
            mautic_data["com_country"]=user.com_country
            mautic_data["com_website"]=user.com_website
            mautic_data["last_login"]=login_datetime
            if login_mautic(mautic_data, user.mauticId) == 'error':
                print("Password verification successful.")  # Additional debug information
                return jsonify({'error': 'Server is busy. Try again later!'}), 400
            
            access_token = create_access_token(identity=user.id, expires_delta=datetime.timedelta(hours=1))
            User.update_login(email)
            # refresh_token = create_refresh_token(identity=user.id, expires_delta=datetime.timedelta(hours=2))
            return jsonify({'accessToken': access_token, 'userId':user.id, 'userIndex':user.index, 'firstName':user.first_name, 'lastName':user.last_name, 'role':user.role, 'plan':user.billing_plan, 'status':user.status, 'isVerified':user.isVerified}), 200
            # set_access_cookies(response, token)
        else:
            print("Password verification failed.")  # Additional debug information
            return jsonify({'error': 'Wrong credentials'}), 403

    except Exception as e:
        logging.error(f"Login error: {e}")  # Use logging for errors
        return jsonify({'error': str(e)}), 500


@user_blueprint.route('/register', methods=['POST'])
@cross_origin()
def register():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    email = data['email']
    is_valid = validate_email(email)
    print (is_valid)
    if is_valid==False:
        return jsonify({'error':'Invalid email!'}),203
    try:
        # User Info
        first_name = data['first_name']
        last_name = data['last_name']
        email = data['email']
        password = generate_password_hash(data['password'])
        language = get_language_code(data['language'])
    
        # Company Info
        com_street = data['com_street']
        com_city = data['com_city']
        com_country = data['com_country']  
        com_name = data['com_name']
        com_vat = data['com_vat']
        com_street_number = data['com_street_number']
        com_postal = data['com_postal']
        com_website = data['com_website']
        data['language'] = language
        verification_token = ''
        index = str(uuid.uuid4())
        if User.check_user_exist(email):
            return jsonify({'error': 'User already exists'}), 409
        mauticId = create_mautic_user(data)
        print(mauticId)
        if mauticId == 'error':
            return jsonify({'error': 'Invalid email!'}), 400
        # Create a stripe customer
        customer_id = create_customer_id(email)
        # verification_token = secrets.token_hex(16)
        # Create a new User instance
        new_user = User(first_name=first_name, last_name=last_name,index = index, email=email, password=password, mauticId=mauticId, botsActive=0,
                        language=language, com_street=com_street, com_city=com_city, com_country=com_country,
                        com_name=com_name, com_vat=com_vat, com_street_number=com_street_number, com_postal= com_postal, com_website=com_website, stripe_customer_id=customer_id, status="cancel", billing_plan="aiana_try", isVerified=False, verification_token=verification_token)
        
        # Attempt to register the user
        if new_user.register_user_if_not_exist():
            print("Starting...")
            serializer = URLSafeTimedSerializer(current_app.config['JWT_SECRET_KEY'])
            verification_token = serializer.dumps(email, salt='email-confirm')
            verification_link = f"http://login.aiana.io/signup/verify-email?token={verification_token}"
            User.save_verification_token(email, verification_token)
            mautic_send_verfication_link(verification_link, mauticId)
            return jsonify({'message': 'User registered successfully', 'email':email}), 201
        else:
            return jsonify({'error': 'User already exists'}), 409

    except KeyError as e:
        # If any key is missing in the data
        return jsonify({'error': f'Missing key in data: {e}'}), 400
    except Exception as e:
        # For any other errors
        print("Error:", str(e))
        return jsonify({'error': str(e)}), 500

@user_blueprint.route('/get_user', methods=['POST'])
@cross_origin()
@jwt_required()
def get_user():
    data = request.get_json()
    userID = data['userID']
    user = User.get_by_userID(userID)
    if user:
        return user.json(), 200
    else:
        return jsonify({'error': 'Not found user!'}), 400

@user_blueprint.route('/del_user', methods=['POST'])
@cross_origin()
@jwt_required()
def del_user():
    try:
        data = request.get_json()
        userID = data['userID']
        targetUserId = data['targetId']

        user = User.get_by_userID(userID)
        if user:
            if user.role == 'admin':
                targetUser = User.get_by_userID(targetUserId)
                if targetUser:
                    User.del_by_id(targetUserId)
                    return jsonify({'message':'success'}), 201
                else:
                    return jsonify({'error': 'Not found user!'}), 400
            else:
                return jsonify({'error': 'You do not have right access!'}), 400
        else:
            return jsonify({'error': 'You do not have right access!'}), 403
    except Exception as e:
        print(str(e))
        return jsonify({'error': 'Server is busy. Try later!'}), 500

@user_blueprint.route('/get_user_as_admin', methods=['POST'])
@cross_origin()
@jwt_required()
def get_user_as_admin():
    data = request.get_json()
    userIndex = data['user']
    user = User.get_by_index(userIndex)
    if user:
        return user.json(), 200
    else:
        return jsonify({'error': 'Not found user!'}), 400

@user_blueprint.route('/get_users', methods=['POST'])
@jwt_required()
def get_users():
    try:
        data = request.get_json()
        userId = data['userId']
        user = User.get_by_userID(userId)
        if user.role == 'user':
            return jsonify({'message': 'No access!'}), 403
        
        users = User.get_all_users()
        user_list = []
        for user in users:
            user_data = user.json()
            user_list.append(user_data)

        return jsonify(user_list), 200
    except Exception as e:
        print('Error in get_users()', str(e))
        return jsonify({'messsage':'Server Error!'}), 500
        
@user_blueprint.route('/update_user', methods=['POST'])
@cross_origin()
@jwt_required()
def update_user():
    data = request.get_json()
    user = User.get_by_userID(data['userId'])
    if user:
        user.first_name = data['first_name']
        user.last_name = data['last_name']
        user.email = data['email']
        user.language = get_language_code(data['language'])
        # user.password = generate_password_hash(data['password'])
        user.com_name = data['com_name']  or ""
        user.com_vat = data['com_vat'] or ""
        user.com_street = data['com_street'] or ""
        user.com_city = data['com_city'] or ""
        user.com_country = data['com_country'] or ""
        user.com_street_number = data['com_street_number'] or ""
        user.com_website = data['com_website'] or ""
        user.com_postal = data['com_postal'] or ""
        data["botsActive"] = user.botsActive
        if update_mautic_user(data, user.mauticId) == 'error':
            return jsonify({'error': 'Not found user!'}), 400
        user.save()
        return jsonify({'message': 'success'}), 201
    else:
        return jsonify({'error': 'Not found user!'}), 400

@user_blueprint.route('/forgot_password', methods=['POST'])
@cross_origin()
def forgot_password():
    data = request.get_json()
    email = data['email']
    user = User.get_by_email(email)

    if not user:
        return 'User not found', 404
    
    # Generate a token
    serializer = URLSafeTimedSerializer(current_app.config['JWT_SECRET_KEY'])
    token = serializer.dumps(email, salt='email-confirm')

    url = request.host_url + 'reset/l'
    user = User.query.filter_by(email=email).first()

    reset_url = f'https://login.aiana.io/reset-password?token={token}'
    data['password_reset_link'] = reset_url
    if mautic_reset_password(data, user.mauticId) == 1:
        return jsonify({'message': 'Password reset link sent to email!'}), 200
    else:
        return jsonify({'message': 'Error sending email!'}), 500

@user_blueprint.route('/send_verification_link', methods=['POST'])
@cross_origin()
def send_link():
    data = request.get_json()
    email = data['email']
    user = User.get_by_email(email)

    if not user:
        print("User not found")
        return 'User not found', 404
    
    serializer = URLSafeTimedSerializer(current_app.config['JWT_SECRET_KEY'])
    verification_token = serializer.dumps(email, salt='email-confirm')
    verification_link = f'https://login.aiana.io/signup/verify-email?token={verification_token}'
    if mautic_send_verfication_link(verification_link, user.mauticId) == 'success':
        User.save_verification_token(email, verification_token)
        return jsonify({'message': 'New verification email is successfully sent. Please, check your email...'}), 200
    else:
        return jsonify({'message': 'Sending error'}), 500

@user_blueprint.route('/reset_with_token', methods = ['GET', 'POST'])
def reset_with_token():
    data = request.get_json()
    print(data)
    password = data['password']
    token = data['token']
    print(current_app.config['JWT_SECRET_KEY'])
    serializer = URLSafeTimedSerializer(current_app.config['JWT_SECRET_KEY'])
    try:
        email = serializer.loads(token, salt='email-confirm', max_age=3600)
        print(email)
        user = User.get_by_email(email)
        user.password = generate_password_hash(password)
        user.save()

        return jsonify({'message': 'success'}), 201
        
    except SignatureExpired:
        return jsonify({'message': 'The password reset link is expired'}), 400

    except Exception as e:
        print(str(e))
        return jsonify({'message':'Server Error'}), 500

@user_blueprint.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    current_user = get_jwt_identity()
    new_access_token = create_access_token(identity=current_user, expires_delta=datetime.timedelta(hours=1))
    return jsonify(access_token=new_access_token), 201

@user_blueprint.route('/get_billing_info', methods=['POST'])
def get_billing_info():
    data = request.get_json()
    email = data['email']
    user = User.query.filter_by(email=email).first()
    return jsonify({'plan':user.billing_plan, 'status':user.status, 'isVerified': user.isVerified}), 200


@user_blueprint.route('/email_verification', methods=['GET','POST'])
def email_verification():
    try:
        data = request.get_json()
        token = data['token']
        serializer = URLSafeTimedSerializer(current_app.config['JWT_SECRET_KEY'])
        email = serializer.loads(token, salt='email-confirm', max_age=300)
        print("email verification", email)
        user = User.query.filter_by(verification_token=token).first()
        print("user verification", user.email)
        if user.email == email:
            user.isVerified = True
            user.verification_token = None
            user.save()
            access_token = create_access_token(identity=user.id, expires_delta=datetime.timedelta(hours=1))
            send_registration_mail(data=user.language, mauticId=user.mauticId)
            return jsonify({'accessToken': access_token, 'userId':user.id, 'userIndex':user.index, 'firstName':user.first_name, 'lastName':user.last_name, 'role':user.role, 'plan':user.billing_plan, 'status':user.status, 'isVerified':user.isVerified}), 200
        return jsonify({'message': 'Invalid verification token'}), 400
    except SignatureExpired:
        return jsonify({'message': 'The verification link is expired'}), 400
