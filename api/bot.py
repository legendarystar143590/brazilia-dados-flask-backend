from flask import Blueprint, request, jsonify, current_app, send_from_directory
from werkzeug.utils import secure_filename
from models import Bot, KnowledgeBase, Conversation, ChatLog, BillingPlan, User
from flask_jwt_extended import jwt_required
from sqlalchemy.exc import IntegrityError
from utils.provider import generate
from utils.common import upload_image_to_spaces, get_url_from_name
import uuid
from datetime import datetime
import os
from api.mautic import get_access_token, login_mautic

bot_blueprint = Blueprint('bot_blueprint', __name__)

@bot_blueprint.route('/create_bot', methods=['POST'])
@jwt_required()
def create_bot():
    try:
        data = request.form
        # print(data)
        name = data['name']
        user_id = data['user_id']
        avatar = request.files.get('avatar')
        color = data['color'] 
        active = data.get('active') == 'true'
        start_time = data['start_time'] 
        end_time = data['end_time'] 
        knowledge_base = data['knowledge_base']

        # Get user from id
        user = User.get_by_userID(user_id)

        userBillingPlan = user.billing_plan
        bots = Bot.get_bots_from_user_id(user_id=user_id)

        # Check the limitation
        limits = BillingPlan.get_by_code(userBillingPlan).max_parallel_bots
        if limits < len(bots) + 1:
           return jsonify({'error': 'limit'}), 403
 

    
        unique_filename = ''
        index = str(uuid.uuid4())
        if avatar:
            unique_filename = index + '_' + avatar.filename
            avatar.save(os.path.join('uploads/images', unique_filename))
            avatar_path = os.path.join('uploads/images', unique_filename)
            image_url = upload_image_to_spaces(avatar_path, "aiana", unique_filename)
            # After processing is done, delete the file
            if os.path.exists(avatar_path):
                os.remove(avatar_path)
                print(f"Deleted file: {avatar_path}")
        else:
            bin_image = None
        new_bot = Bot(user_id=user_id, name=name, index=index,  avatar=unique_filename, color=color, active=active, start_time=start_time, end_time=end_time, knowledge_base=knowledge_base)
        print("Start time >>>",new_bot.start_time)
        new_bot.save()
        user = User.query.filter_by(id=user_id).first()
        user.botsActive = int(user.botsActive) + 1
        user.save()
        mauticData = {}
        total_bots = Bot.query.filter_by(user_id=user.id).count()
        active_bots = Bot.query.filter_by(user_id=user.id, active=1).count()
        mauticData["language"] = user.language
        mauticData["aiana_status"]= "active"
        mauticData["bots_active"] = active_bots
        mauticData["bots_registered"] = total_bots
        mauticData["first_name"]= user.first_name
        mauticData["last_name"]= user.last_name
        mauticData["email"]= user.email
        mauticData["com_name"]= user.com_name
        mauticData["com_vat"]= user.com_vat
        mauticData["com_street"]= user.com_street
        mauticData["com_street_number"]=user.com_street_number
        mauticData["com_postal"]=user.com_postal
        mauticData["com_city"]=user.com_city
        mauticData["com_country"]=user.com_country  
        mauticData["com_website"]=user.com_website
        if login_mautic(mauticData, user.mauticId) == 'error':
            return jsonify({'error': 'Server is busy. Try again later!'}), 400


        return jsonify({'message': 'Success'}), 201

    except Exception as e:
        print(e)
        return jsonify({'error':'Server is busy!'}), 500

@bot_blueprint.route('/get_chatbots', methods=['GET'])
@jwt_required()
def get_chatbots():
    try:
        
        user_id = request.args.get('userId')
        if not user_id:
            return jsonify({'error': 'user_id is required'}), 400

        bots = Bot.query.filter_by(user_id=user_id).all()
        bot_list = []
        for bot in bots:
            knowledgebase = KnowledgeBase.query.filter_by(unique_id=bot.knowledge_base).first()
            bot_data = bot.json()  # Assuming that this method converts the bot instance to a dict
            if bot.avatar:  # Check if the bot has an avatar
                avatarUrl = get_url_from_name(bot.avatar)
                bot_data['avatar'] = avatarUrl
            else:
                bot_data['avatar'] = ""  # No avatar case
            bot_data['knowledgebase_name'] = knowledgebase.name
            bot_list.append(bot_data)

        return jsonify(bot_list), 200
    except ValueError:
        # If the provided user_id cannot be converted to an integer, return an error
        return jsonify({'error': 'Invalid user_id format. It should be an integer.'}), 400

@bot_blueprint.route('/get_chatbot_data', methods=['GET'])
@jwt_required()
def get_chatbot_data():
    try:
        bot_id = request.args.get('botId')
        user_id = request.args.get('userId')
        if not bot_id:
            return jsonify({'error': 'bot_id is required'}), 400
        bot_data = {}
        if bot_id != '-1' and bot_id!='undefined':
            bot = Bot.get_by_id(bot_id)
            bot_data = bot.json()
            # print(bot_data)
            if bot.avatar:  # Check if the bot has an avatar
                avatarUrl = get_url_from_name(bot.avatar)
                bot_data['avatar'] = avatarUrl
            else:
                bot_data['avatar'] = ""  # No avatar case
            if bot_data['knowledge_base'] != "-1":
                print(bot_data['knowledge_base'])
                knowledge_base = KnowledgeBase.query.filter_by(unique_id=bot_data['knowledge_base']).first()
                if knowledge_base:
                    print(knowledge_base)
                    bot_data['knowledge_base'] = knowledge_base.name
                else:
                    bot_data['knowledge_base'] = ''
        else:
            bot_data = '-1'
        if not user_id:
            return jsonify({'error': 'user_id is required'}), 400

        bases = KnowledgeBase.query.filter_by(user_id=user_id).all()
        knowledge_bases_list = [base.json() for base in bases]
        return jsonify({'bot_data':bot_data, 'knowledge':knowledge_bases_list}), 200

    except ValueError:
        # If the provided user_id cannot be converted to an integer, return an error
        return jsonify({'error': 'Invalid bot_id format. It should be an integer.'}), 400

    except Exception as e:
        print("Error:", str(e))
        return jsonify({'error': 'Server error.'}), 400

@bot_blueprint.route('/del_bot', methods=['POST'])
@jwt_required()
def del_bot():
    try:
        data = request.get_json()
        bot_id = data["botId"]
        print(bot_id)
        if not bot_id:
            return jsonify({'error': 'bot_id is required'}), 400

        Bot.del_by_id(bot_id)
        return jsonify({'message':'success'}), 201

    except ValueError:
        # If the provided user_id cannot be converted to an integer, return an error
        return jsonify({'error': 'Invalid bot_id format. It should be an integer.'}), 400

    except Exception as e:
        print("Error:", str(e))
        return jsonify({'error': 'Server error.'}), 400

@bot_blueprint.route('/get_embedding', methods=['GET'])
def get_embeddings():
    try:
        botIndex = request.args.get('botIndex')
        userIndex = request.args.get('userIndex')
        print(botIndex)
        bot_data = {}
        
        if botIndex!=None:
            bot = Bot.get_by_index(botIndex)
            bot_data = bot.json()
            # print(bot_data)
            if bot.avatar:  # Check if the bot has an avatar
                avatarUrl = get_url_from_name(bot.avatar)
                bot_data['avatar'] = avatarUrl
            else:
                bot_data['avatar'] = ""  # No avatar case
        if userIndex != None:
            user = User.get_by_index(userIndex)
            bot_data['user_id'] = user.id 
        return jsonify({'bot': bot_data}), 200
    except Exception as e:
        print(str(e))
        return jsonify({'error':'Server Error'}), 500

@bot_blueprint.route('/update_chatbot', methods=['POST'])
@jwt_required()
def update_chatbot():
    try:
        botId = request.args.get('botId')
        data = request.form
        # Retrieve the existing knowledge base entry using the provided botId
        bot = Bot.query.filter_by(id=botId).first()
        if not bot:
            return jsonify({"error": "Knowledge base entry not found."}), 404
       
        # Extract the relevant information from the form
        name = data['name']
        user_id = data['user_id']
        avatar = request.files.get('avatar')
        color = data['color'] 
        active = data.get('active') == 'true'
        start_time = data['start_time'] 
        end_time = data['end_time'] 
        knowledge_base = data['knowledge_base']
        unique_filename = ''
        print(bot.avatar)
        if avatar:
            if bot.avatar:
                unique_filename = bot.avatar
            else:
                unique_filename = str(uuid.uuid4()) + '_' + avatar.filename
            avatar.save(os.path.join('uploads/images', unique_filename))
            avatar_path = os.path.join('uploads/images', unique_filename)
            image_url = upload_image_to_spaces(avatar_path, "aiana", unique_filename)
            if os.path.exists(avatar_path):
                os.remove(avatar_path)
                print(f"Deleted file: {avatar_path}")
        else:
            unique_filename = bot.avatar
        bot.name = name
        bot.avatar = unique_filename
        bot.color = color
        bot.active = active
        bot.start_time = start_time
        bot.end_time = end_time
        bot.knowledge_base = knowledge_base
        bot.save()

        return jsonify({'message': 'Success'}), 201
    except Exception as e:
        print("Error:", str(e))
        return jsonify({"error": "Server error"}), 500
    
@bot_blueprint.route('/query', methods=['POST'])
def query():
    try:
        data = request.get_json()
        query = data['input']
        bot_id = data['botId']
        user_id = data['userId']
        session_id = data['sessionId']
        created_at = data['createdAt']
        website = data['website']
        # Check the limits
        chat_log = ChatLog.get_by_session(session_id)
        logs = ChatLog.get_logs_by_bot_id(bot_id=bot_id)
        user = User.get_by_userID(id=user_id)
        sessionLimits = BillingPlan.query.filter_by(code=user.billing_plan).first().max_sessions_per_month
        # print(sessionLimits)
        # print(bot_id)
        # print(logs)
        if sessionLimits <= len(logs) and website != None:
            if chat_log is None:
                return jsonify({'error': 'Maximum Session Exceeds'}), 403
             
        # lang = data['lang']
        # language_codes = {
        #     10: 'English',
        #     20: 'Dutch',
        #     30: 'French',
        #     40: 'Spanish'
        # }
        # if lang in language_codes:
        #     lang = language_codes[lang]
        # else:
        #     lang = 'English'
        # print("Respond >>>>", created_at)
        if bot_id:
            bot = Bot.query.filter_by(id=bot_id).first()
        knowledge_base = bot.knowledge_base
        result = generate(bot_id, session_id, query, knowledge_base)
        solve = True
        if "If so, leave me your email" in result or "votre adresse e-mail" in result or "correo electrónico" in result or "laissez-moi votre" in result or "laat me dan je e-mailadres achter" in result:
            solve = False
        if chat_log:
            chat_log.ended_at = created_at
            chat_log.save()
        else:
            new_log = ChatLog(user_id, bot.id, website, session_id, created_at, created_at)
            new_log.save()

        return jsonify({'message': result, 'solve':solve}), 200
    except Exception as e:
        print(str(e))
        return jsonify({'error': 'Server Error'}), 500

@bot_blueprint.route('/del_messages', methods=['POST'])
@jwt_required()
def del_messages():
    try:
        data = request.get_json()
        bot_id = data['bot_id']
        Conversation.del_by_bot_id(bot_id)
        return jsonify({'status': 'success'}), 201
        
    except Exception as e:
        print(str(e))
        return jsonify({'status':'error'}), 500
    

    
