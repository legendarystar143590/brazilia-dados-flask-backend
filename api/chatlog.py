from flask import Blueprint, request, jsonify, current_app
from models import Bot, KnowledgeBase, Conversation, ChatLog, Order, User
from utils.common import get_url_from_name
from flask_jwt_extended import jwt_required
from utils.provider import generate
import datetime
log_blueprint = Blueprint('log_blueprint', __name__)

@log_blueprint.route('/get_chat', methods=['POST'])
@jwt_required()
def get_chat():
    try:
        data = request.get_json()
        user_id = data['userID']
        chatLog = ChatLog.get_by_user(user_id)
        logLists = []
        
        for log in chatLog:
            log_json = log.json()
            print(log.bot_name)
        
            bot = Bot.query.filter_by(id=log.bot_name).first()
            log_json['bot_name'] = bot.name
            log_json['bot_active'] = bot.active
            if bot.avatar:
                log_json['bot_avatar'] = get_url_from_name(bot.avatar)
            else:
                log_json['bot_avatar'] = '' 
            # start_time = datetime.fromisoformat(log_json["created_at"])
            # end_time = datetime.fromisoformat(log_json["ended_at"])
             
            # # Convert to user-friendly format
            # user_friendly_starttime = start_time.strftime('%Y-%m-%d %I:%M:%S %p')
            # user_friendly_endtime = end_time.strftime('%Y-%m-%d %I:%M:%S %p')
            # log_json["created_at"] = user_friendly_starttime
            # log_json["ended_at"] = user_friendly_endtime
            logLists.append(log_json)
        
        return jsonify(logLists), 200
    
    except Exception as e:
        print(str(e))
        return jsonify({'error':'Server Error!'}), 500

@log_blueprint.route('/get_log_data', methods=['POST'])
@jwt_required()
def get_log_data():
    try:
        data = request.get_json()
        session_id = data['session']
        chatLog = ChatLog.get_by_session(session_id)
        conversations = Conversation.get_by_session(session_id)
        imageUrl = ''

        
        convLists = []
        for log in conversations:
            log_json = log.json()
            # print(log.bot_id)
            # bot = Bot.get_by_id(log.bot_id)
            # print(bot)
            # if bot.avatar and imageUrl == '':
            #     imageUrl = get_url_from_name(bot.avatar)
            convLists.append(log_json)
        # print(convLists)
        user = User.get_by_userID(chatLog.user_id)
        return jsonify({'log':chatLog.json(), 'conversation':convLists, 'bot_avatar':imageUrl, 'user_name':user.first_name + " " + user.last_name, 'user_email':user.email}), 200
    
    except Exception as e:
        print(str(e))
        return jsonify({'error':'Server Error!'}), 500

@log_blueprint.route('/del_chatlog', methods=['POST'])
@jwt_required()
def del_chatlog():
    try:
        data = request.get_json()
        session_id = data['sessionId']
        ChatLog.del_by_session(session_id)
        convs = Conversation.del_by_session_id(session_id)
        
        return jsonify({"message":"success"}), 201
    
    except Exception as e:
        print(str(e))
        return jsonify({'error':'Server Error!'}), 500



