from flask import Blueprint, request, jsonify, current_app
from models import Bot, KnowledgeBase, Conversation, ChatLog, Order
from utils.provider import generate
from datetime import datetime
log_blueprint = Blueprint('log_blueprint', __name__)

@log_blueprint.route('/get_chat', methods=['POST'])
def get_chat():
    try:
        data = request.get_json()
        user_id = data['userID']
        chatLog = ChatLog.get_by_user(user_id)
        logLists = []
        for log in chatLog:
            log_json = log.json()
            start_time = datetime.fromisoformat(log_json["created_at"])
            end_time = datetime.fromisoformat(log_json["ended_at"])
             
            # Convert to user-friendly format
            user_friendly_starttime = start_time.strftime('%Y-%m-%d %I:%M:%S %p')
            user_friendly_endtime = end_time.strftime('%Y-%m-%d %I:%M:%S %p')
            log_json["created_at"] = user_friendly_starttime
            log_json["ended_at"] = user_friendly_endtime
            logLists.append(log_json)
        
        return jsonify(logLists), 200
    
    except Exception as e:
        print(str(e))
        return jsonify({'error':'Server Error!'}), 500

@log_blueprint.route('/get_log_data', methods=['POST'])
def get_log_data():
    try:
        data = request.get_json()
        session_id = data['session']
        chatLog = ChatLog.get_by_session(session_id)
        conversations = Conversation.get_by_session(session_id)

        convLists = []
        for log in conversations:
            log_json = log.json()
            start_time = datetime.fromisoformat(log_json["created_at"])
            
            # Convert to user-friendly format
            user_friendly_starttime = start_time.strftime('%Y-%m-%d %I:%M:%S %p')
            log_json["created_at"] = user_friendly_starttime
            convLists.append(log_json)
        
        return jsonify({'log':chatLog.json(), 'conversation':convLists}), 200
    
    except Exception as e:
        print(str(e))
        return jsonify({'error':'Server Error!'}), 500



