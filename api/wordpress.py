from flask import Blueprint, Flask, request, jsonify, redirect, url_for, current_app
from models import WordPressInfor , RegisteredWebsite , Bot , User , ProudctsTable


wordpress_blueprint = Blueprint('wordpress_blueprint', __name__)


@wordpress_blueprint.route('/wordpressinstall' , methods=['GET'])
def install():
    try:
        print("wordpress install called")
        website_url = request.args.get('website_url')
        access_token = request.args.get('access_token')

        if not website_url or not access_token:
            return jsonify({'status': 'error', 'message': 'Invalid request'}), 400
        
        # Check if the WordPress entry already exists in the database
        wordpress_check = WordPressInfor.check_wordpress_exist(website_url , access_token)

        if wordpress_check:
            return jsonify({'status': 'success', 'message': 'WordPress connected'}), 200
    except Exception as e:
        print("Error:", e)
        return "An error occurred", 500


@wordpress_blueprint.route(",getActiveChatbots" , methods = ['GET'])
def getActiveChatbots():
    print("getActiveChatbots called")

    website_url =  request.args.get('website_url')
    access_token = request.args.get('access_token')

    if not website_url or not access_token:
        return jsonify({'status': 'error', 'message': 'Invalid request no website or access_token'}), 400
    
    try:

        db_wordpress = WordPressInfor.get_by_wordpress(website_url)
        if not db_wordpress:
            return jsonify({"error": "Please obtain a valid eCommerce license in Aiana to let your website visitors answer questions about your products."}), 403
        
        if access_token != db_wordpress.wordpress_token:
            return jsonify({"error": "Invalid shop token"}), 403

        wordpress_url = f"https://{website_url}"
        registered_website = RegisteredWebsite.query.filter_by(domain=wordpress_url).first()
        print("The bot_id of registered_website", registered_website.bot_id)
        
        if not registered_website:
            return jsonify({"error": "Website not registered"}), 404
        else :
            bot = Bot.query.filter_by(id = registered_website.bot_id).first()
            user = User.query.filter_by(id = bot.user_id).first()
            print("bot", bot)
            if not bot:
                return jsonify({"error": "Bot not found"}), 404
            response = []
            response.append({
                "name": bot.name,
                "chatbotid": bot.index,
                "userid": user.index,
                "status": bot.active,
                "avatar": bot.avatar,
                "color" : bot.color,
                "knowledge_base": bot.knowledge_base,
            })

            return jsonify(response), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500
