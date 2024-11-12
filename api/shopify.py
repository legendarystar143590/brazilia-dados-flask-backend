from flask import Blueprint, Flask, request, jsonify, redirect, url_for, current_app
from flask_jwt_extended import jwt_required
from dotenv import load_dotenv
import requests
import hmac
import hashlib
import base64
import os
import json
from datetime import datetime
from models import ShopInfo, ProudctsTable, User, Bot, RegisteredWebsite
from utils.provider import tiktoken_products_split, generate_kb_from_products
from utils.vectorizor import delDocument

load_dotenv()

SHOPIFY_SECRET_KEY = os.getenv("SHOPIFY_SECRET_KEY")
SHOPIFY_API_KEY = os.getenv("SHOPIFY_API_KEY")
REDIRECT_URI = os.getenv("REDIRECT_URL")

shopify_blueprint = Blueprint('shopify_blueprint', __name__)

def verify_webhook(data: bytes, hmac_header: str) -> bool:
    """
    Verifies the HMAC of incoming webhook data against a provided HMAC header.
    """
    digest = hmac.new(SHOPIFY_SECRET_KEY.encode('utf-8'), data, hashlib.sha256).digest()
    print("digest", digest)
    computed_hmac = base64.b64encode(digest).decode('utf-8')
    print("computed_hmac", computed_hmac)
    return hmac.compare_digest(computed_hmac, hmac_header)

@shopify_blueprint.route('/shopifyinstall', methods=['GET', 'POST'])
def install():
    try:
        # headers = dict(request.headers)
        # body = request.get_data()
        # print("header--->>>>>", headers, "body--->>>>>", body)
        # shop = request.args.get('shop')
        # timestamp = request.args.get('timestamp')
        # hmac_header = request.args.get('hmac')
        # state = request.args.get('state')
        # # Verify the webhook using the provided parameters
        # data = f'shop={shop}&timestamp={timestamp}&state={state}'.encode('utf-8')
        # if verify_webhook(data, hmac_header):
        #     # Store the shop code and state securely (implement your own storage logic)
        #     store_shop_data(shop, state)
        #     print("Verification successful")
        #     # Redirect to Shopify authorization URL
        #     return redirect(f'https://{shop}/admin/oauth/authorize?client_id={SHOPIFY_API_KEY}&scope=read_products&redirect_uri={REDIRECT_URI}&state={state}')
        
        # return "Verification failed", 403
        print("shopify install")
        shop = request.args.get('shop')
        shop_token = request.args.get('shopify_shop_token')
        shopify_token = request.args.get('shopify_token')
        if not shop or not shop_token or not shopify_token:
            return jsonify({'status': 'error', 'message': 'Invalid request'}), 400
        print("shop", shop, "shop_token", shop_token, "shopify_token", shopify_token)
        print(ShopInfo.check_shop_exist(shop))
        if ShopInfo.check_shop_exist(shop):
            print("shop already exist")
            ShopInfo.update_shop_info(shop, shop_token, shopify_token)
            return jsonify({'status': 'success', 'message': 'Shop updated successfully'}), 200

        new_shop = ShopInfo(shop=shop, shop_token=shop_token, shopify_token=shopify_token)
        print("shop not exist", new_shop)
        new_shop.save()
        return jsonify({'status': 'success', 'message': 'Shop created successfully'}), 200
    except Exception as e:
        print("Error:", e)
        return "An error occurred", 500

@shopify_blueprint.route('/shopifyauth', methods=['GET', 'POST'])
def auth_callback():
    try:
        headers = dict(request.headers)
        body = request.get_data()
        print("header--->>>>>", headers, "body--->>>>>", body)
        code = request.args.get('code')
        shop = request.args.get('shop')
        state = request.args.get('state')
        timestamp = request.args.get('timestamp')
        hmac_header = request.args.get('hmac')
        print("shop", shop)
        data = f'shop={shop}&code={code}&state={state}&timestamp={timestamp}'.encode('utf-8')
        # Verify that state matches what was stored during installation
        if verify_webhook(data, hmac_header):
            print("Verification successful")
            if verify_state(shop, state):
                print("State verification successful")
                # Store the hashed code with the shop code securely (implement your own storage logic)
                access_token = get_access_token(shop, code)
                store_hashed_code(shop, code, access_token)

                products = get_shopify_products(shop, access_token)
                current_shop = ShopInfo.query.filter_by(shop = shop).first()            
                for product in products:
                    insert_product_data(product, current_shop.id)

                activebots = get_active_chatbots(shop)[0].get_json()

                return {'status':"success",'message':f'Authorization successful', 'activebots': activebots}, 200
        
        return "State verification failed", 403
    except Exception as e:
        print("Error:", e)
        return "Error occurred", 500

@shopify_blueprint.route('/active_chatbots', methods=['GET', 'POST'])
def get_active_chatbots(shop=None):
    try:
        if not shop:
            shop = request.args.get('shop')
            print("shop", shop)
            shop_token = request.args.get('shopify_shop_token')
            print("shop_token", shop_token)
        db_shop = ShopInfo.get_by_shop(shop)
        
        if not db_shop:
            return jsonify({"error": "Please obtain a valid eCommerce license in Aiana to let your website visitors answer questions about your products."}), 403
        
        if shop_token != db_shop.shop_token or shop_token is None:
            return jsonify({"error": "Invalid shop token"}), 403

        shop_url = f"https://{shop}"
        print("shop_url", shop_url)
        registered_website = RegisteredWebsite.query.filter_by(domain=shop_url).first()
        print("registered_website", registered_website.bot_id)
        if not registered_website:
            return jsonify({"error": "Website not registered"}), 404
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
        })
        db_products = ProudctsTable.query.filter_by(shop_id = db_shop.id).first()
        if db_products:
            return jsonify({"error": "Bot already installed"}), 403
        products = get_shopify_products(shop, db_shop.shopify_token)
        if update_knowledgebase_by_unique_id(db_shop.id, shop, products):
            ShopInfo.update_connected_bot(shop, bot.index)          
            return jsonify(response), 200
        else:
            return jsonify({"error": "Failed to update knowledgebase"}), 500
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@shopify_blueprint.route('/uninstall_app', methods=['GET', 'POST'])
def shopify_webhook():
    try:
        if request.method == 'POST':
            headers = dict(request.headers)
            data = request.get_json()
            shop = data['shop']
            print("header--->>>>>", headers, "body--->>>>>", data)
            print("shopify webhook")
        elif request.method == 'GET':
            shop = request.args.get('shop')
        print("shop", shop)
        db_shop = ShopInfo.get_by_shop(shop)
        db_products = ProudctsTable.query.filter_by(shop_id=db_shop.id).first()
        if delDocument(db_products.product_unique_id, db_products.id, "products"):
            ProudctsTable.query.filter_by(shop_id=db_shop.id).delete()
            ShopInfo.query.filter_by(shop=shop).delete()
            # ShopInfo.del_by_shop(shop)
            shop_url = f"https://{shop}"
            if RegisteredWebsite.check_shopify_domain(shop_url):
                RegisteredWebsite.query.filter_by(domain=shop_url).delete()
                print("RegisteredWebsite deleted")
                # current_website = RegisteredWebsite.query.filter_by(domain=shop_url).first()
                # RegisteredWebsite.del_by_index(current_website.index)
            return jsonify({'status': 'success', 'message': 'Uninstall successfully'}), 200
        else:
            return jsonify({'status': 'failed', 'message': 'Failed remove knowledgebase'}), 400
    except Exception as e:
        return jsonify({'status':'failed',"error": str(e)}), 500

def store_shop_data(shop: str, state: str):
    """
    Store shop data securely (implement your own storage logic).
    """
    print(f"Storing shop: {shop}, state: {state}")

    if ShopInfo.check_shop_exist(shop):
        return jsonify({'error': 'Shop already exists'}), 409
    
    new_shop = ShopInfo(shop=shop, state=state, code='')
    print(new_shop)
    


def store_hashed_code(shop: str, code: str, access_token: str):
    """
    Store hashed authorization code securely (implement your own storage logic).
    """
    hashed_code = hash_code(code)  # Implement your hashing logic here
    print(f"Storing hashed code for shop {shop}: {hashed_code}")

    if ShopInfo.check_shop_exist(shop) == False:
        return jsonify({'error':'Shop is not exist'}), 409
    
    ShopInfo.update_shop_info(shop, code, access_token)

def verify_state(shop: str, state: str) -> bool:
    """
    Verify that the state matches what was stored during installation.
    """
    # Implement your logic to retrieve and compare stored state
    db_shop = ShopInfo.query.filter_by(shop=shop).first()
    if db_shop.state == state and state != '':
        return True  # Replace with actual comparison logic
    return False

def hash_code(code: str) -> str:
    """
    Hash the authorization code for secure storage.
    """
    return hashlib.sha256(code.encode()).hexdigest()

def get_access_token(shop: str, code: str) -> str:
    """
    Retrieve the access token for a given shop using the provided code.
    """
    # Implement your logic to retrieve the access token using the provided code
    # This is a placeholder and should be replaced with actual API calls
    new_url = f'https://{shop}/admin/oauth/access_token'
    data = {
        'client_id': SHOPIFY_API_KEY,
        'client_secret': SHOPIFY_SECRET_KEY,
        'code': code
    }
    response = requests.post(new_url, data=data)
    if response.status_code == 200:
        return response.json()['access_token']
    else:
        return None

def get_current_api_version() -> str:
    """
    Determine the current Shopify API version based on the release schedule.
    
    :return: The latest stable API version in 'YYYY-MM' format.
    """
    now = datetime.utcnow()
    year = now.year
    
    # Determine the current quarter and set the version accordingly
    if now.month >= 10:  # October, November, December
        return f"{year}-10"
    elif now.month >= 7:  # July, August, September
        return f"{year}-07"
    elif now.month >= 4:  # April, May, June
        return f"{year}-04"
    else:  # January, February, March
        return f"{year}-01"

# Example usage
api_version = get_current_api_version()
print(f"Current Shopify API Version: {api_version}")

def get_shopify_products(shop: str, shopify_token: str) -> list:
    """
    Retrieve products from Shopify using the provided access token.
    """
    # Implement your logic to retrieve products using the provided access token
    # This is a placeholder and should be replaced with actual API calls
    try:
        api_version = get_current_api_version()
        print(api_version)
        new_url = f'https://{shop}/admin/api/{api_version}/products.json'
        headers = {
            'Content-Type': 'application/json',
            'X-Shopify-Access-Token': shopify_token
        }
        response = requests.get(new_url, headers=headers)
        # print(response.json()['products'])
        if response.status_code == 200:
            return response.json()['products']
        else:
            return []
    except Exception as e:
        print(e)
        return []
    
def insert_product_data(product: dict, shop_id: int):
    """
    Insert product data into the database.
    """
    # Implement your logic to insert product data into the database
    # This is a placeholder and should be replaced with actual database operations
    try:
        new_product = ProudctsTable(shop_id=shop_id, product_id=product['id'], product_type=product['product_type'], product_title=product['title'], product_price=product['variants'][0]['price'], created_at=product['created_at'])
        new_product.save()
        # print(new_product)
        return jsonify({'status':'success'}), 200
    except Exception as e:
        print("error", e)
        return jsonify({'status':'failed'}), 400

# def sync_products():
#     """
#     Synchronize products from Shopify to the database.
#     """
#     # Implement your logic to synchronize products from Shopify to the database
#     # This is a placeholder and should be replaced with actual API calls
#     print("sync_products()")
#     try:
#         with current_app.app_context():
#             ProudctsTable.clear_all_products()
#             shops = ShopInfo.query.all()
#             print("sync_products()", shops)
#             for shop in shops:
#                 shopify_token = shop.shopify_token
#                 if shopify_token == '':
#                     continue
#                 products = get_shopify_products(shop.shop, shopify_token)
#                 print("get_shopify_products", products)
#                 for product in products:
#                     insert_product_data(product, shop.id)
#         return jsonify({'message': 'Products synchronized successfully'}), 200
#     except Exception as e:
#         print(e)
#         return jsonify({'error': 'Failed to synchronize products'}), 500

def get_products_knowledgebase_unique_id_by_shop(shop):
    try:
        shop_url = f"https://{shop}"
        registered_website = RegisteredWebsite.query.filter_by(domain = shop_url).first()

        if registered_website.bot_id is None:
            return None
        
        bot = Bot.query.filter_by(id = registered_website.bot_id).first()
        
        if bot is None:
            return None
        
        return registered_website.index
    except Exception as e:
        print(f"Error getting knowledge base ID: {str(e)}")
        return None

def update_knowledgebase_by_unique_id(shop_id, shop_shop, products):
    try:
        products_text = json.dumps(products, indent=2)
        type_of_knowledge = "products"
        registered_website_unique_id = get_products_knowledgebase_unique_id_by_shop(shop_shop)
        print("registered_website_unique_id", registered_website_unique_id)
        new_products = ProudctsTable(shop_id=shop_id, product_type="txt", product_unique_id=registered_website_unique_id)
        new_products.save()
        chunks = tiktoken_products_split(products_text)
        generate_kb_from_products(chunks, registered_website_unique_id, new_products.id, type_of_knowledge)
        return True
    except Exception as e:
        print(e)
        return False

def sync_products():
    """
    Synchronize products from Shopify to the database.
    """
    # Implement your logic to synchronize products from Shopify to the database
    # This is a placeholder and should be replaced with actual API calls
    try:
        with current_app.app_context():
            # ProudctsTable.clear_all_products()
            shops = ShopInfo.query.all()
            print("sync_products()", shops)
            for shop in shops:
                shopify_token = shop.shopify_token
                if not shopify_token:
                    continue

                products = get_shopify_products(shop.shop, shopify_token)
                # print("get_shopify_products", products)
                if products:
                    db_products = ProudctsTable.query.filter_by(shop_id=shop.id).first()
                    if db_products is None:
                        update_knowledgebase_by_unique_id(shop.id, shop.shop, products)
                    else:
                        if delDocument(db_products.product_unique_id, db_products.id, "products"):
                            ProudctsTable.query.filter_by(id=db_products.id).delete()
                            update_knowledgebase_by_unique_id(shop.id, shop.shop, products)
        print("sync_products()", "Products synchronized successfully")
        return jsonify({'message': 'Products synchronized successfully'}), 200
    except Exception as e:
        print(f"Sync error: {str(e)}")
        return jsonify({'error': 'Failed to synchronize products'}), 500
