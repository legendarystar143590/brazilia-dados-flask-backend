from flask import Blueprint, Flask, request, jsonify, redirect, url_for, current_app
from flask_jwt_extended import jwt_required
from dotenv import load_dotenv
import requests
import hmac
import hashlib
import base64
import os
from models import ShopInfo, ProudctsTable, User, Bot, RegisteredWebsite

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

@shopify_blueprint.route('/shopifyinstall', methods=['GET'])
def install():
    try:
        shop = request.args.get('shop')
        timestamp = request.args.get('timestamp')
        hmac_header = request.args.get('hmac')
        state = request.args.get('state')
        print("shop", shop)
        # Verify the webhook using the provided parameters
        data = f'shop={shop}&timestamp={timestamp}&state={state}'.encode('utf-8')
        if verify_webhook(data, hmac_header):
            # Store the shop code and state securely (implement your own storage logic)
            store_shop_data(shop, state)
            print("Verification successful")
            # Redirect to Shopify authorization URL
            return redirect(f'https://{shop}/admin/oauth/authorize?client_id={SHOPIFY_API_KEY}&scope=read_products&redirect_uri={REDIRECT_URI}&state={state}')
        
        return "Verification failed", 403
    except Exception as e:
        print("Error:", e)
        return "An error occurred", 500

@shopify_blueprint.route('/shopifyauth', methods=['GET'])
def auth_callback():
    try:
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

# @shopify_blueprint.route('/active_chatbots', methods=['GET'])
def get_active_chatbots(shop:str):
    try:
        # shop = request.args.get('shop')
        shop_info = ShopInfo.get_by_shop(shop)
        
        if not shop_info:
            return jsonify({"error": "Please obtain a valid eCommerce license in Aiana to let your website visitors answer questions about your products."}), 403

        registered_website = RegisteredWebsite.query.filter_by(domain=shop).first()
        if not registered_website:
            return jsonify({"error": "Website not registered"}), 404
        bot = Bot.query.filter_by(index = registered_website.bot_id).first()
        response = []
        response.append({
            "name": bot.name,
            "chatbotid": registered_website.bot_id,
            "userid": registered_website.user_id,
        })

        return jsonify(response), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

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

def get_shopify_products(shop: str, access_token: str) -> list:
    """
    Retrieve products from Shopify using the provided access token.
    """
    # Implement your logic to retrieve products using the provided access token
    # This is a placeholder and should be replaced with actual API calls
    try:
        new_url = f'https://{shop}/admin/api/2023-04/products.json'
        headers = {
            'Content-Type': 'application/json',
            'X-Shopify-Access-Token': access_token
        }
        response = requests.get(new_url, headers=headers)
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
        new_product = ProudctsTable(shop_id=shop_id, product_id=product['id'], product_type=product['type'], product_title=product['title'], product_price=product['price'])
        print(new_product)
        return jsonify({'status':'success'}), 200
    except Exception as e:
        print(e)
        return jsonify({'status':'failed'}), 400

def sync_products():
    """
    Synchronize products from Shopify to the database.
    """
    # Implement your logic to synchronize products from Shopify to the database
    # This is a placeholder and should be replaced with actual API calls
    try:
        with current_app.app_context():
            ProudctsTable.clear_all_products()
            shops = ShopInfo.query.all()
            print("sync_products()", shops)
            for shop in shops:
                access_token = shop.access_token
                if access_token == '':
                    continue
                products = get_shopify_products(shop.shop, access_token)
                for product in products:
                    insert_product_data(product, shop.id)
        return jsonify({'message': 'Products synchronized successfully'}), 200
    except Exception as e:
        print(e)
        return jsonify({'error': 'Failed to synchronize products'}), 500
