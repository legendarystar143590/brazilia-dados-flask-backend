from flask import Blueprint, request, jsonify, current_app
from dotenv import load_dotenv
import os
import stripe
import json
from models import User, BillingPlan

load_dotenv()

payment_blueprint = Blueprint('payment_blueprint', __name__)

stripe_keys = {
    "secret_key": os.environ["STRIPE_SECRET_KEY"],
    "publishable_key": os.environ["STRIPE_PUBLISHABLE_KEY"],
    "endpoint_secret":os.environ["STRIPE_ENDPINT_SECRET"]
}
domain_url = os.environ["FRONTEND_DOMAIN"]

stripe.api_key = stripe_keys["secret_key"]


print(stripe_keys["secret_key"])
print(stripe_keys["publishable_key"])
print(stripe_keys["endpoint_secret"])

# @payment_blueprint.route('/create-checkout-session', methods=['POST'])
# def create_checkout_session():
#     try:
#         # Create new checkout session for the order
#         data = request.get_json()
#         checkoutSession = stripe.checkout.Session.create (
#             payment_method_types=["card"],
#             mode="subscription",
#             line_items=[{"price":data["price_id"], "quantity":1}],
#             success_url=f"{domain_url}/success?session_id={CHECKOUT_SESSION_ID}",
#             cancel_url=f"{domain_url}/cancel",
#         )

#         return jsonify({"sessionId":checkoutSession.id})
    
#     except Exception as e:
#         return jsonify(error=str(e)), 403

def create_customer_id(email):
    customer = stripe.Customer.create(email=email)
    return customer.id

@payment_blueprint.route('/create-checkout-session', methods=['POST'])
def create_checkout_session():
    try:
        data = request.get_json()
        price_id = data.get('priceId')
        user_email = data.get('email')
        print(price_id)
        if not price_id:
            return jsonify({'error': 'Price ID is required'}), 400

        session = stripe.checkout.Session.create(
            customer_email=user_email,
            # submit_type='subscribe',
            line_items=[
                {
                    'price': price_id,
                    'quantity': 1,
                },
            ],
            mode='subscription',
            success_url=request.headers.get('origin') + '/billing-plan?success=true',
            cancel_url=request.headers.get('origin') + '/billing-plan?success=false',
        )
        return jsonify({'sessionId':session.url}), 201

    except stripe.error.StripeError as e:
        return jsonify({'error': str(e), 'statusCode': e.http_status}), e.http_status
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
@payment_blueprint.route('/create_new_url', methods=['POST'])
def create_new_url():
    try:
        data = request.get_json()
        user = User.get_by_email(data['email'])
        if user.stripe_customer_id:
            customer = stripe.Customer.retrieve(user.stripe_customer_id)
            session = stripe.billing_portal.Session.create(
                customer=customer.id,
                return_url="https://login.aiana.io/admin"
            )
            return jsonify({"sessionId":session.url}), 200
        else:
            customer = stripe.Customer.create(email=data['email'])
            user.stripe_customer_id = customer.id
            user.save()
            session = stripe.billing_portal.Session.create(
                customer=customer.id,
                return_url="https://login.aiana.io/admin"
            )
            return jsonify({"sessionId":session.url}), 200
    except Exception as e:
        return jsonify(error=str(e)), 403

@payment_blueprint.route("/webhook", methods=["POST"])
def stripe_webhook():
    payload = request.get_data(as_text=False)
    sig_header = request.headers.get("Stripe-Signature")
    try:        
        event = stripe.Webhook.construct_event(
            payload, sig_header, stripe_keys["endpoint_secret"]
        )

    except ValueError as e:
        # Invalid payload
        return "Invalid payload", 400
    except stripe.error.SignatureVerificationError as e:
        # Invalid signature
        return "Invalid signature", 400
    print("event type----->", event["type"])
    # Handle the checkout.session.completed event
    if event["type"] == "customer.subscription.created":
        subscription = event['data']['object']
        prod_id = subscription['plan']['product']
        # print(prod_id)
        customer_id = subscription['customer']
        customer = stripe.Customer.retrieve(customer_id)
        customer_email = customer['email']
        # print(customer_email)
        user = User.query.filter_by(email=customer_email).first()
        # print(user)
        if user:
            user.stripe_customer_id = customer_id
            plan = BillingPlan.query.filter_by(prod_id=prod_id).first()
            print(plan.code)
            user.billing_plan = plan.code
            user.status = 'active'
            user.save()
        print("Subscription created")

    if event["type"] == "checkout.session.completed":
        print("Payment was successful.")
        # print(event['data']['object'])
        subscription = event['data']['object']
        # customer_email = subscription.customer_email
        prod_id = subscription['plan']['product']
        print(prod_id)
        customer_id = subscription['customer']
        customer = stripe.Customer.retrieve(customer_id)
        customer_email = customer['email']
        # print(customer_email)
        user = User.query.filter_by(email=customer_email).first()
        # print(user)
        if user:
            user.stripe_customer_id = customer_id
            plan = BillingPlan.query.filter_by(prod_id=prod_id).first()
            print(plan.code)
            user.billing_plan = plan.code
            user.status = 'active'
            user.save()
        # product_id = subscription['price']['product']
        # print("Customer --->  ", customer_email)
        # print("Product --->  ", product_id)
        # TODO: run some custom code here
    
    if event["type"] == "customer.subscription.updated":
        # print(event['data']['object'])
        subscription = event['data']['object']
        prod_id = subscription['plan']['product']
        previous_attributes = event['data']['previous_attributes']
        customer_id = subscription['customer']
        customer = stripe.Customer.retrieve(customer_id)
        customer_email = customer['email']
        # print(customer_email)
        user = User.query.filter_by(email=customer_email).first()
        # print(user)
        if user:   
            if previous_attributes.get('cancel_at_period_end') == True or previous_attributes.get('cancel_at_period_end') == None:
                user.stripe_customer_id = customer_id
                plan = BillingPlan.query.filter_by(prod_id=prod_id).first()
                print(plan.code)
                user.billing_plan = plan.code
                user.status = 'active'
                user.save()
            elif previous_attributes.get('cancel_at_period_end') == False:
                user.stripe_customer_id = customer_id                
                user.billing_plan = "aiana_try"
                print(user.billing_plan)
                user.status = 'active'
                user.save()               

        # plan_id = subscription['items']['data'][0]['price']['product']
        print("Updated")
    
    # if event["type"] == "customer.subscription.paused":
    #     print("Paused")

    # if event["type"] == "subscription_schedule.canceled":
    #     print("Plan canceled!")
    
    # if event["type"] == "invoice.payment_succeeded":
    #     print(event)
    #     print("Invoice paid")
    
    if event["type"] == "invoice.payment_failed":
        subscription = event['data']['object']
        prod_id = subscription['plan']['product']
        # print(prod_id)
        customer_id = subscription['customer']
        customer = stripe.Customer.retrieve(customer_id)
        customer_email = customer['email']
        # print(customer_email)
        user = User.query.filter_by(email=customer_email).first()
        # print(user)
        if user:
            user.stripe_customer_id = customer_id
            user.billing_plan = "aiana_try"
            user.save()

        print("Update user profile")
    # Subscription deleted
    if event["type"] == "customer.subscription.deleted":
        subscription = event['data']['object']
        prod_id = subscription['plan']['product']
        # print(prod_id)
        customer_id = subscription['customer']
        customer = stripe.Customer.retrieve(customer_id)
        customer_email = customer['email']
        # print(customer_email)
        user = User.query.filter_by(email=customer_email).first()
        # print(user)
        if user:
            user.stripe_customer_id = customer_id
            
            user.billing_plan = "aiana_try"
            user.status = 'cancel'
            user.save()
        print("Update user profile")
    return "Success", 200