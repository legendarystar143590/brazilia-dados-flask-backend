from dotenv import load_dotenv
import requests
import os
import json
import datetime
load_dotenv()

MAUTIC_BASE_URL = os.getenv('MAUTIC_BASE_URL')
MAUTIC_CLIENT_ID = os.getenv('MAUTIC_CLIENT_ID')
MAUTIC_CLIENT_SECRET = os.getenv('MAUTIC_CLIENT_SECRET')
# Set up the Mautic API client
language_dict = {
    'en': 1,
    'nl': 4,
    'fr': 5
}

def get_mautic_user_by_email(email):
    search_url = f'{MAUTIC_BASE_URL}/api/contacts?search={email}'
    access_token = get_access_token()
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Accept': 'application/json',
    }
    response = requests.get(search_url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        print(data)
        if data['total'] != '0':
            return data['contacts'][0]
    return None

def create_mautic_user(data):
    try:
        payload =  {
            "firstname": data["first_name"],
            "lastname": data["last_name"],
            "email": data["email"],
            "company_name": data["com_name"] or "",
            "company_vat": data["com_vat"] or "",
            "company_street": data["com_street"] or "",
            "company_street_number": data["com_street_number"] or "",
            "company_postal_code": data["com_postal"] or "",
            "company_city": data["com_city"] or "",
            "company_country": data["com_country"] or "",
            "company_website_url": data["com_website"] or "",
            "language": data["language"] or "",
            "aiana_status": "registered",
            "bots_active": 0,
            "aiana_environment": "TEST",
            "license": "FREE",
            "person_source":"APPLICATION",
        }

        create_user_url = f'{MAUTIC_BASE_URL}/api/contacts/new'
        # print(create_user_url)

        access_token = get_access_token()
        # print("Token", access_token)
        # Headers including the access token
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Accept': 'application/json',
        }

        # Sending the POST request
        response = requests.post(create_user_url, data=payload, headers=headers)
        

        # print(response.status_code)
        # print(response.json())
        print("Done")
        if response.status_code == 201:
            print("User created successfully")
            response_data = response.json()
            contact_id = response_data['contact']['id']
            # Checking response
            print("Here is contact id", contact_id)
            return contact_id            
        else:
            return 'error'
        
    except Exception as e:
        print(e)
        return "error"

def update_mautic_user(data, mauticId):
    try:
        payload = {
            "firstname": data["first_name"],
            "lastname": data["last_name"],
            # "email": data["email"],
            "company_name": data["com_name"] or "",
            "company_vat": data["com_vat"] or "",
            "company_street": data["com_street"] or "",
            "company_street_number": data["com_street_number"] or "",
            "company_postal_code": data["com_postal"] or "",
            "company_city": data["com_city"] or "",
            "company_country": data["com_country"] or "",
            "company_website_url": data["com_website"] or "",
            "language": data["language"] or "",
            "aiana_status": "registered",
            "bots_active": data["botsActive"],
            "aiana_environment": "TEST",
            "license": "FREE",
        }

        update_user_url = f'{MAUTIC_BASE_URL}/api/contacts/{mauticId}/edit'
        # print(update_user_url)

        access_token = get_access_token()
        # print("Token", access_token)
        # Headers including the access token
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Accept': 'application/json',
        }

        # Sending the POST request
        payload_json = json.dumps(payload)
        response = requests.patch(update_user_url, data=payload_json, headers=headers)
        print(response.status_code)
        # print(response.json())
        if response.status_code==201 or response.status_code==200:
            print("User updated successfully")
            response_data = response.json()
            contact_id = response_data['contact']['id']
            # Checking response
            return contact_id
        else:
            return 'error'
        
    except Exception as e:
        print(e)
        return "error"

def update_bot_number(number, mauticId):
    try:
        payload =  {
            "bots_active": number,
        }

        update_user_url = f'{MAUTIC_BASE_URL}/api/update/{mauticId}'
        print(update_user_url)

        access_token = get_access_token()
        # print("Token", access_token)
        # Headers including the access token
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Accept': 'application/json',
        }

        # Sending the POST request
        response = requests.post(update_user_url, data=payload, headers=headers)
        

        print(response.status_code)
        if response.status_code == 201:
            print("User created successfully")
            response_data = response.json()
            contact_id = response_data['contact']['id']
            # Checking response
            return contact_id
        else:
            return 'error'
        
    except Exception as e:
        print(e)
        return "error"

def get_access_token():
    token_url = f'{MAUTIC_BASE_URL}/oauth/v2/token'
    data = {
        'client_id': MAUTIC_CLIENT_ID,
        'client_secret': MAUTIC_CLIENT_SECRET,
        'grant_type':'client_credentials'
    }

    response = requests.post(token_url, data)

    # Checking if the request was successful
    if response.status_code == 200:
        # If the response is successful, parse it as JSON
        response_data = response.json()  # This converts the JSON response to a Python dictionary
        # print("Response Data:", response_data)
        # Example of accessing specific data in the response
        access_token = response_data.get('access_token')  # Assuming the token is returned in 'access_token'
        # print("Access Token:", access_token)
        return access_token
    else:
        # If the response was not successful, print the status code and response text
        print("Failed to retrieve data")
        print("Status Code:", response.status_code)
        print("Response Text:", response.text)
        print(response.data)
        return response.status_code

def login_mautic(data, mauticId):
    try:
        now = datetime.datetime.now()
        payload =  {
            "language": data["language"],
            "aiana_status": "active",
            "bots_active": data["bots_active"],
            "bots_registered": data["bots_registered"],
            "firstname": data["first_name"],
            "lastname": data["last_name"],
            # "email": data["email"],
            "company_name": data["com_name"],
            "company_vat": data["com_vat"],
            "company_street": data["com_street"],
            "company_street_number": data["com_street_number"],
            "company_postal_code": data["com_postal"],
            "company_city": data["com_city"],
            "company_country": data["com_country"],
            "company_website_url": data["com_website"],
            "last_login":now,
            "aiana_status": "registered",
            "aiana_environment": "TEST",
            "license": "FREE",
            "person_source":"APPLICATION",
        }

        update_user_url = f'{MAUTIC_BASE_URL}/api/contacts/{mauticId}/edit'
        print(update_user_url)

        access_token = get_access_token()
        # print("Token", access_token)
        # Headers including the access token
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Accept': 'application/json',
        }

        # Sending the POST request
        response = requests.patch(update_user_url, data=payload, headers=headers)
        
        if response.status_code == 200 or response.status_code == 201:
            print("User updated successfully")
            response_data = response.json()
            contact_id = response_data['contact']['id']
            # Checking response
            return contact_id
        else:
            return 'error'
        
    except Exception as e:
        print(e)
        return "error"

def mautic_reset_password(data, mauticId):
    try:
        link = data["password_reset_link"]
        payload = {
            "tokens": {
                "{password_reset_link}": link
            }
        }
        payload_string = json.dumps(payload)
        update_user_url = f'{MAUTIC_BASE_URL}/api/emails/2/contact/{mauticId}/send'
        print(update_user_url)

        access_token = get_access_token()
        # print("Token", access_token)
        # Headers including the access token
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Accept': 'application/json',
            'Content-Type': 'application/json',
        }

        # Sending the POST request
        response = requests.post(update_user_url, data=payload_string, headers=headers)
        
        print(response.status_code)
        if response.status_code == 200:
            print("Sent password reset mail successfully")
            response_data = response.json()
            print(response_data)
            # Checking response
            return response_data['success']
        else:
            return 'error'
        
    except Exception as e:
        print(e)
        return "error"

def mautic_send_verfication_link(verification_link, mauticId):
    try:
        link = verification_link
        payload = {
            "tokens": {
                "{email_verification_url}": link
            }
        }
        payload_string = json.dumps(payload)
        update_user_url = f'{MAUTIC_BASE_URL}/api/emails/9/contact/{mauticId}/send'
        # print(update_user_url)

        access_token = get_access_token()
        # print("Token", access_token)
        # Headers including the access token
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Accept': 'application/json',
            'Content-Type': 'application/json',
        }
        print(f"Mautic Id is : {mauticId}")
        print(f"Access Token:: {access_token}")
        # Sending the POST request
        response = requests.post(update_user_url, data=payload_string, headers=headers)
        
        print(response.status_code)
        if response.status_code == 200:
            print("Sent email verification link mail successfully")
            response_data = response.json()
            # Checking response
            return response_data['success']
        else:
            return 'error'
        
    except Exception as e:
        print(e)
        return "error"

def send_registration_mail(data, mauticId):
    try:
        access_token = get_access_token()
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Accept': 'application/json',
        }
        registration_url = f'{MAUTIC_BASE_URL}/api/emails/{language_dict[data]}/contact/{mauticId}/send'
        print(registration_url)
        registration = requests.post(registration_url, headers=headers)
        registration = registration.json()
        if registration['success']:
            print(registration['success'])
    except Exception as e:
        print(e)
        return "error"

def delete_mautic_contact(contactId):
    delete_user_url = f'{MAUTIC_BASE_URL}/api/contacts/{contactId}/delete'
    access_token = get_access_token()
    # print("Token", access_token)
    # Headers including the access token
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Accept': 'application/json',
    }

    result = requests.delete(delete_user_url, headers=headers)
    print(result)

def book_ticket(data, mauticId):
    try:
        payloads = {
            "tokens": {
                "ticket_url":data['link'],
                "ticket_number": data['id'],
                "created_at": str(data['created']),
                }
        }
        payload_string = json.dumps(payloads)
        book_ticket_url = f'{MAUTIC_BASE_URL}/api/emails/3/contact/{mauticId}/send'
        print(book_ticket_url)

        access_token = get_access_token()
        # print("Token", access_token)
        # Headers including the access token
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Accept': 'application/json',
        }

        # Sending the POST request
        response = requests.post(book_ticket_url, data=payload_string, headers=headers)
        
        print(response.status_code)
        if response.status_code == 200:
            print("Booking ticket mail successfully")
            response_data = response.json()
            # Checking response
            return response_data['success']
        else:
            print(response.status_code)
            return 'error'
        
    except Exception as e:
        print(e)
        return "error"