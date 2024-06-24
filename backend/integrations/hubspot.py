# slack.py

import asyncio
import base64
import requests
from http.client import HTTPException
import json
import secrets
from redis_client import add_key_value_redis, delete_key_redis, get_value_redis
import httpx
from fastapi import Request
from fastapi.responses import HTMLResponse

authorization_url = "https://app.hubspot.com/oauth/authorize"
scope = 'oauth crm.objects.contacts.read'  # Example scope, adjust based on your needs

REDIRECT_URI = 'http://localhost:8000/integrations/hubspot/oauth2callback'

CLIENT_ID = '319b8dbf-6e80-43f2-8cd1-84d0b19154cd'
CLIENT_SECRET = '7cf22027-12ca-4f7f-a88f-d983722be648'

encoded_client_id_secret = base64.b64encode(f'{CLIENT_ID}:{CLIENT_SECRET}'.encode()).decode()

async def authorize_hubspot(user_id, org_id):
    # Create state data
    state_data = {
        'state': secrets.token_urlsafe(32),
        'user_id': user_id,
        'org_id': org_id
    }
    encoded_state = base64.urlsafe_b64encode(json.dumps(state_data).encode('utf-8')).decode('utf-8')


    # Store state data and code verifier in Redis
    await asyncio.gather(
        add_key_value_redis(f'hubspot_state:{org_id}:{user_id}', json.dumps(state_data), expire=600)
    )

    # Construct authorization URL
    auth_url = f'{authorization_url}?client_id={CLIENT_ID}&scope={scope}&state={encoded_state}&redirect_uri={REDIRECT_URI}'
    return auth_url

async def oauth2callback_hubspot(request: Request):
    if request.query_params.get('error'):
        raise HTTPException(status_code=400, detail=request.query_params.get('error_description'))
    code = request.query_params.get('code')
    encoded_state = request.query_params.get('state')
    state_data = json.loads(base64.urlsafe_b64decode(encoded_state).decode('utf-8'))

    original_state = state_data.get('state')
    user_id = state_data.get('user_id')
    org_id = state_data.get('org_id')

    saved_state = await asyncio.gather(
        get_value_redis(f'hubspot_state:{org_id}:{user_id}'),
    )
    if type(saved_state) is list: 
        saved_state = saved_state[0]

    print(saved_state, "this is the state i got");
    if not saved_state or original_state != json.loads(saved_state).get('state'):
        raise HTTPException(status_code=400, detail='State does not match.')

    async with httpx.AsyncClient() as client:
        response, _, _ = await asyncio.gather(
            client.post(
                'https://api.hubapi.com/oauth/v1/token',
                data={
                    'grant_type': 'authorization_code',
                    'code': code,
                    'redirect_uri': REDIRECT_URI,
                    'client_id': CLIENT_ID,
                    'client_secret': CLIENT_SECRET
                },
                headers={
                    'Authorization': f'Basic {encoded_client_id_secret}',
                    'Content-Type': 'application/x-www-form-urlencoded',
                }
            ),
            delete_key_redis(f'hubspot_state:{org_id}:{user_id}'),
            delete_key_redis(f'hubspot_verifier:{org_id}:{user_id}'),
        )

    await add_key_value_redis(f'hubspot_credentials:{org_id}:{user_id}', json.dumps(response.json()), expire=600)
    
    close_window_script = """
    <html>
        <script>
            window.close();
        </script>
    </html>
    """
    return HTMLResponse(content=close_window_script)


async def get_hubspot_credentials(user_id, org_id):
    credentials = await get_value_redis(f'hubspot_credentials:{org_id}:{user_id}')
    if not credentials:
        raise HTTPException(status_code=400, detail='No credentials found.')
    credentials = json.loads(credentials)
    await delete_key_redis(f'hubspot_credentials:{org_id}:{user_id}')

    return credentials

async def create_integration_item_metadata_object(response_json):
    # TODO
    pass

async def get_items_hubspot(credentials):
    credentials = json.loads(credentials)
    url = 'https://api.hubapi.com/contacts/v1/lists/all/contacts/all?count=1'
    list_of_integration_item_metadata = []
    list_of_responses = []
    response = requests.get(
        url,
        headers={
            'Authorization': f'Bearer {credentials.get("access_token")}',
            'Content-Type': 'application/json'
        },
    ) 
    if response.status_code == 200:
        print(response.json(), "this is the data")
        # results = response.json()['results']

        # list_of_integration_item_metadata = []
        # for result in results:
        #     list_of_integration_item_metadata.append(
        #         create_integration_item_metadata_object(result)
        #     )

        # print(list_of_integration_item_metadata)

    print(f'list_of_integration_item_metadata: {list_of_integration_item_metadata}')