import json
import boto3
import hashlib
import logging
from datetime import datetime

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# AWS clients
dynamodb = boto3.client("dynamodb")
sns = boto3.client("sns")
apigatewaymanagementapi = boto3.client(
    "apigatewaymanagementapi",
    endpoint_url="wss://4v0tsfgv53.execute-api.ap-south-1.amazonaws.com/demo/"
)

# Table names
USER_TABLE = "HandleUserProfiles"
COMMUNITY_TABLE = "ManageCommunities"
AUTH_TABLE = "HCUsers"
CONNECTIONS_TABLE = "ChatConnections"
CHAT_MESSAGES_TABLE = "ChatMessages"

# SNS Topic ARN
SNS_TOPIC_ARN = "arn:aws:sns:ap-south-1:992382789441:Community-Hub"

# Helper function to hash passwords
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Function to create a response in a standard format
def create_response(status_code, body):
    return {
        "statusCode": status_code,
        "body": json.dumps(body)
    }

# WebSocket handlers
def connect_handler(connection_id):
    dynamodb.put_item(
        TableName=CONNECTIONS_TABLE,
        Item={"connectionId": {"S": connection_id}}
    )
    return create_response(200, {"message": "Connected"})

def disconnect_handler(connection_id):
    dynamodb.delete_item(
        TableName=CONNECTIONS_TABLE,
        Key={"connectionId": {"S": connection_id}}
    )
    return create_response(200, {"message": "Disconnected"})

def send_message_handler(connection_id, body):
    chat_room_id = body.get("chatRoomId")
    sender_name = body.get("senderName")
    message = body.get("message")
    timestamp = body.get("timestamp", datetime.now().isoformat())

    if not (chat_room_id and sender_name and message):
        return create_response(400, {"error": "Missing required fields"})

    dynamodb.put_item(
        TableName=CHAT_MESSAGES_TABLE,
        Item={
            "chatRoomId": {"S": chat_room_id},
            "timestamp": {"S": timestamp},
            "senderName": {"S": sender_name},
            "message": {"S": message}
        }
    )

    connections = dynamodb.scan(TableName=CONNECTIONS_TABLE).get("Items", [])
    for conn in connections:
        conn_id = conn["connectionId"]["S"]
        try:
            apigatewaymanagementapi.post_to_connection(
                ConnectionId=conn_id,
                Data=json.dumps({
                    "chatRoomId": chat_room_id,
                    "senderName": sender_name,
                    "message": message,
                    "timestamp": timestamp
                })
            )
        except Exception as e:
            logger.error(f"Error sending message to {conn_id}: {e}")
            dynamodb.delete_item(TableName=CONNECTIONS_TABLE, Key={"connectionId": {"S": conn_id}})

    return create_response(200, {"message": "Message sent"})

def subscribe_to_community_handler(body):
    user_id = body.get("userId")
    community_id = body.get("communityId")

    if not (user_id and community_id):
        return create_response(400, {"error": "Missing required fields"})

    try:
        user_response = dynamodb.get_item(
            TableName=USER_TABLE,
            Key={"userId": {"S": user_id}}
        )
        user_email = user_response.get("Item", {}).get("email", {}).get("S")

        if not user_email:
            return create_response(404, {"error": "User email not found"})

        sns.subscribe(
            TopicArn=SNS_TOPIC_ARN,
            Protocol="email",
            Endpoint=user_email
        )
        logger.info(f"Subscribed {user_email} to SNS topic.")

        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject="Community Subscription Confirmation",
            Message=f"You have successfully subscribed to community {community_id}."
        )

        return create_response(200, {"message": f"Subscription email sent to {user_email}"})
    except Exception as e:
        logger.error(f"Error processing subscription: {e}")
        return create_response(500, {"error": "Failed to process subscription"})

# User and community management handlers
def register_user(data):
    username = data.get("username")
    password = data.get("password")

    if not (username and password):
        return create_response(400, {"error": "Missing username or password"})

    hashed_password = hash_password(password)

    try:
        dynamodb.put_item(
            TableName=AUTH_TABLE,
            Item={
                "username": {"S": username},
                "password": {"S": hashed_password}
            }
        )
        return create_response(200, {"message": "User registered successfully"})
    except Exception as e:
        logger.error(f"Error registering user: {e}")
        return create_response(500, {"error": "Failed to register user"})

def login_user(data):
    username = data.get("username")
    password = data.get("password")

    if not (username and password):
        return create_response(400, {"error": "Missing username or password"})

    hashed_password = hash_password(password)

    try:
        response = dynamodb.get_item(
            TableName=AUTH_TABLE,
            Key={"username": {"S": username}}
        )
        stored_password = response.get("Item", {}).get("password", {}).get("S")

        if stored_password == hashed_password:
            return create_response(200, {"message": "Login successful"})
        else:
            return create_response(401, {"error": "Invalid credentials"})
    except Exception as e:
        logger.error(f"Error logging in user: {e}")
        return create_response(500, {"error": "Failed to login"})

# Existing route handler
def handle_existing_routes(event):
    action = event.get("action")
    data = event.get("data", {})

    if action == "register":
        return register_user(data)
    elif action == "login":
        return login_user(data)
    else:
        return create_response(400, {"error": "Invalid action."})

def lambda_handler(event, context):
    route_key = event.get("requestContext", {}).get("routeKey")
    connection_id = event.get("requestContext", {}).get("connectionId")

    if route_key == "$connect":
        return connect_handler(connection_id)
    elif route_key == "$disconnect":
        return disconnect_handler(connection_id)
    elif route_key == "sendMessage":
        body = json.loads(event.get("body", "{}"))
        return send_message_handler(connection_id, body)
    elif route_key == "subscribeToCommunity":
        body = json.loads(event.get("body", "{}"))
        return subscribe_to_community_handler(body)
    else:
        return handle_existing_routes(event)
