import json
import boto3
import logging
import hashlib

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# DynamoDB client
dynamodb = boto3.client("dynamodb")

# Table names
USER_TABLE = "HandleUserProfiles"
COMMUNITY_TABLE = "ManageCommunities"
AUTH_TABLE = "HCUsers"  # Table for authentication

def lambda_handler(event, context):
    logger.info(f"Received event: {json.dumps(event)}")
    
    # Parse the body of the event
    try:
        if isinstance(event, str):  # For direct invocation tests
            event = json.loads(event)
        elif "body" in event:  # For API Gateway requests
            event = json.loads(event["body"])
    except Exception as e:
        return create_response(400, {"error": "Request body is missing or invalid."})

    action = event.get("action")
    data = event.get("data", {})

    if not action:
        return create_response(400, {"error": "Missing 'action' in the request."})

    try:
        if action == "register":
            return register_user(data)
        elif action == "login":
            return login_user(data)
        elif action == "addUser":
            return add_user(data)
        elif action == "getUser":
            return get_user(data)
        elif action == "addCommunity":
            return add_community(data)
        elif action == "getCommunity":
            return get_community(data)
        elif action == "deleteCommunity":
            return delete_community(data)
        elif action == "deleteUser":
            return delete_user(data)
        else:
            return create_response(400, {"error": "Invalid action."})
    except Exception as e:
        logger.error(f"Error processing request: {e}")
        return create_response(500, {"error": str(e)})

# Helper function to create consistent responses
def create_response(status_code, body):
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",  # Allow CORS
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization",
        },
        "body": json.dumps(body),
    }

# Authentication functions
def register_user(data):
    username = data.get("username")
    password = data.get("password")
    
    if not username or not password:
        return create_response(400, {"message": "Username and password are required."})
    
    # Hash the password
    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    # Check if user already exists
    existing_user = dynamodb.get_item(
        TableName=AUTH_TABLE,
        Key={"username": {"S": username}}
    ).get("Item")

    if existing_user:
        return create_response(400, {"message": "Username already exists."})

    # Add new user
    dynamodb.put_item(
        TableName=AUTH_TABLE,
        Item={
            "username": {"S": username},
            "password": {"S": hashed_password}
        }
    )
    return create_response(201, {"message": "User registered successfully."})

def login_user(data):
    username = data.get("username")
    password = data.get("password")
    
    if not username or not password:
        return create_response(400, {"message": "Username and password are required."})
    
    # Hash the password
    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    # Retrieve user details
    user = dynamodb.get_item(
        TableName=AUTH_TABLE,
        Key={"username": {"S": username}}
    ).get("Item")

    if not user or user.get("password", {}).get("S") != hashed_password:
        return create_response(401, {"message": "Invalid username or password."})
    
    # Generate authentication token
    token = f"token-{username}"

    return create_response(200, {"authenticated": True, "token": token})

# User-related actions
def add_user(data):
    dynamodb.put_item(
        TableName=USER_TABLE,
        Item={
            "userId": {"S": data["userId"]},
            "name": {"S": data["name"]},
            "email": {"S": data["email"]},
            "hobbies": {"L": [{"S": hobby} for hobby in data["hobbies"]]},
            "profilePicture": {"S": data["profilePicture"]}
        }
    )
    return create_response(200, {"message": "User profile added successfully."})

def get_user(data):
    response = dynamodb.get_item(
        TableName=USER_TABLE,
        Key={"userId": {"S": data["userId"]}}
    )
    return create_response(200, response.get("Item", {}))

# Community-related actions
def add_community(data):
    dynamodb.put_item(
        TableName=COMMUNITY_TABLE,
        Item={
            "communityId": {"S": data["communityId"]},
            "name": {"S": data["name"]},
            "description": {"S": data["description"]},
            "members": {"L": [{"S": member} for member in data["members"]]},
            "adminId": {"S": data["adminId"]}
        }
    )
    return create_response(200, {"message": "Community added successfully."})

def get_community(data):
    response = dynamodb.get_item(
        TableName=COMMUNITY_TABLE,
        Key={"communityId": {"S": data["communityId"]}}
    )
    return create_response(200, response.get("Item", {}))

def delete_community(data):
    dynamodb.delete_item(
        TableName=COMMUNITY_TABLE,
        Key={"communityId": {"S": data["communityId"]}}
    )
    return create_response(200, {"message": "Community deleted successfully."})

# New delete_user function
def delete_user(data):
    user_id = data.get("userId")
    if not user_id:
        return create_response(400, {"message": "User ID is required."})
    
    # Delete user profile from HandleUserProfiles table
    try:
        dynamodb.delete_item(
            TableName=USER_TABLE,
            Key={"userId": {"S": user_id}}
        )
    except Exception as e:
        logger.error(f"Error deleting user from USER_TABLE: {e}")
        return create_response(500, {"message": "Failed to delete user profile."})
    
    # Delete user from HCUsers table (authentication)
    try:
        dynamodb.delete_item(
            TableName=AUTH_TABLE,
            Key={"username": {"S": user_id}}  # Assuming userId is used as the username
        )
    except Exception as e:
        logger.error(f"Error deleting user from AUTH_TABLE: {e}")
        return create_response(500, {"message": "Failed to delete user authentication."})
    
    return create_response(200, {"message": "User deleted successfully."})
