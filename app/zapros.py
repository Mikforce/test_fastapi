import requests

# регистрация

register_url = "http://localhost:8080/register"
register_data = {
    "username": "john@mail.com",
    "password": "secret_password"
}
register_response = requests.post(register_url, json=register_data)

print(register_response.json())

url = "http://localhost:8080/token"

data = {
    "username": "john_doe",
    "password": "secret_password"
}
# создание сообщения

response = requests.post(url, json=data)
if response.status_code == 200:
    access_token = response.json()["access_token"]
    headers = {"Authorization": f"Bearer {access_token}"}

    message_url = "http://localhost:8080/create_message"

    message_data = {
        "id": 1,
        "text": "Текст вашего сообщения",
        "owner": "john_doe"
    }

    message_response = requests.post(message_url, json=message_data, headers=headers)

    print(message_response.json())

# лайк

url = "http://localhost:8080/messages/1/like"
headers = {
    "Authorization": f"Bearer {access_token}"
}

response = requests.post(url, headers=headers)

if response.ok:
    print("Like added successfully")
else:
    print("Failed to add like")

# удаление сообщения
url = "http://localhost:8080/messages/1"

headers = {
    "Authorization": f"Bearer {access_token}"
}

response = requests.delete(url, headers=headers)

if response.status_code == 200:
    print("Message deleted successfully")
else:
    print("Failed to delete message")

