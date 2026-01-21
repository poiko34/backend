import requests
import random, string

BASE_URL = "http://127.0.0.1:8080"

def random_username():
    return "rate_test_user_" + "".join(random.choices(string.digits, k=6))

def register(username):
    resp = requests.post(f"{BASE_URL}/register", json={"username": username, "password": "testpass"})
    return resp.status_code, resp.json()

def login(username):
    resp = requests.post(f"{BASE_URL}/login", json={"username": username, "password": "testpass"})
    if resp.status_code == 200:
        return resp.status_code, resp.json()["token"]
    return resp.status_code, resp.text

def balance(token):
    headers = {"Authorization": f"Bearer {token}"}
    resp = requests.get(f"{BASE_URL}/balance", headers=headers)
    return resp.status_code, resp.json()

def recover(recovery_code):
    resp = requests.post(f"{BASE_URL}/recover", json={"recovery_code": recovery_code, "new_password": "newpass123"})
    return resp.status_code, resp.json()

if __name__ == "__main__":
    username = random_username()
    print("=== Генерация нового пользователя ===")
    print("Username:", username)

    # 1. Регистрация
    code, data = register(username)
    print("\n1. Регистрация")
    print(code, data)

    recovery_code = data["recovery_code"]

    # 2. Логин
    code, token = login(username)
    print("\n2. Логин")
    print(code, token)

    # 3. Баланс
    code, bal = balance(token)
    print("\n3. Проверка баланса")
    print(code, bal)

    # 4. Rate-limit тест логина (7 запросов, лимит 5)
    print("\n4. Тест rate-limiting на логин (7 запросов при лимите 5)")
    for i in range(7):
        c, t = login(username)
        print(f"Запрос {i+1}: {c} {t if c==200 else ''}")

    # 5. Rate-limit тест восстановления пароля
    print("\n5. Тест rate-limiting на восстановление пароля (7 запросов при лимите 5)")
    for i in range(7):
        c, r = recover(recovery_code)
        print(f"Запрос {i+1}: {c} {r if c==200 else ''}")

    # 6. Логин с новым паролем
    code, token = login(username)
    print("\n6. Логин с новым паролем после восстановления")
    print(code, token)
