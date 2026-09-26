"""
Демонстрационный файл с намеренными уязвимостями.

Используется для проверки работы сканера. НЕ ИСПОЛЬЗУЙ ЭТОТ КОД!
Каждая функция содержит конкретную уязвимость, которую должен
найти bandit. Если не находит — что-то сломано в сканере.
"""
import hashlib
import os
import pickle
import subprocess


# B105: hardcoded_password_string
ADMIN_PASSWORD = "super_secret_password_123"
API_KEY = "sk-1234567890abcdef"


def get_user(user_id: str) -> str:
    """B608: hardcoded_sql_expressions — SQL через f-string."""
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return query


def run_command(user_input: str) -> None:
    """B602: subprocess_popen_with_shell_equals_true — command injection."""
    subprocess.run(f"echo {user_input}", shell=True)


def weak_hash(data: bytes) -> str:
    """B324: hashlib — слабый алгоритм MD5."""
    return hashlib.md5(data).hexdigest()


def unsafe_eval(code: str):
    """B307: eval — выполнение произвольного кода."""
    return eval(code)


def load_pickle(path: str):
    """B301: pickle — небезопасная десериализация."""
    with open(path, "rb") as f:
        return pickle.load(f)


def check_admin(user) -> None:
    """B101: assert_used — assert можно отключить флагом -O."""
    assert user.is_admin, "User is not admin"
    return None


def os_system_wrapper(cmd: str) -> None:
    """B605: start_process_with_a_shell — os.system с пользовательским вводом."""
    os.system(cmd)