import os

import requests
from dotenv import load_dotenv

load_dotenv()


def get_api_key():
    """Zwraca klucz API OpenAI ze zmiennych środowiskowych (kilka możliwych nazw) lub pusty string."""
    # Accept a few common env var names to avoid config mismatches.
    candidates = [
        os.environ.get("OPEN_AI_KEY_STUDENT"),
        os.environ.get("OPEN_API_KEY_STUDENT"),
        os.environ.get("OPENAI_API_KEY"),
    ]
    for value in candidates:
        if value and value.strip():
            return value.strip().strip("\"'")
    return ""


def prompt(content):
    """Wysyła prosty prompt tekstowy do Chat Completions i wypisuje odpowiedź na stdout (np. do testów lokalnych)."""
    api_key = get_api_key()
    url = "https://api.openai.com/v1/chat/completions"
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    data = {
        "model": "gpt-4o-mini",  # or gpt-4o, gpt-3.5-turbo, etc.
        "messages": [{"role": "user", "content": content}],
        "temperature": 0.7,
    }

    if not api_key:
        print("Missing API key. Set OPEN_AI_KEY_STUDENT or OPENAI_API_KEY.")
        return
    try:
        response = requests.post(url, headers=headers, json=data, timeout=15)
        if response.status_code == 200:
            result = response.json()
            print(result["choices"][0]["message"]["content"])
        else:
            print(f"Error {response.status_code}: {response.text}")
    except requests.RequestException as exc:
        print(f"Request error: {exc}")


def create_data_uri(base64_str, image_type="jpeg"):
    """Składa data URI obrazu (np. do osadzenia w JSON API wizji)."""
    return f"data:image/{image_type};base64,{base64_str}"


def prompt_img(img, tresc, logger):
    """Wywołuje model wizji/tekstu OpenAI, by wygenerować krótką „opinię studenta” do posta; zwraca tekst lub None przy błędzie."""
    api_key = get_api_key()
    #logger.info(f"Running prompt {tresc}")
    zapytanie = f"Napisz śmieszną żartobliwą reakcje na posta składającego z załączonego zdjęcia i treści:'{tresc}'. Max 150 liter. Wciel sie w młodego studenta i używaj nowoczesnego młodocianego języka i slangu, terminologii typu brainrot. "
    url = "https://api.openai.com/v1/chat/completions"
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    if img:
        data = {
            "model": "gpt-4o-mini",
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": zapytanie},
                        {
                            "type": "image_url",
                            "image_url": {"url": f"data:image/jpeg;base64,{img}"},
                        },
                    ],
                }
            ],
            "max_tokens": 300,
        }
    else:
        data = {
            "model": "gpt-4o-mini",
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": zapytanie},
                    ],
                }
            ],
            "max_tokens": 300,
        }

    if not api_key:
        logger.error("Missing API key. Set OPEN_AI_KEY_STUDENT or OPENAI_API_KEY.")
        return None
    try:
        response = requests.post(url, headers=headers, json=data, timeout=15)
        if response.status_code == 200:
            result = response.json()
            return result["choices"][0]["message"]["content"]
        logger.error(f"{response.status_code}: {response.text}")
    except requests.RequestException as exc:
        logger.error(f"Request error: {exc}")
    return None


if __name__ == "__main__":
    print("hello")
    # all_posts = requests.get("http://localhost:5000/api/post")
    # Create list of Post contents
    # text_contents = "\n".join([x["tresc"] for x in all_posts.json()])
    # prompt_txt = f"Podsumuj treści postów stworzonych przez studentów. Każda nowa treść jest w nowej linii \n {text_contents}"
    # prompt(prompt_txt)
    # print(prompt_img(all_posts.json()[2]))
