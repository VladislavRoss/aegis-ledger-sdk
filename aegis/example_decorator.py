"""
example_decorator.py — Minimal example using the @trace decorator.

No LangChain, no CrewAI, no framework required. Just pure Python
functions with automatic tamper-evident logging.

Setup:
    pip install aegis-ledger-sdk
    aegis init
"""

import json
import urllib.request

from aegis import AegisClient

client = AegisClient(
    canister_id="toqqq-lqaaa-aaaae-afc2a-cai",
    api_key_id="ak_REPLACE_WITH_YOUR_KEY",
    private_key_path="./agent_key.pem",
    agent_id="agent_weather_v1",
)


# ── Every call to this function is now tamper-evident logged ───────────
@client.trace(tool_name="weather_api")
def get_weather(city: str) -> dict:
    """Fetch current weather for a city."""
    url = f"https://wttr.in/{city}?format=j1"
    with urllib.request.urlopen(url) as resp:
        return json.loads(resp.read())


@client.trace(action_type="decision", tool_name="outfit_recommender")
def recommend_outfit(weather: dict) -> str:
    """Decide what to wear based on weather."""
    temp_c = int(weather["current_condition"][0]["temp_C"])
    if temp_c < 10:
        return "Heavy coat, scarf, gloves"
    elif temp_c < 20:
        return "Light jacket, long sleeves"
    else:
        return "T-shirt, shorts"


# ── Run the agent ───────────────────────────────────────────────────
def main() -> None:
    with client.span("morning_routine", reasoning="Daily outfit planning"):
        weather = get_weather("London")
        outfit = recommend_outfit(weather)

    print(f"Recommendation: {outfit}")
    print(f"\nLogged {client.sequence_number} actions to Aegis")
    print(f"Session: {client.session_id}")
    print(f"Pending spill: {client.pending_spill_count}")


if __name__ == "__main__":
    main()
