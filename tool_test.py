import ollama

def get_weather(city: str) -> str:
    """Get the weather for a city."""
    return f"Sunny in {city}"

resp = ollama.chat(
    model="qwen2.5:7b",
    messages=[{"role": "user", "content": "What's the weather in Paris?"}],
    tools=[get_weather],
)
print(resp.message)