import requests
import yaml

def query(prompt, config_path="config/settings.yaml"):
    with open(config_path) as f:
        cfg = yaml.safe_load(f)

    provider = cfg["llm"]["provider"]
    model = cfg["llm"]["model"]
    base_url = cfg["llm"]["base_url"]

    if provider == "ollama":
        try:
            resp = requests.post(
                base_url + "/api/generate",
                json={"model": model, "prompt": prompt, "stream": False},
                timeout=300
            )
            if resp.status_code == 200:
                return resp.json().get("response", "").strip()
            return "[LLM error: HTTP " + str(resp.status_code) + "]"
        except requests.exceptions.ConnectionError:
            return "[LLM not available - is Ollama running?]"
        except requests.exceptions.Timeout:
            return "[LLM error: Request timed out]"
        except Exception as e:
            return "[LLM error: " + str(e) + "]"
    return "[Unknown LLM provider]"
