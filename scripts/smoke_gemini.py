import os, sys, time, json
sys.path.insert(0, ".")
from plutonium.config import load_dotenv
load_dotenv()
from google import genai
from google.genai import types
c = genai.Client(api_key=os.environ["GEMINI_API_KEY"])
schema = {"type": "object", "properties": {"answer": {"type": "string"}}, "required": ["answer"]}
for model in ["gemma-4-26b-a4b-it", "gemma-4-31b-it"]:
    for label, cfg in [
        ("full", dict(system_instruction="Reply in JSON.", temperature=0.1, response_mime_type="application/json", response_schema=schema, thinking_config=types.ThinkingConfig(thinking_level="high"))),
        ("no_thinking", dict(system_instruction="Reply in JSON.", temperature=0.1, response_mime_type="application/json", response_schema=schema)),
        ("bare", dict(temperature=0.1)),
    ]:
        t = time.time()
        try:
            r = c.models.generate_content(model=model, contents=["What is 2+2? JSON {\"answer\":...}"], config=types.GenerateContentConfig(**cfg))
            print(model, label, "OK", round(time.time()-t,1), repr(r.text[:200]))
        except Exception as e:
            print(model, label, "ERR", round(time.time()-t,1), str(e)[:300])
