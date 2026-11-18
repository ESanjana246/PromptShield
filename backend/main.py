from fastapi import FastAPI
from pydantic import BaseModel

from detection.injection_detector import detect_prompt_injection
from detection.leakage_detector import detect_sensitive_data
from detection.risk_scorer import calculate_risk_score
from detection.ml_classifier import train_classifier, predict_prompt


app = FastAPI(
    title="PromptShield API",
    description="AI Prompt Injection and Data Leakage Detection",
    version="1.1"
)


# Train ML model when backend starts
ml_model = train_classifier()


class PromptRequest(BaseModel):
    prompt: str


@app.get("/")
def home():
    return {
        "message": "Welcome to PromptShield API",
        "status": "Running"
    }


@app.post("/analyze")
def analyze_prompt(request: PromptRequest):

    prompt = request.prompt

    # 1. Detect prompt injection
    injection_result = detect_prompt_injection(prompt)

    # 2. Detect sensitive information
    leakage_result = detect_sensitive_data(prompt)

    # 3. Run ML classification
    ml_result = predict_prompt(prompt, ml_model)

    # 4. Calculate combined risk
    risk_result = calculate_risk_score(
        injection_result,
        leakage_result,
        ml_result
    )

    return {
        "prompt_injection": injection_result,
        "data_leakage": leakage_result,
        "ml_classification": ml_result,
        "overall_risk": risk_result
    }