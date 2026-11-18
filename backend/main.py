from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from detection.injection_detector import detect_prompt_injection
from detection.leakage_detector import detect_sensitive_data
from detection.risk_scorer import calculate_risk_score
from detection.ml_classifier import load_classifier, predict_prompt


app = FastAPI(
    title="PromptShield API",
    description="AI Prompt Injection and Data Leakage Detection",
    version="2.0"
)

# Load the previously trained ML model
ml_model = load_classifier()


class PromptRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=5000)


@app.get("/")
def home():
    return {
        "message": "Welcome to PromptShield API",
        "status": "Running",
        "version": "2.0"
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "model_loaded": ml_model is not None
    }


@app.post("/analyze")
def analyze_prompt(request: PromptRequest):

    prompt = request.prompt.strip()

    if not prompt:
        raise HTTPException(
            status_code=400,
            detail="Prompt cannot be empty."
        )

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

    # 5. Return complete analysis
    return {
        "prompt_injection": injection_result,
        "data_leakage": leakage_result,
        "ml_classification": ml_result,
        "overall_risk": risk_result
    }