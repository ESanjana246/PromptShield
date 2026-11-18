import streamlit as st
import requests
import json
import csv
import io
from datetime import datetime

# ================= PAGE CONFIG =================

st.set_page_config(
    page_title="PromptShield | AI Security",
    page_icon="🛡️",
    layout="wide"
)

API_URL = "http://127.0.0.1:8000/analyze"

# ================= CUSTOM CSS =================

st.markdown("""
<style>
.stApp {
    background: #08111f;
    color: #e5eefb;
}

h1, h2, h3 {
    color: #e5eefb;
}

div[data-testid="stMetric"] {
    background: #122238;
    border: 1px solid #244365;
    padding: 18px;
    border-radius: 12px;
}

.stButton button {
    background: #1677ff;
    color: white;
    border-radius: 8px;
    border: none;
    padding: 10px 22px;
}

.stButton button:hover {
    background: #095ac7;
    color: white;
}

section[data-testid="stSidebar"] {
    background: #101e32;
}
</style>
""", unsafe_allow_html=True)


# ================= SESSION STATE =================

if "history" not in st.session_state:
    st.session_state.history = []


# ================= HELPER FUNCTIONS =================

def get_explanation(result):

    injection = result.get("prompt_injection", {})
    leakage = result.get("data_leakage", {})
    ml = result.get("ml_classification", {})
    risk = result.get("overall_risk", {})

    explanations = []

    if injection.get("is_suspicious"):
        explanations.append(
            "⚠️ Possible prompt injection detected. "
            f"Categories: {injection.get('detected_categories', [])}"
        )
    else:
        explanations.append(
            "✅ No significant prompt injection indicators detected."
        )

    if leakage.get("data_leak_detected"):
        explanations.append(
            "🚨 Sensitive information detected: "
            f"{leakage.get('detected_types', [])}"
        )
    else:
        explanations.append(
            "✅ No supported sensitive data patterns detected."
        )

    explanations.append(
        f"🤖 ML prediction: {ml.get('prediction', 'Unknown')}"
    )

    explanations.append(
        f"📊 Overall risk: {risk.get('risk_level', 'Unknown')} "
        f"({risk.get('risk_score', 0)}/100)"
    )

    return explanations


def create_csv(history):

    output = io.StringIO()

    writer = csv.writer(output)

    writer.writerow([
        "Date",
        "Prompt",
        "Risk Score",
        "Risk Level",
        "ML Prediction",
        "ML Confidence"
    ])

    for item in history:

        risk = item.get("overall_risk", {})
        ml = item.get("ml_classification", {})

        writer.writerow([
            item.get("analyzed_at", ""),
            item.get("analyzed_prompt", ""),
            risk.get("risk_score", 0),
            risk.get("risk_level", ""),
            ml.get("prediction", ""),
            ml.get("confidence", 0)
        ])

    return output.getvalue()


# ================= SIDEBAR =================

with st.sidebar:

    st.title("🛡️ PromptShield")

    st.caption("AI Security Monitoring")

    st.divider()

    st.subheader("Dashboard")

    st.write("🔍 Prompt Analysis")
    st.write("🧩 Injection Detection")
    st.write("🔐 Data Leakage Detection")
    st.write("🤖 ML Classification")
    st.write("📚 Analysis History")

    st.divider()

    st.metric(
        "Total Analyses",
        len(st.session_state.history)
    )

    if st.button("Clear Analysis History"):

        st.session_state.history = []
        st.rerun()


# ================= MAIN HEADER =================

st.title("🛡️ PromptShield")

st.subheader(
    "AI Prompt Injection & Data Leakage Detector"
)

st.caption(
    "Intelligent AI security monitoring powered by Machine Learning"
)

st.divider()


# ================= PROMPT INPUT =================

st.header("🔍 Analyze Your Prompt")

prompt = st.text_area(
    "Enter text for security analysis",
    height=150,
    placeholder="Enter a prompt to analyze..."
)

analyze = st.button(
    "🔍 Analyze Prompt",
    type="primary",
    use_container_width=True
)


# ================= API ANALYSIS =================

if analyze:

    if not prompt.strip():

        st.warning("Please enter text before analysis.")

    else:

        try:

            with st.spinner("Analyzing prompt security..."):

                response = requests.post(
                    API_URL,
                    json={"prompt": prompt},
                    timeout=30
                )

                response.raise_for_status()

                result = response.json()

                required_keys = [
                    "prompt_injection",
                    "data_leakage",
                    "ml_classification",
                    "overall_risk"
                ]

                if not isinstance(result, dict):
                    raise ValueError("API response must be a JSON object.")

                if not all(key in result for key in required_keys):
                    raise ValueError(
                        "API response is missing required analysis fields."
                    )

                result["analyzed_at"] = datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                )

                result["analyzed_prompt"] = prompt

                st.session_state.history.insert(0, result)

                st.success("Security analysis completed!")

        except requests.RequestException as error:

            st.error(f"API connection failed: {error}")

        except (ValueError, TypeError) as error:

            st.error(f"Invalid analysis response: {error}")


# ================= DISPLAY RESULTS =================

if st.session_state.history:

    result = st.session_state.history[0]

    injection = result.get("prompt_injection", {})
    leakage = result.get("data_leakage", {})
    ml = result.get("ml_classification", {})
    risk = result.get("overall_risk", {})

    score = risk.get("risk_score", 0)
    level = risk.get("risk_level", "Unknown")

    try:
        score = max(0, min(100, float(score)))
    except (ValueError, TypeError):
        score = 0

    st.divider()

    st.header("📊 Security Analysis Dashboard")

    # ================= METRICS =================

    col1, col2, col3 = st.columns(3)

    col1.metric(
        "Risk Score",
        f"{score:g}/100"
    )

    col2.metric(
        "Risk Level",
        level
    )

    col3.metric(
        "ML Confidence",
        f"{ml.get('confidence', 0)}%"
    )

    st.progress(score / 100)

    if level == "High":

        st.error("🚨 High Risk Detected")

    elif level == "Medium":

        st.warning("⚠️ Medium Risk Detected")

    else:

        st.success("✅ Low Risk")

    # ================= DETECTION RESULTS =================

    st.divider()

    st.header("🧩 Detection Results")

    col1, col2 = st.columns(2)

    with col1:

        st.subheader("🛡️ Prompt Injection")

        if injection.get("is_suspicious"):
            st.error("Suspicious prompt detected")
        else:
            st.success("No significant injection detected")

        st.write(
            "**Categories:**",
            injection.get("detected_categories", [])
        )

        st.write(
            "**Risk Level:**",
            injection.get("risk_level", "Unknown")
        )

    with col2:

        st.subheader("🔐 Data Leakage")

        if leakage.get("data_leak_detected"):
            st.error("Sensitive data detected")
        else:
            st.success("No supported leakage patterns detected")

        st.write(
            "**Detected Types:**",
            leakage.get("detected_types", [])
        )

        st.write(
            "**Risk Level:**",
            leakage.get("risk_level", "Unknown")
        )

    # ================= ML RESULTS =================

    st.divider()

    st.subheader("🤖 Machine Learning Classification")

    col1, col2 = st.columns(2)

    col1.metric(
        "Prediction",
        str(ml.get("prediction", "Unknown"))
    )

    col2.metric(
        "Confidence",
        f"{ml.get('confidence', 0)}%"
    )

    # ================= EXPLANATIONS =================

    st.divider()

    st.header("💡 Detection Explanations")

    explanations = get_explanation(result)

    for explanation in explanations:
        st.write(explanation)

    # ================= REPORT DOWNLOAD =================

    st.divider()

    st.header("📥 Download Security Report")

    report = json.dumps(result, indent=4)

    filename = datetime.now().strftime(
        "promptshield_report_%Y%m%d_%H%M%S.json"
    )

    st.download_button(
        "⬇️ Download JSON Report",
        data=report,
        file_name=filename,
        mime="application/json",
        use_container_width=True
    )

    st.caption(
        f"Last analysis: {result.get('analyzed_at', 'Unknown')}"
    )

    with st.expander("View Complete JSON Response"):
        st.json(result)


# ================= ANALYSIS HISTORY =================

st.divider()

st.header("📚 Analysis History")

if st.session_state.history:

    st.metric(
        "Total Analyses Completed",
        len(st.session_state.history)
    )

    csv_data = create_csv(st.session_state.history)

    st.download_button(
        "⬇️ Download Analysis History (CSV)",
        data=csv_data,
        file_name="promptshield_analysis_history.csv",
        mime="text/csv"
    )

    for index, item in enumerate(st.session_state.history):

        item_risk = item.get("overall_risk", {})

        with st.expander(
            f"Analysis {index + 1} | "
            f"{item_risk.get('risk_level', 'Unknown')} Risk | "
            f"{item_risk.get('risk_score', 0)}/100"
        ):

            st.write(
                "**Date:**",
                item.get("analyzed_at", "")
            )

            st.write(
                "**Analyzed Prompt:**",
                item.get("analyzed_prompt", "")
            )

            st.write(
                "**Risk Level:**",
                item_risk.get("risk_level", "Unknown")
            )

            st.json(item)


else:

    st.info("No analysis history available yet.")


# ================= FOOTER =================

st.divider()

st.caption(
    "PromptShield | AI Security Research Project | "
    "Built using Python, FastAPI, Streamlit and Machine Learning"
)