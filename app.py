import streamlit as st
import requests
import json
import csv
import io
from datetime import datetime

# =====================================================
# CONFIGURATION
# =====================================================

st.set_page_config(
    page_title="PromptShield | Security Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

API_URL = "https://promptshield-api-7xzr.onrender.com"
API_ENDPOINT = f"{API_URL}/analyze"

# =====================================================
# CYBERSECURITY THEME
# =====================================================

st.markdown("""
<style>
.stApp {
    background: #080808;
    color: #f5f5f5;
}

header[data-testid="stHeader"] {
    background: #080808;
}

[data-testid="stAppViewContainer"] {
    background: #080808;
}

h1, h2, h3, h4 {
    color: white !important;
    font-weight: 700 !important;
}

h1 {
    border-left: 5px solid #ff263f;
    padding-left: 14px;
}

p, label, span, li {
    color: #d4d4d4;
}

section[data-testid="stSidebar"] {
    background: #111111;
    border-right: 1px solid #8b1525;
}

section[data-testid="stSidebar"] h1,
section[data-testid="stSidebar"] h2,
section[data-testid="stSidebar"] h3 {
    color: #ff334f !important;
}

div[data-testid="stMetric"] {
    background: linear-gradient(145deg, #191919, #101010);
    border: 1px solid #64202b;
    border-left: 4px solid #ff263f;
    padding: 20px;
    border-radius: 12px;
}

div[data-testid="stMetricValue"] {
    color: #ff334f !important;
    font-weight: 800;
}

.stButton button,
.stDownloadButton button,
.stFormSubmitButton button {
    background: linear-gradient(135deg, #d71936, #ff334f);
    color: white !important;
    border: 1px solid #ff5268;
    border-radius: 9px;
    font-weight: 700;
}

.stTextArea textarea {
    background: #151515 !important;
    color: white !important;
    border: 1px solid #8c2636 !important;
    border-radius: 10px;
}

div[data-testid="stExpander"] {
    background: #141414;
    border: 1px solid #63202b;
    border-radius: 10px;
}

hr {
    border-color: #49202a;
}

.small-text {
    color: #a3a3a3 !important;
    font-size: 13px;
}

a {
    color: #ff5268 !important;
}
</style>
""", unsafe_allow_html=True)

# =====================================================
# SESSION STATE
# =====================================================

if "history" not in st.session_state:
    st.session_state.history = []

if "latest_result" not in st.session_state:
    st.session_state.latest_result = None

if "api_error" not in st.session_state:
    st.session_state.api_error = None

# =====================================================
# HELPER FUNCTIONS
# =====================================================

def safe_number(value, default=0):
    try:
        return float(value)
    except (ValueError, TypeError):
        return float(default)


def get_risk_color(level):
    level = str(level).lower()

    if level == "high":
        return "#ff263f"
    elif level == "medium":
        return "#ffad33"

    return "#22c55e"


def create_csv(history):
    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "Date",
        "Prompt",
        "Risk Score",
        "Risk Level",
        "Injection Detected",
        "Leakage Detected",
        "ML Prediction",
        "ML Confidence"
    ])

    for item in history:
        risk = item.get("overall_risk", {})
        injection = item.get("prompt_injection", {})
        leakage = item.get("data_leakage", {})
        ml = item.get("ml_classification", {})

        writer.writerow([
            item.get("analyzed_at", ""),
            item.get("analyzed_prompt", ""),
            risk.get("risk_score", 0),
            risk.get("risk_level", ""),
            injection.get("is_suspicious", False),
            leakage.get("data_leak_detected", False),
            ml.get("prediction", ""),
            ml.get("confidence", 0)
        ])

    return output.getvalue()


def get_explanations(result):
    injection = result.get("prompt_injection", {})
    leakage = result.get("data_leakage", {})
    ml = result.get("ml_classification", {})
    risk = result.get("overall_risk", {})

    explanations = []

    if injection.get("is_suspicious"):
        explanations.append(
            "⚠️ Prompt injection indicators detected: "
            + ", ".join(map(
                str, injection.get("detected_categories", [])
            ))
        )
    else:
        explanations.append(
            "✅ No significant prompt injection indicators detected."
        )

    if leakage.get("data_leak_detected"):
        explanations.append(
            "🚨 Sensitive information patterns detected: "
            + ", ".join(map(
                str, leakage.get("detected_types", [])
            ))
        )
    else:
        explanations.append(
            "✅ No supported sensitive data patterns detected."
        )

    explanations.append(
        f"🤖 ML classification: {ml.get('prediction', 'Unknown')}"
    )

    explanations.append(
        f"📊 Overall risk: {risk.get('risk_level', 'Unknown')} "
        f"({risk.get('risk_score', 0)}/100)"
    )

    return explanations


# =====================================================
# SIDEBAR
# =====================================================

with st.sidebar:

    st.title("🛡️ PromptShield")
    st.caption("AI Security Monitoring Center")

    st.divider()

    st.subheader("Navigation")

    st.markdown("""
    🔍 Prompt Scanner

    🛡️ Injection Monitoring

    🔐 Data Leakage Monitoring

    🤖 ML Classification

    📚 Security History
    """)

    st.divider()

    st.subheader("System Overview")

    st.metric("Total Scans", len(st.session_state.history))

    high_count = sum(
        1 for item in st.session_state.history
        if str(item.get("overall_risk", {}).get(
            "risk_level", ""
        )).lower() == "high"
    )

    st.metric("High Risk Scans", high_count)

    if st.button("🗑️ Clear History", use_container_width=True):
        st.session_state.history = []
        st.session_state.latest_result = None
        st.session_state.api_error = None
        st.rerun()

    st.caption("Version 2.0 | AI Security Research")


# =====================================================
# MAIN HEADER
# =====================================================

st.title("🛡️ PromptShield Security Center")

st.markdown("### AI Prompt Injection & Data Leakage Detection")

st.markdown(
    '<p class="small-text">Monitor prompt security, identify '
    'suspicious inputs and analyze potential sensitive data exposure.</p>',
    unsafe_allow_html=True
)

st.divider()

# =====================================================
# DASHBOARD METRICS
# =====================================================

history = st.session_state.history

high_risks = sum(
    1 for item in history
    if str(item.get("overall_risk", {}).get(
        "risk_level", ""
    )).lower() == "high"
)

medium_risks = sum(
    1 for item in history
    if str(item.get("overall_risk", {}).get(
        "risk_level", ""
    )).lower() == "medium"
)

low_risks = sum(
    1 for item in history
    if str(item.get("overall_risk", {}).get(
        "risk_level", ""
    )).lower() == "low"
)

col1, col2, col3, col4 = st.columns(4)

col1.metric("Total Scans", len(history))
col2.metric("🔴 High Risk", high_risks)
col3.metric("🟠 Medium Risk", medium_risks)
col4.metric("🟢 Low Risk", low_risks)

st.divider()

# =====================================================
# PROMPT SCANNER
# =====================================================

st.header("🔍 Prompt Security Scanner")

st.write("Enter a prompt to evaluate its security risks.")

with st.form("prompt_analysis_form"):

    prompt = st.text_area(
        "Prompt Input",
        height=160,
        placeholder="Enter text to analyze for prompt injection and data leakage..."
    )

    analyze = st.form_submit_button(
        "🔍 Analyze Security",
        type="primary",
        use_container_width=True
    )

# =====================================================
# API CONNECTION
# =====================================================

if analyze:

    if not prompt.strip():
        st.warning("Please enter a prompt before scanning.")

    else:

        st.session_state.api_error = None

        try:

            with st.spinner(
                "🔄 Connecting to PromptShield security engine..."
            ):

                response = requests.post(
                    API_ENDPOINT,
                    json={"prompt": prompt},
                    timeout=60
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
                    raise ValueError("API returned an invalid JSON object.")

                for key in required_keys:
                    if key not in result:
                        raise ValueError(
                            f"API response is missing: {key}"
                        )

                    if not isinstance(result[key], dict):
                        raise ValueError(
                            f"Invalid API response section: {key}"
                        )

                result["analyzed_at"] = datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                )

                result["analyzed_prompt"] = prompt

                st.session_state.latest_result = result

                st.session_state.history.insert(0, result)

            st.success("✅ Security analysis completed!")

        except requests.Timeout:
            st.session_state.api_error = (
                "The API request timed out. The free Render service "
                "may be waking up. Please try again."
            )

        except requests.RequestException as error:
            st.session_state.api_error = (
                f"API connection failed: {error}"
            )

        except (ValueError, TypeError) as error:
            st.session_state.api_error = (
                f"Invalid API response: {error}"
            )


if st.session_state.api_error:
    st.error(st.session_state.api_error)

    st.info(
        "Check your Render backend and verify the API endpoint."
    )

# =====================================================
# SECURITY RESULTS
# =====================================================

result = st.session_state.latest_result

if result:

    injection = result.get("prompt_injection", {})
    leakage = result.get("data_leakage", {})
    ml = result.get("ml_classification", {})
    risk = result.get("overall_risk", {})

    score = max(
        0,
        min(100, safe_number(risk.get("risk_score", 0)))
    )

    level = risk.get("risk_level", "Unknown")
    risk_color = get_risk_color(level)

    st.divider()

    st.header("📊 Security Analysis Results")

    st.caption(
        f"Scan completed: {result.get('analyzed_at', 'Unknown')}"
    )

    # RISK OVERVIEW

    st.subheader("Overall Risk Assessment")

    col1, col2 = st.columns([1, 2])

    with col1:

        st.metric("Security Risk Score", f"{score:g}/100")

        st.markdown(
            f"<h3 style='color:{risk_color};'>{level} Risk</h3>",
            unsafe_allow_html=True
        )

    with col2:

        st.write("Risk Score Indicator")
        st.progress(score / 100)

        st.caption(
            "Higher scores indicate more detected security risks."
        )

    if str(level).lower() == "high":
        st.error("🚨 High security risk detected. Review the findings.")

    elif str(level).lower() == "medium":
        st.warning("⚠️ Medium security risk detected.")

    else:
        st.success(
            "✅ Low risk according to the configured detectors."
        )

    st.divider()

    # DETECTION MODULES

    st.header("🛡️ Security Detection Modules")

    col1, col2 = st.columns(2)

    with col1:

        st.subheader("🧩 Prompt Injection")

        if injection.get("is_suspicious"):
            st.error("Suspicious indicators detected")
        else:
            st.success("No significant indicators detected")

        st.write(
            "**Detection Status:**",
            "Detected" if injection.get(
                "is_suspicious"
            ) else "Not detected"
        )

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
            st.error("Sensitive data patterns detected")
        else:
            st.success("No supported patterns detected")

        st.write(
            "**Detection Status:**",
            "Detected" if leakage.get(
                "data_leak_detected"
            ) else "Not detected"
        )

        st.write(
            "**Detected Types:**",
            leakage.get("detected_types", [])
        )

        st.write(
            "**Risk Level:**",
            leakage.get("risk_level", "Unknown")
        )

    st.divider()

    # ML CLASSIFICATION

    st.header("🤖 Machine Learning Analysis")

    col1, col2 = st.columns(2)

    confidence = max(
        0,
        min(100, safe_number(ml.get("confidence", 0)))
    )

    with col1:
        st.metric(
            "ML Prediction",
            str(ml.get("prediction", "Unknown"))
        )

    with col2:
        st.metric(
            "Model Confidence",
            f"{confidence:g}%"
        )

    st.progress(confidence / 100)

    st.caption(
        "Classifier confidence is not a guarantee of detection accuracy."
    )

    st.divider()

    # SECURITY FINDINGS

    st.header("💡 Security Findings")

    for explanation in get_explanations(result):
        st.write(explanation)

    with st.expander("View Analyzed Prompt"):
        st.code(
            result.get("analyzed_prompt", ""),
            language="text"
        )

    # EXPORT REPORTS

    st.divider()

    st.header("📥 Export Security Report")

    col1, col2 = st.columns(2)

    with col1:

        report = json.dumps(result, indent=4)

        filename = datetime.now().strftime(
            "PromptShield_Report_%Y%m%d_%H%M%S.json"
        )

        st.download_button(
            "⬇️ Download JSON Report",
            data=report,
            file_name=filename,
            mime="application/json",
            use_container_width=True
        )

    with col2:

        single_csv = create_csv([result])

        st.download_button(
            "⬇️ Download CSV Report",
            data=single_csv,
            file_name="PromptShield_Scan_Report.csv",
            mime="text/csv",
            use_container_width=True
        )

    with st.expander("View Complete API Response"):
        st.json(result)

# =====================================================
# SCAN HISTORY
# =====================================================

st.divider()

st.header("📚 Security Scan History")

if st.session_state.history:

    st.write(
        f"Total completed analyses: {len(st.session_state.history)}"
    )

    csv_data = create_csv(st.session_state.history)

    st.download_button(
        "⬇️ Export Complete Scan History",
        data=csv_data,
        file_name="PromptShield_History.csv",
        mime="text/csv"
    )

    for index, item in enumerate(st.session_state.history):

        item_risk = item.get("overall_risk", {})

        item_level = item_risk.get("risk_level", "Unknown")
        item_score = item_risk.get("risk_score", 0)

        with st.expander(
            f"Scan {index + 1} | {item_level} Risk | {item_score}/100"
        ):

            st.write("**Date:**", item.get("analyzed_at", ""))
            st.write("**Prompt:**", item.get("analyzed_prompt", ""))
            st.write("**Risk Level:**", item_level)

            st.json(item)

else:

    st.info(
        "No scan history available. Run your first security analysis."
    )

# =====================================================
# FOOTER
# =====================================================

st.divider()

st.markdown("""
<div style="
    text-align:center;
    padding:20px;
    background:#111111;
    border:1px solid #63202b;
    border-radius:12px;
">
    <h3 style="color:#ff334f !important;">🛡️ PromptShield</h3>
    <p class="small-text">
        AI Prompt Injection & Data Leakage Detection
    </p>
    <p class="small-text">
        Built with Python | FastAPI | Streamlit | Machine Learning
    </p>
    <p class="small-text">
        AI Security Research Project | Version 2.0
    </p>
</div>
""", unsafe_allow_html=True)