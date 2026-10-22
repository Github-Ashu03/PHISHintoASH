# PHISHintoASH
## AI-Powered Phishing URL and Email Detector

**Cybersecurity project report**  
**Submission context:** IBM SkillsBuild Cybersecurity portfolio  
**Prepared by:** ASHU KUMAR  
**Date:** 22 October 2026

> PHISHintoASH is an independent educational portfolio project. It is not an IBM product or an official IBM security service.

## Abstract

PHISHintoASH is a small defensive analysis application that helps users inspect suspicious URLs and message text. It combines hand-written URL and language heuristics with a machine-learning text classifier built from TF-IDF features and Multinomial Naive Bayes. A Streamlit dashboard presents an estimated risk score, a classification, and the signals that contributed to the result.

The project demonstrates an end-to-end machine-learning workflow, explainable security indicators, and a simple web interface. Its built-in dataset is synthetic and intentionally small. The reported holdout result is therefore a demonstration of the training pipeline, not evidence of real-world phishing detection performance.

## 1. Project objectives

- Identify common URL characteristics associated with suspicious links.
- Detect urgent language, suspicious calls to action, and account-security impersonation cues in messages.
- Train and save a lightweight text classifier using scikit-learn.
- Combine indicators into a readable 0–100 risk estimate and show why the result was produced.
- Provide an interactive dashboard and setup documentation suitable for a cybersecurity portfolio demonstration.

## 2. Scope and threat model

### Threat addressed

The project focuses on phishing and social engineering attempts that try to persuade a person to click a link, disclose credentials, or provide sensitive account or payment information. Example tactics include fake account suspension notices, urgent verification requests, and links whose host or URL structure looks unusual.

### Out of scope

PHISHintoASH does not open or fetch submitted URLs, check domain reputation, inspect attachments, authenticate the sender, analyze email headers, or block messages. It cannot determine whether a site is safe with certainty. HTTPS only encrypts a connection; it does not prove that the destination is trustworthy.

### Intended user

The intended user is a learner or defensive analyst who wants a simple, local demonstration of phishing indicators. Results should support human review, not replace a mail security gateway, incident response process, or trusted verification channel.

## 3. System architecture

```text
User input
   │
   ├── URL(s) ── URLFeatureExtractor ── URL indicators and score
   │
   └── Message text ── heuristic checks + TF-IDF/Naive Bayes model
                                  │
                                  ▼
                     Combined score and classification
                                  │
                                  ▼
                       Streamlit results dashboard
```

### Main components

| File | Purpose |
|---|---|
| `app.py` | Streamlit dashboard, appearance themes, example inputs, result display, and feedback/contact form. |
| `detector.py` | URL feature extraction, message heuristics, model loading, and combined risk classification. |
| `model_trainer.py` | Synthetic training data, TF-IDF/Naive Bayes pipeline, holdout evaluation, and model serialization. |
| `requirements.txt` | Python dependency list. |
| `.streamlit/secrets.toml.example` | Template for optional SMTP settings; replace placeholders locally and keep real secrets private. |
| `README.md` | Project overview and setup guide. |
| `BEGINNER_GUIDE.md` | Beginner-oriented explanation and exercises. |

## 4. Detection methodology

### URL indicators

`URLFeatureExtractor` parses a URL and checks for these configured signals:

| Indicator | Trigger | Heuristic points |
|---|---|---:|
| Long URL | 75 or more characters | 12 |
| `@` symbol | At sign appears in the URL | 20 |
| IP host | Host is an IPv4 or IPv6 address | 25 |
| Many subdomains | Host has at least five labels | 12 |
| Hyphenated domain | Hyphen appears in the second-level host label | 8 |
| Selected TLD | Host ends in `.xyz`, `.top`, or `.tk` | 15 |
| Non-standard port | Port is specified and is not 80 or 443 | 12 |
| No HTTPS | Parsed URL does not use HTTPS | 10 |
| Credential-related wording | URL contains `login`, `verify`, `secure`, `update`, or `account` | 8 |

The URL heuristic score is the sum of triggered points, capped at 100. These clues can occur on legitimate sites and should not be interpreted alone.

### Message indicators

The rule-based text checks look for configured urgency and threat phrases, suspicious calls to action, and a known brand name paired with account-security language. Each matching urgency phrase adds 12 points; each matching call to action adds 10; a matching brand/security combination adds 12. The heuristic subtotal is capped when combined with other signals.

The text model uses `TfidfVectorizer` with one- and two-word features and `MultinomialNB`. It is trained to distinguish label `0` (legitimate) from label `1` (phishing). When a message contains no detected URL, the model's phishing-class probability is used as one scoring signal.

### Combined score and labels

- **Text without a detected URL:** 55% of the capped heuristic score plus 45% of the model's phishing score. If no model is available, the heuristic score is used.
- **Input containing a detected URL:** 55% of the URL score plus 35% of the message heuristic score, capped at 60 before blending. The current implementation does not apply the text model to messages that contain URLs.
- The combined score is clamped to the range 0–100.
- Below 35: **Legitimate**; 35 to below 70: **Suspicious**; 70 or above: **High-Risk Phishing**.

The score is a hand-weighted estimate, not a calibrated probability. “Legitimate” means only that the configured checks produced a low score; it does not establish that the input is safe.

## 5. Dataset and model training

The default trainer creates 24 synthetic examples: 12 labeled legitimate and 12 labeled phishing. It uses a reproducible stratified 75/25 train/test split (18 training examples and 6 holdout examples), with `random_state=42`. The fitted TF-IDF and Naive Bayes pipeline is saved as `message_model.joblib` using joblib.

The synthetic data makes the project runnable without downloading a dataset. It is not representative of current phishing campaigns, languages, writing styles, or legitimate messages. The small holdout set makes the metrics highly sensitive to individual predictions. For a credible assessment, replace this data with a larger, licensed, carefully labeled dataset; remove duplicates and near-duplicates; and reserve time- or source-separated data for final evaluation.

## 6. Demonstration results

The trainer was run with the included synthetic examples and printed the following holdout result:

- **Holdout accuracy:** 0.833 (5 correct predictions out of 6)
- **Confusion matrix** (rows are actual labels; columns are predicted labels; order is legitimate, phishing):

| Actual \ Predicted | Legitimate | Phishing |
|---|---:|---:|
| Legitimate | 2 | 1 |
| Phishing | 0 | 3 |

This is a six-message demonstration result only. It must not be described as an 83.3% real-world detection rate. No independent, representative phishing corpus was used to validate the system.

## 7. Setup and use

From the project folder, use PowerShell on Windows:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python model_trainer.py
streamlit run app.py
```

The dashboard opens locally in a browser. Choose a sample or paste a URL/message and select **Analyze for threats**. Review the classification and each listed indicator. Never paste real passwords or confidential content. The application does not fetch submitted links.

## 8. Privacy and responsible use

Analysis runs in the local Streamlit application and the detector does not send submitted scan text to an external threat-intelligence service. The optional feedback form can send content to the project contact when SMTP is configured. Without SMTP settings, it opens a prefilled Gmail compose page; the user must review and send it. SMTP credentials must be held in `.streamlit/secrets.toml` and must never be committed or placed in source code.

Use this project for education, defensive analysis, and authorized testing. Do not use the score as the sole basis for security decisions. Verify unexpected requests through a known-good website, application, or contact method.

## 9. Limitations and future work

Current limitations include the tiny synthetic dataset, simple keyword rules, no URL reputation service, no email-header or attachment analysis, possible false positives and missed attacks, and scores that are not calibrated probabilities. The model is not multilingual and can be affected by changes in attacker language.

Potential next steps:

1. Train and evaluate on a larger, current, properly licensed dataset.
2. Report precision, recall, F1, false-positive rate, and a confusion matrix on a held-out dataset.
3. Separate URL-bearing messages from plain-message evaluation and apply the text classifier consistently where appropriate.
4. Add URL normalization, IDN/punycode checks, and carefully selected reputation sources without automatically visiting untrusted links.
5. Add input limits, structured logging that avoids retaining sensitive content, and a deployment-specific privacy notice.
6. Improve accessibility and test the user interface with keyboard navigation and screen readers.

## Conclusion

PHISHintoASH demonstrates how URL heuristics, explainable language checks, and a basic NLP classifier can be assembled into a small cybersecurity application. It provides a useful learning and presentation artifact, while its synthetic training data and limited scope mean it is not a production phishing defense system.
