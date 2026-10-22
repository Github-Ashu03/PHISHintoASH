# PHISHintoASH Beginner Guide: Learn the Detector Step by Step

This guide assumes you are new to Python and cybersecurity. You do not need to understand every line before you try the project. Start by using it, then learn one piece at a time.

## 1. What does this project do?

Phishing is a trick that tries to get someone to reveal a password, payment information, or other sensitive data. A phishing message may include a dangerous link or pressure you to act quickly.

This project looks for clues in a URL or message. It combines:

- **URL checks:** Looks at the link's spelling and structure. For example, does it use an unusual domain ending such as `.xyz`? Does it use an IP address instead of a domain name?
- **Message clues:** Looks for phrases such as “verify your account” or “click now.”
- **A small machine-learning model:** Learns word patterns from example messages labeled legitimate or phishing.

It adds these clues into a **risk score** from 0 to 100 and shows which clues were found. The score is an estimate, not a guarantee or a true probability.

## 2. Try the dashboard

The dashboard is already running at [http://localhost:8501](http://localhost:8501). If it is not open, start PowerShell, go to the project folder, and run:

```powershell
cd C:\Users\crick\Projects\phishing-url-email-detector
.\venv\Scripts\streamlit.exe run app.py
```

Choose an example from the dropdown and click **Analyze**. Try all three examples. Look at the risk score and the “Triggered indicators” list. Change a few words and analyze again to see how the result changes.

Do not paste a real password, private message, or confidential link. Do not open suspicious links to check them.

## 3. Learn what happens when you click Analyze

Think of the program as a small assembly line:

```text
Text you enter → URL and message checks → combined score → result on the page
```

The dashboard in `app.py` collects your text and displays the result. It asks `detector.py` to analyze that text. The detector uses `message_model.joblib`, which is created by `model_trainer.py`. The trainer uses the example messages in its `demo_dataset()` function.

## 4. Learn the files in a useful order

1. **`app.py` — the screen.** Find `st.text_area` to see where the input box is made. Find `st.button` to see what happens when Analyze is clicked.
2. **`detector.py` — the checks.** Find `URLFeatureExtractor` for URL clues. Find `PhishingClassifier.analyze` for message clues and how the score is assembled.
3. **`model_trainer.py` — teaching the model.** Find `demo_dataset()` for labeled examples and `train()` for the TF-IDF and Naive Bayes training steps.
4. **`requirements.txt` — the packages.** These are the extra Python tools the project uses.
5. **`README.md` — project and setup notes.** It is useful when presenting the project to someone else.

## 5. Learn the machine-learning terms

- **Dataset:** A collection of examples. Here, each example is a message and a label.
- **Label:** The answer attached to an example: `0` means legitimate and `1` means phishing.
- **TF-IDF:** A way to turn words into numbers. Words that help distinguish messages get more influence.
- **Classifier:** A program that uses those numbers and learned examples to choose a label.
- **Training data:** Examples used to teach the classifier.
- **Test data:** Separate examples used to check how it did. The trainer holds some examples back for this.
- **Confusion matrix:** A small table showing correct and incorrect predictions for each label.

The built-in dataset is only 24 made-up examples, so its printed accuracy is a software demonstration, not proof that the detector works reliably on real phishing.

## 6. Make one small change at a time

Try these learning exercises in order:

1. Add a new harmless or suspicious message to `demo_dataset()` in `model_trainer.py`, keeping the benign and phishing lists balanced.
2. Change one trigger phrase in `detector.py`, then try messages containing that phrase in the dashboard.
3. Change a URL feature weight and compare the score for the suspicious URL example.
4. After changing training examples, retrain the model from PowerShell:

   ```powershell
   .\venv\Scripts\python.exe model_trainer.py
   ```

5. Refresh the dashboard. If it has not picked up the new model, stop Streamlit with `Ctrl+C` in the terminal and start it again.

Before each edit, save a copy of the file. If something stops working, undo only your last change and try again.

## 7. Understand the limits

This is a beginner portfolio demonstration. It does not visit links, inspect attachments, verify who sent a message, or know every new scam. A legitimate website can use HTTPS, and a phishing site can use HTTPS too. A low score does not prove that a message is safe. Real security systems need better data, careful testing, and human review.

For a stronger next version, study how to use a larger licensed dataset, measure false positives and missed phishing messages, and keep a separate test set that was not used for training.

## Contact and feedback

The app includes a feedback form addressed to the contact email in `.streamlit/secrets.toml`. Copy `.streamlit/secrets.toml.example` to `.streamlit/secrets.toml`, set `contact_email`, and restart the app to enable the Contact link. To have feedback sent automatically, also fill in SMTP settings for an account you control. Keep the secrets file private; never paste an email password into Python code. Without SMTP, the form opens a prefilled Gmail compose page, and the visitor must press Send. See the README for setup notes.
