# SentinelML — AI Network Intrusion Detection

SentinelML is a machine learning application that classifies network traffic as **Normal** or **Attack** using a Random Forest classifier trained on the UNSW-NB15 dataset.

The project combines a machine learning pipeline, a FastAPI REST API, persistent prediction history, and a web dashboard. It is deployed on Render and uses Neon PostgreSQL for cloud-based prediction storage.

## Live Demo

- **Live Dashboard:** https://sentinelml-49na.onrender.com/dashboard
- **API Documentation (Swagger UI):** https://sentinelml-49na.onrender.com/docs
- **GitHub Repository:** https://github.com/ManosLyrantzakis/SentinelML

> Note: The deployed service may take a short time to wake up after a period of inactivity.

## Features

- Network traffic classification using machine learning
- Random Forest model trained on the UNSW-NB15 dataset
- Data preprocessing and feature preparation with scikit-learn
- REST API built with FastAPI
- Interactive API documentation through Swagger UI
- Persistent prediction history using Neon PostgreSQL
- Local SQLite database fallback when PostgreSQL is not configured
- Web dashboard for viewing predictions and history
- Automated tests with pytest
- Continuous integration with GitHub Actions
- Saved model for inference using joblib

## Tech Stack

| Technology | Purpose |
|---|---|
| Python | Application and ML development |
| pandas | Data manipulation |
| scikit-learn | Preprocessing, model training and inference |
| Random Forest | Network traffic classification |
| FastAPI | REST API |
| Uvicorn | ASGI server |
| PostgreSQL / Neon | Cloud prediction history |
| SQLite | Local database fallback |
| joblib | Model serialization |
| pytest | Automated testing |
| GitHub Actions | Continuous integration |
| Render | Application deployment |

## Model Performance

Evaluation on the selected UNSW-NB15 test set:

| Metric | Score |
|---|---:|
| Accuracy | 90.25% |
| Attack Precision | 98.78% |
| Attack Recall | 86.75% |
| Attack F1-score | 92.38% |

These results reflect performance on the selected dataset and test split. They do not guarantee equivalent performance on real-world network traffic.

The model missed some attacks in the test set. Further evaluation, false-negative analysis, and threshold tuning would be necessary before considering any real-world security application.

## Architecture

The application follows this workflow:

1. Network traffic features are submitted to the API.
2. FastAPI validates the input using a Pydantic model.
3. The trained Random Forest model predicts whether the traffic is Normal or an Attack.
4. The prediction and timestamp are stored in the configured database.
5. The API returns the prediction result.
6. The dashboard displays prediction information and history.

## Project Structure

```text
SentinelML/
├── app.py
├── test_app.py
├── machine_learning.ipynb
├── models/
│   └── random_forest_model.joblib
├── reports/
│   └── baseline_metrics.json
├── requirements.txt
└── .gitignore
```

## Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/ManosLyrantzakis/SentinelML.git
cd SentinelML
```

### 2. Create a virtual environment

**Windows:**

```bash
python -m venv .venv
.venv\Scripts\activate
```

### 3. Install dependencies

```bash
python -m pip install -r requirements.txt
```

### 4. Run the API locally

```bash
python -m uvicorn app:app --reload
```

The application will be available at:

- API: http://127.0.0.1:8000
- API documentation: http://127.0.0.1:8000/docs
- Dashboard: http://127.0.0.1:8000/dashboard

The application uses SQLite when `DATABASE_URL` is not configured. To use PostgreSQL, configure the `DATABASE_URL` environment variable with a valid PostgreSQL connection string.

**Never commit database credentials or other secrets to GitHub.**

## API Usage

### Make a prediction

Send a `POST` request to `/predict` with all required network traffic features in the JSON request body.

The endpoint expects the feature fields directly in the request body, not nested inside a `features` object.

You can explore the required fields and submit test requests through the [interactive API documentation](https://sentinelml-49na.onrender.com/docs).

### Example response

```json
{
  "id": 1,
  "timestamp": "2026-10-16T13:19:58.760860+00:00",
  "prediction": 0,
  "label": "Normal"
}
```

The values above are an illustrative example.

- `0` represents a Normal classification.
- `1` represents an Attack classification.
- `id` identifies the stored prediction.
- `timestamp` records when the prediction was created.
- `label` provides a human-readable classification.

A model prediction is not, by itself, confirmation that a real attack has occurred.

## Database and Prediction History

SentinelML stores prediction records in a database.

Each record contains:

- Prediction ID
- Timestamp
- Numeric prediction
- Classification label

The deployed application uses Neon PostgreSQL for persistent cloud storage. A SQLite fallback is available for local development when PostgreSQL is not configured.

## Testing

Run the automated test suite with:

```bash
python -m pytest -v -p no:cacheprovider
```

GitHub Actions runs automated tests to help verify the application when code changes are pushed to the repository.

## Dataset

This project uses the UNSW-NB15 network intrusion detection dataset for model development and evaluation.

The dataset files are not included in this repository.

## Limitations

- This is an educational and portfolio project, not a production-ready intrusion detection system.
- Model performance depends on the dataset, feature distribution, and training process.
- Real-world network traffic may differ significantly from the evaluation data.
- False negatives and false positives remain possible.
- Production deployment would require additional validation, monitoring, access controls, and security testing.

## Future Improvements

- Add Docker support and containerized deployment.
- Add prediction confidence scores and probability-based analysis.
- Expand evaluation with additional datasets.
- Analyze false positives and false negatives in greater detail.
- Improve monitoring, observability, and deployment reliability.

## Author

**Manos Lyrantzakis**

GitHub: https://github.com/ManosLyrantzakis

