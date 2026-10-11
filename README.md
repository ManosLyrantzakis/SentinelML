# SentinelML — Network Intrusion Detection

SentinelML is a machine learning project that classifies network traffic as **Normal** or **Attack** using the UNSW-NB15 dataset.

The project combines a Random Forest classifier with a FastAPI backend to expose predictions through a REST API.

## Features

- Network traffic classification using machine learning
- Data preprocessing with scikit-learn pipelines
- Random Forest classifier
- REST API built with FastAPI
- Interactive API documentation with Swagger UI
- Automated tests with pytest
- Saved model for inference

## Tech Stack

- Python
- pandas
- scikit-learn
- FastAPI
- Uvicorn
- joblib
- pytest

## Model Performance

Evaluation on the UNSW-NB15 test set:

| Metric | Score |
|---|---:|
| Accuracy | 90.25% |
| Attack Precision | 98.78% |
| Attack Recall | 86.75% |
| Attack F1-score | 92.38% |

**Important:** These results reflect performance on the selected dataset and test split. They do not guarantee the same performance on real-world network traffic.

The model missed some attacks in the test set, so further evaluation and threshold tuning would be necessary before any real-world security use.

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

Windows:

```bash
python -m venv .venv
.venv\Scripts\activate
```

### 3. Install dependencies

```bash
python -m pip install -r requirements.txt
```

### 4. Run the API

```bash
python -m uvicorn app:app --reload
```

The API will be available at:

`http://127.0.0.1:8000`

Interactive API documentation:

`http://127.0.0.1:8000/docs`

### 5. Run tests

```bash
python -m pytest -v -p no:cacheprovider
```

## API Usage

Send a `POST` request to `/predict` with the required network traffic features in JSON format.

Example response:

```json
{
  "prediction": 1,
  "label": "Attack"
}
```

Here, `1` represents the model's Attack classification and `0` represents Normal traffic. This is a model prediction, not confirmation of a real attack.

## Dataset

This project uses the UNSW-NB15 network intrusion detection dataset.

The dataset files are not included in this repository.

## Limitations

- This is a portfolio and educational project, not a production-ready intrusion detection system.
- Predictions depend on the dataset and features used during training.
- Real-world deployment would require additional validation, monitoring, and security testing.

## Future Improvements

- Add Docker support
- Add automated testing with GitHub Actions
- Improve evaluation and analyze false negatives
- Add prediction confidence scores
- Build a simple web dashboard

## Author

**Manos Lyrantzakis**

GitHub: [ManosLyrantzakis](https://github.com/ManosLyrantzakis)