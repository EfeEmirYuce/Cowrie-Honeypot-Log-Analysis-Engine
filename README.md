# Cowrie Honeypot Log Analysis Engine

![Python Version](https://img.shields.io/badge/python-3.9%2B-blue.svg)
![Libraries](https://img.shields.io/badge/libraries-pandas%20%7C%20seaborn%20%7C%20matplotlib-orange.svg)

This project provides a complete, end-to-end pipeline for analyzing SSH/Telnet honeypot logs from Cowrie. It automates the process of ingesting raw JSON log files, processing tens of thousands of events, classifying attacker behavior using a custom rule-based engine, and generating insightful reports and visualizations.

---

## Table of Contents

1.  [The Problem](#1-the-problem)
2.  [The Solution: An Automated Analysis Pipeline](#2-the-solution-an-automated-analysis-pipeline)
3.  [Project Architecture](#3-project-architecture)
4.  [Getting Started](#4-getting-started)
    - [Prerequisites](#prerequisites)
    - [Installation](#installation)
5.  [Data Collection: Cowrie Honeypot](#5-data-collection-the-cowrie-honeypot)
    - [Setting up Cowrie](#setting-up-cowrie)
    - [About the Dataset](#about-the-dataset)
6.  [How to Run the Analyzer](#6-how-to-run-the-analyzer)
7.  [Understanding the Output](#7-understanding-the-output)
8.  [How the Analysis Engine Works](#8-how-the-analysis-engine-works)
9.  [Future Improvements](#9-future-improvements)

---

### 1. The Problem

In the field of cybersecurity, one of the biggest challenges for researchers, students, and enthusiasts is the lack of access to real-world attack data. Large-scale datasets are often proprietary and held by large corporations. Without this data, it's difficult to study attacker tactics, techniques, and procedures (TTPs), understand current threat landscapes, and develop defensive strategies. Honeypots are an excellent solution to this problem, as they are designed to attract and log attack attempts. However, a running honeypot can generate hundreds of thousands of log entries, creating a new challenge: how to sift through this massive amount of data to find meaningful insights.

### 2. The Solution: An Automated Analysis Pipeline

This project presents a solution by providing a complete, automated analysis pipeline written in Python. It takes raw log files from the Cowrie honeypot as input and produces high-level, human-readable reports and visualizations as output.

The system processes all log events, groups them into unique attacker sessions, and uses a custom-built, rule-based analysis engine to classify each session based on the commands executed. This turns raw, noisy data into actionable intelligence.

### 3. Project Architecture

The script operates as a 5-stage data pipeline:

1.  **Ingestion (`read_log_files`):** Discovers and reads all `cowrie*.json` log files from the `logs` directory.
2.  **Processing (`group_and_filter_sessions`):** Parses thousands of events and groups them into coherent attacker sessions based on their unique session ID.
3.  **Analysis (`analyze_session_with_rules`):** The core of the project. This custom engine evaluates the commands in each session against a set of predefined keywords and heuristics to determine the attacker's intent and estimated skill level.
4.  **Reporting (`save_report`):** Generates a detailed report of the analysis in both CSV and user-friendly HTML formats.
5.  **Visualization (`create_visualizations`):** Creates summary charts from the analysis data, providing a high-level overview of the attack landscape.

### 4. Getting Started

Follow these steps to set up and run the analysis engine on your own machine.

#### Prerequisites

- Python 3.9 or higher
- `pip` package installer

#### Installation

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/EfeEmirYuce/Cowrie-Honeypot-Log-Analysis-Engine]
    cd [Cowrie-Honeypot-Log-Analysis-Engine]
    ```

2.  **Create a `requirements.txt` file** in the main project directory and paste the following content into it:
    ```
    pandas
    matplotlib
    seaborn
    ```

3.  **Install the required libraries:**
    ```bash
    pip install -r requirements.txt
    ```

### 5. Data Collection: The Cowrie Honeypot

The raw data for this analysis comes from the Cowrie SSH/Telnet honeypot.

#### Setting up Cowrie

Cowrie is an open-source medium- and high-interaction SSH and Telnet honeypot designed to log brute force attacks and the shell interaction performed by the attacker. The easiest way to set it up is by using its official Docker image.

For detailed installation instructions, please check out cowrie github repository (https://github.com/cowrie/cowrie).

After running the honeypot, it will generate log files in a `logs/` directory in the format `cowrie.json.YYYY-MM-DD`. These are the files that our analysis script uses.

#### About the Dataset

The log file samples used for the development and demonstration of this project were taken from kaggle (https://www.kaggle.com/datasets/nlaha11/global-ssh-and-telnet-honeypot-logs-cowrie?resource=download). To use this script with your own cowrie logs, place your collected `cowrie*.json` files into a `logs` directory inside the main project folder.

### 6. How to Run the Analyzer

Ensure your project has the following directory structure:

```
your-project-folder/
├── analysis.py
├── requirements.txt
└── logs/
    ├── cowrie.json.2025-07-01
    ├── cowrie.json.2025-07-02
    └── ...
```

To start the analysis, simply run the script from the main project directory:

```bash
python analysis.py
```

The script will provide real-time feedback in the console as it progresses through the pipeline and will generate the output files in the same directory.

### 7. Understanding the Output

After the script finishes, you will find four new files in your project directory:

1.  **`rule_based_analysis_report.csv`:** A Comma-Separated Values file containing a detailed breakdown of every analyzed session. This file is ideal for further data processing or for use in spreadsheet applications like Excel or Google Sheets.
2.  **`rule_based_analysis_report.html`:** A user-friendly HTML version of the report that can be opened directly in any web browser for easy reading.
3.  **`attack_intent_distribution.png`:** A bar chart visualizing the most common types of attacks observed (e.g., Malware Deployment, Reconnaissance). This provides a quick overview of *why* attackers are targeting your honeypot.
4.  **`attacker_skill_level.png`:** A pie chart showing the distribution of attacker skill levels as estimated by the analysis engine. This helps to understand if the attacks are from simple automated bots or more sophisticated actors.

### 8. How the Analysis Engine Works

The core of this project is the custom-built, rule-based engine in the `analyze_session_with_rules` function. It does not rely on any external AI API.

- **Keyword Dictionary:** The engine uses a predefined dictionary of `KEYWORDS` containing common commands associated with different attack phases (reconnaissance, download, destruction, etc.).
- **Scoring System:** It iterates through every command in a session and increments a score for each category if a command matches a keyword.
- **Heuristic-Based Classification:** After scoring all commands, a series of `if/elif` rules evaluates the scores to assign a final `intent` and `skill_level` to the session. For example, a session with many reconnaissance commands and a download command is classified differently than a session with only a single download command.
- **Evidence Extraction:** The engine also extracts potentially malicious URLs from `wget` or `curl` commands, providing concrete evidence in the final report.

This engine is designed to be easily extendable. You can add new keywords or write more complex classification rules to make the analysis even more intelligent.

### 9. Future Improvements

This project provides a solid foundation that can be extended in many exciting ways:

-   **AI Agent Integration:** The rule-based engine could be used as a pre-filter for a more advanced AI Agent (e.g., using Google Gemini via LangChain). The agent could be equipped with tools (like an IP reputation checker or URL scanner) and used to perform deep-dive analyses on only the most interesting sessions identified by the rule engine.
-   **Threat Intelligence Enrichment:** The attacker's source IP address could be automatically checked against external APIs like **AbuseIPDB** or **Shodan** to enrich the data with reputation and context (e.g., "Is this a known bot? Is it coming from a data center?").
-   **Advanced Visualizations:** More sophisticated visuals could be created, such as:
    -   A **geospatial map** (`folium`) showing the origin of attacks.
    -   A **time-series analysis** (`matplotlib`) showing attack frequency over time.
    -   A **word cloud** (`wordcloud`) of the most frequently used commands.
-   **Real-time Analysis:** The script could be adapted to monitor the log directory in real-time and analyze new sessions as they occur, potentially triggering alerts.

---
