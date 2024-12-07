# Log Analysis Script

A Python script to analyze web server log files, extract key information, and detect suspicious activities. This project demonstrates proficiency in file handling, string manipulation, and data analysis, which are essential skills in cybersecurity and software development.

---

## Features

1. **Count Requests per IP Address**:
   - Calculates the number of requests made by each IP address.
   - Displays results in descending order of request counts.

2. **Identify the Most Frequently Accessed Endpoint**:
   - Extracts and identifies the endpoint accessed the most times.

3. **Detect Suspicious Activity**:
   - Flags IP addresses with failed login attempts exceeding a configurable threshold (default: 10 attempts).

4. **Output Results**:
   - Results are displayed in the terminal and saved in a structured CSV file.

---

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/<your-username>/log-analysis-script.git
   cd log-analysis-script
