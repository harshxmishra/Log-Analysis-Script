import argparse
import csv
from collections import Counter, defaultdict

# Define a function to parse log entries
def parse_log_line(line):
    try:
        parts = line.split()
        ip_address = parts[0]
        endpoint = parts[6]
        status_code = parts[8]
        return ip_address, endpoint, status_code
    except IndexError:
        return None, None, None

# Count requests per IP
def count_requests_per_ip(log_file):
    ip_counter = Counter()
    with open(log_file, 'r') as file:
        for line in file:
            ip_address, _, _ = parse_log_line(line)
            if ip_address:
                ip_counter[ip_address] += 1
    return ip_counter

# Identify the most frequently accessed endpoint
def most_frequent_endpoint(log_file):
    endpoint_counter = Counter()
    with open(log_file, 'r') as file:
        for line in file:
            _, endpoint, _ = parse_log_line(line)
            if endpoint:
                endpoint_counter[endpoint] += 1
    return endpoint_counter.most_common(1)[0] if endpoint_counter else (None, 0)

# Detect suspicious activity
def detect_suspicious_activity(log_file, threshold):
    failed_attempts = defaultdict(int)
    with open(log_file, 'r') as file:
        for line in file:
            ip_address, _, status_code = parse_log_line(line)
            if ip_address and status_code == "401":
                failed_attempts[ip_address] += 1
    return {ip: count for ip, count in failed_attempts.items() if count > threshold}

# Write results to a CSV file
def write_results_to_csv(ip_requests, most_accessed, suspicious_activities, output_file):
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        # Write Requests per IP
        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_requests.items():
            writer.writerow([ip, count])

        writer.writerow([])  # Blank line

        # Write Most Accessed Endpoint
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow([most_accessed[0], most_accessed[1]])

        writer.writerow([])  # Blank line

        # Write Suspicious Activity
        writer.writerow(["Suspicious Activity Detected"])
        writer.writerow(["IP Address", "Failed Login Attempts"])
        for ip, count in suspicious_activities.items():
            writer.writerow([ip, count])

# Main function
def main():
    # Set up argument parsing
    parser = argparse.ArgumentParser(description="Analyze web server log files.")
    parser.add_argument("--logfile", type=str, required=True, help="Path to the log file to be analyzed.")
    parser.add_argument("--threshold", type=int, default=10, help="Threshold for failed login attempts (default: 10).")
    parser.add_argument("--output", type=str, default="log_analysis_results.csv", help="Path to save the CSV results.")
    args = parser.parse_args()

    # Analyze the log file
    ip_requests = count_requests_per_ip(args.logfile)
    most_accessed = most_frequent_endpoint(args.logfile)
    suspicious_activities = detect_suspicious_activity(args.logfile, args.threshold)

    # Display results
    print("Requests per IP:")
    for ip, count in ip_requests.items():
        print(f"{ip:20} {count}")
    
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed[0]} (Accessed {most_accessed[1]} times)")

    print("\nSuspicious Activity Detected:")
    if suspicious_activities:
        for ip, count in suspicious_activities.items():
            print(f"{ip:20} {count}")
    else:
        print("No suspicious activity detected.")

    # Save results to CSV
    write_results_to_csv(ip_requests, most_accessed, suspicious_activities, args.output)
    print(f"\nResults saved to {args.output}")

if __name__ == "__main__":
    main()
