import re
import csv
from collections import defaultdict
from typing import List, Dict, Tuple

def parse_log_file(file_path: str) -> List[Dict[str, str]]:
    log_entries = []
    log_pattern = re.compile(r'([\d.]+).*"(.*?)".*?(\d{3})\s.*?(".*?")?')
    
    with open(file_path, 'r') as file:
        for line in file:
            match = log_pattern.search(line)
            print(match)
            if match:
                ip, request, status, error = match.groups()
                
                endpoint = request.split()[1] if request else 'Unknown'
                error = error.strip('"') if error else ''
                
                log_entries.append({
                    'ip': ip,
                    'endpoint': endpoint,
                    'status': status,
                    'error': error
                })
    
    return log_entries

def count_requests_per_ip(log_entries: List[Dict[str, str]]) -> Dict[str, int]:
    ip_requests = defaultdict(int)
    for entry in log_entries:
        ip_requests[entry['ip']] += 1
    
    return dict(sorted(ip_requests.items(), key=lambda x: x[1], reverse=True))

def find_most_accessed_endpoint(log_entries: List[Dict[str, str]]) -> Tuple[str, int]:
    endpoint_counts = defaultdict(int)
    for entry in log_entries:
        endpoint_counts[entry['endpoint']] += 1
    
    return max(endpoint_counts.items(), key=lambda x: x[1])

def detect_suspicious_activity(log_entries: List[Dict[str, str]], threshold: int = 10) -> Dict[str, int]:
    failed_logins = defaultdict(int)
    for entry in log_entries:
        if entry['endpoint'] == '/login' and (entry['status'] == '401' or 'Invalid credentials' in entry['error']):
            failed_logins[entry['ip']] += 1
    
    return dict(sorted(failed_logins.items(), key=lambda x: x[1], reverse=True))

def save_combined_results_to_csv(log_entries: List[Dict[str, str]], filename: str):
    ip_requests = count_requests_per_ip(log_entries)
    most_accessed_endpoint, endpoint_count = find_most_accessed_endpoint(log_entries)
    suspicious_ips = detect_suspicious_activity(log_entries)

    with open(filename, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        
        writer.writerow(['--- Requests per IP Address ---'])
        writer.writerow(['IP Address', 'Request Count'])
        for ip, count in ip_requests.items():
            writer.writerow([ip, count])
        
        writer.writerow([])
        writer.writerow(['--- Most Frequently Accessed Endpoint ---'])
        writer.writerow(['Endpoint', 'Access Count'])
        writer.writerow([most_accessed_endpoint, endpoint_count])
        
        writer.writerow([])
        writer.writerow(['--- Suspicious Activity Detected ---'])
        writer.writerow(['IP Address', 'Failed Login Count'])
        for ip, failed_count in suspicious_ips.items():
            writer.writerow([ip, failed_count])

def main(log_file_path: str = 'sample.log'):
    log_entries = parse_log_file(log_file_path)
    
    ip_requests = count_requests_per_ip(log_entries)
    print("\n--- Requests per IP Address ---")
    for ip, count in ip_requests.items():
        print(f"{ip:<20} {count}")
    
    most_accessed_endpoint, access_count = find_most_accessed_endpoint(log_entries)
    print(f"\n--- Most Frequently Accessed Endpoint ---")
    print(f"{most_accessed_endpoint} (Accessed {access_count} times)")
    
    suspicious_ips = detect_suspicious_activity(log_entries)
    print("\n--- Suspicious Activity Detected ---")
    for ip, failed_count in suspicious_ips.items():
        print(f"{ip:<20} {failed_count}")
    
    save_combined_results_to_csv(log_entries, 'log_analysis_results.csv')

if __name__ == "__main__":
    main()