# Log Analysis Tool


## Features

- **Log Parsing**: Extracts key information from log files, including:
  - IP addresses
  - Requested endpoints
  - Response status codes
  - Error messages

- **IP Request Analysis**: 
  - Counts and ranks requests per IP address
  - Identifies most active IP addresses

- **Endpoint Tracking**:
  - Determines the most frequently accessed endpoint
  - Provides access count for top endpoints

- **Suspicious Activity Detection**:
  - Identifies potential security threats
  - Tracks failed login attempts
  - Highlights IPs with multiple failed login attempts

- **Reporting**:
  - Prints detailed analysis to console
  - Generates a comprehensive CSV report

## Requirements

- Python 3.7+
- Standard Python libraries (no additional installations required)
  - `re`
  - `csv`
  - `collections`
  - `typing`

## Usage

### Running the Script

```bash
python log_analysis.py [path_to_log_file]
```

If no log file is specified, the script defaults to `sample.log` in the current directory.

### Output

The script produces two types of output:

1. **Console Output**: 
   - Requests per IP Address
   - Most Frequently Accessed Endpoint
   - Suspicious Activity Detection

2. **CSV Report**: 
   - `log_analysis_results.csv` with detailed breakdown of findings


## Log Format Support

The script is designed to parse log files with the following pattern:
- IP Address
- Request Details
- Status Code
- Optional Error Message

Example log line:
```
192.168.1.100 - - [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326
```


