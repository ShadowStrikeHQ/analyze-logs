import argparse
import logging
import pandas as pd
import re  # For regex-based pattern matching

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Analyze log files for patterns and generate reports.")

    # Add arguments
    parser.add_argument("log_file", help="Path to the log file to analyze.")
    parser.add_argument("-p", "--pattern", help="Regex pattern to search for in the log file.", required=False)
    parser.add_argument("-o", "--output", help="Path to the output CSV file (optional).", required=False)
    parser.add_argument("-l", "--limit", type=int, help="Limit the number of log entries to process (optional).", required=False)
    parser.add_argument("--ip_address", help="Extract and analyze IP addresses.", action="store_true", required=False)
    parser.add_argument("--error_codes", help="Extract and analyze error codes.", action="store_true", required=False)
    parser.add_argument("--user_agents", help="Extract and analyze User-Agent strings.", action="store_true", required=False) #offensive
    
    return parser.parse_args()


def analyze_log_file(log_file, pattern=None, limit=None, ip_address=False, error_codes=False, user_agents=False):
    """
    Parses and analyzes the log file, extracting relevant information based on the specified arguments.

    Args:
        log_file (str): Path to the log file.
        pattern (str, optional): Regex pattern to search for. Defaults to None.
        limit (int, optional): Limit the number of log entries. Defaults to None.
        ip_address (bool, optional): Extract IP addresses. Defaults to False.
        error_codes (bool, optional): Extract error codes. Defaults to False.
        user_agents (bool, optional): Extract user agents. Defaults to False.
    
    Returns:
        pandas.DataFrame: A DataFrame containing the analysis results. Returns an empty DataFrame if an error occurs.
    """
    try:
        with open(log_file, "r", encoding="utf-8") as f:  # Explicit encoding for wider compatibility
            lines = f.readlines()

        if limit:
            lines = lines[:limit]

        data = []
        for line in lines:
            entry = {}
            entry["log_entry"] = line.strip()

            if pattern:
                match = re.search(pattern, line)
                if match:
                    entry["pattern_match"] = match.group(0)  # Store the entire matched string
                else:
                    entry["pattern_match"] = None

            if ip_address:
                ip_match = re.search(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', line)
                if ip_match:
                    entry["ip_address"] = ip_match.group(0)
                else:
                    entry["ip_address"] = None
            
            if error_codes:
                error_code_match = re.search(r'ERROR\s+(\d+)', line)  # Example: "ERROR 1234"
                if error_code_match:
                    entry["error_code"] = error_code_match.group(1) # Group(1) is the code itself, not the whole string.
                else:
                    entry["error_code"] = None
            
            if user_agents:
                user_agent_match = re.search(r'User-Agent:\s*(.+)', line)
                if user_agent_match:
                    entry["user_agent"] = user_agent_match.group(1)
                else:
                    entry["user_agent"] = None

            data.append(entry)

        df = pd.DataFrame(data)
        return df

    except FileNotFoundError:
        logging.error(f"Log file not found: {log_file}")
        return pd.DataFrame()
    except Exception as e:
        logging.error(f"An error occurred during log analysis: {e}")
        return pd.DataFrame()


def main():
    """
    Main function to orchestrate the log analysis process.
    """
    args = setup_argparse()

    # Input validation: Check if the log file is a string
    if not isinstance(args.log_file, str):
        logging.error("Invalid log file path. Please provide a string.")
        return

    # Input validation: Check if the output file is a string (if provided)
    if args.output and not isinstance(args.output, str):
        logging.error("Invalid output file path. Please provide a string.")
        return

    # Input validation: Check if the limit is a positive integer (if provided)
    if args.limit is not None and (not isinstance(args.limit, int) or args.limit <= 0):
        logging.error("Invalid limit value. Please provide a positive integer.")
        return


    try:
        df = analyze_log_file(args.log_file, args.pattern, args.limit, args.ip_address, args.error_codes, args.user_agents)

        if not df.empty:
            if args.output:
                df.to_csv(args.output, index=False)
                logging.info(f"Analysis results saved to: {args.output}")
            else:
                print(df.to_string()) # Print to console if no output file is specified.
        else:
             logging.warning("No data to display/save.  Check log file or parameters.")

    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    # Example Usage:
    # 1. Analyze a log file and print the results: python main.py mylog.txt
    # 2. Analyze a log file, searching for a pattern, and save to CSV: python main.py mylog.txt -p "error" -o error_log.csv
    # 3. Analyze a log file, limit to 100 lines, and extract IP addresses: python main.py mylog.txt -l 100 --ip_address
    # 4. Analyze a log file for error codes: python main.py mylog.txt --error_codes
    # 5. Analyze a log file for user agents: python main.py mylog.txt --user_agents
    main()