import time
import threading
import queue
import logging
import os

# Configure logging for better visibility of agent actions
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class LogMonitor:
    """
    Simulates a log monitoring tool that reads new entries.
    In a real-world scenario, this would connect to a real log source (e.g., a SIEM).
    """
    def __init__(self, log_file_path, interval=1):
        self.log_file_path = log_file_path
        self.interval = interval
        self.last_read_position = 0

    def start_monitoring(self, log_queue):
        """
        Starts the monitoring loop in a separate thread.
        This function continuously checks for new lines in the log file.
        """
        logging.info("Starting log monitoring...")
        while True:
            try:
                with open(self.log_file_path, 'r') as f:
                    f.seek(self.last_read_position)
                    new_logs = f.readlines()
                    self.last_read_position = f.tell()

                    for log_entry in new_logs:
                        if log_entry.strip(): # Process non-empty lines
                            log_queue.put(log_entry.strip())
                            logging.debug(f"Queued log entry: {log_entry.strip()}")
            except FileNotFoundError:
                # This should not happen with the fix, but good practice for robustness
                logging.error(f"Log file not found: {self.log_file_path}. Waiting for it to be created.")
            except Exception as e:
                logging.error(f"An unexpected error occurred in LogMonitor: {e}")

            time.sleep(self.interval)

class ThreatDetector:
    """
    An AI agent component that analyzes log entries to detect threats.
    This uses a simple rule-based system, but could be replaced with an
    advanced machine learning model for real-world applications.
    """
    def __init__(self, mitigation_queue):
        self.mitigation_queue = mitigation_queue
        # Define a list of simple threat signatures
        self.threat_signatures = [
            "Failed login attempt",
            "Port scan detected",
            "Suspicious file access"
        ]

    def analyze_log(self, log_entry):
        """
        Checks a log entry against known threat signatures.
        """
        logging.debug(f"Analyzing log entry: {log_entry}")
        for signature in self.threat_signatures:
            if signature.lower() in log_entry.lower():
                logging.warning(f"Threat detected! Signature matched: '{signature}'")
                # If a threat is found, add it to the mitigation queue
                self.mitigation_queue.put(log_entry)
                return True
        return False

class MitigationAgent:
    """
    An agent component that takes action to mitigate detected threats.
    This simulates a response, such as blocking an IP address or disabling an account.
    """
    def __init__(self):
        self.blocked_ips = set()

    def take_action(self, log_entry):
        """
        Performs a simulated mitigation action based on the log entry.
        """
        logging.info(f"🚨 Mitigating threat from log entry: {log_entry}")

        # Extract "threat" data from the log entry
        parts = log_entry.split()
        if "Failed login attempt from IP" in log_entry:
            ip_address = parts[-1]
            if ip_address not in self.blocked_ips:
                self.blocked_ips.add(ip_address)
                logging.critical(f"🛡️ Action: Blocked IP address {ip_address} due to repeated failed logins.")
        elif "Port scan detected on" in log_entry:
            ip_address = parts[-1]
            if ip_address not in self.blocked_ips:
                self.blocked_ips.add(ip_address)
                logging.critical(f"🛡️ Action: Blocked IP address {ip_address} for port scanning.")
        else:
            # Generic mitigation for other threats
            logging.critical(f"🛡️ Action: Alerting security team for manual review of threat.")
        
        logging.info("Mitigation action completed.")

def run_agent_loop(log_queue, mitigation_queue):
    """
    The main control loop for the autonomous defense agent.
    It orchestrates the flow from log analysis to mitigation.
    """
    detector = ThreatDetector(mitigation_queue)
    mitigator = MitigationAgent()

    logging.info("Autonomous Defense Agent is active.")
    while True:
        try:
            # Get a log entry from the queue without blocking
            log_entry = log_queue.get_nowait()
            logging.debug(f"Processing log: {log_entry}")
            
            # Analyze the log and act on detected threats
            if detector.analyze_log(log_entry):
                mitigator.take_action(log_entry)
            
            log_queue.task_done()
        except queue.Empty:
            # No new logs, sleep for a bit to avoid busy-waiting
            time.sleep(0.1)

def simulate_threats(log_file_path):
    """
    Simulates new log entries being written to a file over time.
    """
    threats = [
        "User 'admin' failed login attempt from IP 192.168.1.10",
        "INFO: Normal application activity.",
        "Port scan detected on TCP port 443 from IP 203.0.113.5",
        "User 'guest' failed login attempt from IP 192.168.1.10",
        "INFO: User 'manager' logged in successfully.",
        "Suspicious file access by user 'dev' to /etc/passwd"
    ]
    
    with open(log_file_path, 'a') as f:
        f.write("") # Ensure file is empty before starting
    
    for i, entry in enumerate(threats):
        with open(log_file_path, 'a') as f:
            f.write(entry + '\n')
        logging.info(f"Simulated log entry {i+1} written.")
        time.sleep(1) # Simulate a delay between log entries
    logging.info("Threat simulation complete.")

if __name__ == "__main__":
    # Define a log file for our simulation
    LOG_FILE = "simulated_security.log"

    # CRITICAL FIX: Ensure the file exists before starting the threads
    # Use 'w' to create a new, empty file if it doesn't exist
    if not os.path.exists(LOG_FILE):
        open(LOG_FILE, 'w').close()
        
    # Create thread-safe queues for communication between components
    log_queue = queue.Queue()
    mitigation_queue = queue.Queue()

    # Create and start the log monitoring thread
    monitor = LogMonitor(LOG_FILE)
    monitor_thread = threading.Thread(target=monitor.start_monitoring, args=(log_queue,), daemon=True)
    monitor_thread.start()

    # Create and start the main agent loop thread
    agent_thread = threading.Thread(target=run_agent_loop, args=(log_queue, mitigation_queue), daemon=True)
    agent_thread.start()

    # Start the simulation that writes "threats" to the log file
    simulate_threats(LOG_FILE)

    # Keep the main thread alive to allow daemon threads to run
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("Program terminated by user.")
