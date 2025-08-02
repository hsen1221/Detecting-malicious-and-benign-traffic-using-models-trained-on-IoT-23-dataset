# File: dashboard.py
import sys
import json
import time
from yaspin import yaspin

class BColors:
    """A class for terminal color codes."""
    HEADER = '\033[95m'
    OKGREEN = '\033[92m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    CYAN = '\033[96m'

def update_dashboard(benign_count, malicious_count, last_detection_info):
    """Clears the screen and redraws the entire dashboard."""
    total = benign_count + malicious_count
    if total == 0:
        return

    benign_perc = (benign_count / total) * 100
    malicious_perc = (malicious_count / total) * 100
    
    # Define the width of the bar chart
    bar_width = 50
    benign_bar = '█' * int(benign_perc / 100 * bar_width)
    malicious_bar = '█' * int(malicious_perc / 100 * bar_width)

    # Clear the terminal screen
    print("\033[H\033[J", end="")
    
    # Print the dashboard
    print(f"{BColors.BOLD}{BColors.HEADER}--- Real-Time IoT Intrusion Detection System ---{BColors.ENDC}")
    print("="*55)
    print(f"Total Connections Analyzed: {BColors.CYAN}{total}{BColors.ENDC}\n")
    
    print(f"{BColors.OKGREEN}Normal Traffic:{BColors.ENDC} {benign_count} ({benign_perc:.1f}%)")
    print(f"[{BColors.OKGREEN}{benign_bar:<{bar_width}}{BColors.ENDC}]")
    
    print(f"\n{BColors.FAIL}Attack Traffic:{BColors.ENDC} {malicious_count} ({malicious_perc:.1f}%)")
    print(f"[{BColors.FAIL}{malicious_bar:<{bar_width}}{BColors.ENDC}]")
    
    print("\n" + "="*55)
    if last_detection_info:
        ts = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(last_detection_info['ts']))
        print(f"{BColors.BOLD}Last Attack Detected:{BColors.ENDC}")
        print(f"  Time:    {ts}")
        print(f"  Source:  {last_detection_info['src']}")
        print(f"  Dest:    {last_detection_info['dst']}")
        print(f"  State:   {last_detection_info['state']}")
    else:
        print(f"{BColors.BOLD}Last Attack Detected:{BColors.ENDC} None")
    
    print("\n" + "="*55)
    print("Listening for predictions... (Ctrl+C to exit)")

def main():
    """Reads JSON from stdin and updates the dashboard."""
    benign_count = 0
    malicious_count = 0
    last_detection = None

    # Initial display
    update_dashboard(0, 0, None)

    with yaspin(text="Waiting for prediction data from predict.py...", color="yellow").right as spinner:
        for line in sys.stdin:
            spinner.ok("✔") # Show a checkmark once data starts flowing
            
            try:
                data = json.loads(line)
                
                if data.get('prediction') == 1:
                    malicious_count += 1
                    # Store info about the last detected attack
                    last_detection = {
                        'ts': data['features']['ts'],
                        'src': data['features']['id_orig_h'],
                        'dst': f"{data['features']['id_resp_h']}:{data['features']['id_resp_p']}",
                        'state': data['features']['conn_state']
                    }
                else:
                    benign_count += 1
                
                # Update the dashboard with the new counts
                update_dashboard(benign_count, malicious_count, last_detection)

            except (json.JSONDecodeError, KeyError):
                # Ignore malformed lines or lines without the expected keys
                continue
            except KeyboardInterrupt:
                break
    
    print("\nDashboard stopped.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nDashboard stopped by user.")

