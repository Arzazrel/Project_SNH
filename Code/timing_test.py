import requests
import time
import statistics

# --- CONFIGURATION ---
LOGIN_URL = "http://localhost/login.php" 		        # Update with your actual local URL
VALID_EMAIL = "user@musicwave.it"                       # An email already registered in your DB
INVALID_EMAIL = "nonexistent_user_999@fake.com"         # A completely random/fake email
DUMMY_PASSWORD = "WrongPassword123!"                    # We use a wrong password to test the failure path
NUM_REQUESTS = 3                                        # Number of samples per test case to get a reliable average
# SEE NOTE TO THE WORKFLOW

# test function
def measure_response_time(email, password, iterations):
    times = []
    print(f"Starting test for: {email} ({iterations} requests)...")
    
    session = requests.Session()		# Establish a session to reuse the underlying TCP connection (reduces network noise)
    
    # start test itertion
    for i in range(iterations):
        payload = {
            'email': email,
            'password': password
        }
        
        start_time = time.perf_counter()			# start time
        response = session.post(LOGIN_URL, data=payload)
        end_time = time.perf_counter()				# end time
        
        duration_ms = (end_time - start_time) * 1000		# Calculate duration in milliseconds
        times.append(duration_ms)				# add current time to total time
        
        time.sleep(0.05)	# Small cooldown between requests to avoid self-induced network throttling
        
    return times

# function to calculate and print statistics
def print_statistics(label, dataset):
    avg = statistics.mean(dataset)
    med = statistics.median(dataset)
    stdev = statistics.stdev(dataset)
    print(f"\n=== STATS FOR {label} ===")
    print(f"  Average (Mean): {avg:.2f} ms")
    print(f"  Median:         {med:.2f} ms")
    print(f"  Std Deviation:  {stdev:.2f} ms")
    return avg

if __name__ == "__main__":
    print("=== MUSICWAVE TIMING ATTACK TEST ===\n")
    
    # Run benchmarks for both scenarios
    valid_user_times = measure_response_time(VALID_EMAIL, DUMMY_PASSWORD, NUM_REQUESTS)
    invalid_user_times = measure_response_time(INVALID_EMAIL, DUMMY_PASSWORD, NUM_REQUESTS)
    
    # Process and display metrics
    avg_valid = print_statistics("VALID USERNAME (Existing Email)", valid_user_times)
    avg_invalid = print_statistics("INVALID USERNAME (Non-existent Email)", invalid_user_times)
    
    # Final Evaluation
    print("\n=== FINAL ANALYSIS ===")
    time_difference = abs(avg_valid - avg_invalid)
    print(f"Delta Difference between averages: {time_difference:.2f} ms")
    
    if time_difference > 10:  # Threshold of 10ms is usually a clear indicator of cryptographic execution
        print("[!] ALERT: A significant timing discrepancy was detected.")
        print("    An attacker can systematically differentiate valid profiles from fake ones.")
    else:
        print("[+] SUCCESS: The response times are highly symmetric.")
        print("    The system is mathematically resilient against side-channel user enumeration.")
        
"""
- Login Workflow -
validate email
|-> Email is validate correctly.
|	|-> check if user is in DB
|		|-> There is
|		|	|-> check if user is blocked
|		|		|-> Is blocked -> exit
|		|		|-> Is not blocked
|		|			|-> check if password is correct (use BCRYPT)
|		|				|-> Is correct -> enter
|		|				|-> Isn't correct -> update attempt and Exit
|		|-> There isn't -> Exit
|-> Email is not valid -> Exit
"""
