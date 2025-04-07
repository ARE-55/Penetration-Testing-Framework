import subprocess
import concurrent.futures
import os
import ipaddress

def run_nmap_scan(target_ip, port_range='22-443', scan_delay="1s", decoy=False, randomize=False):
    """
    Runs an Nmap scan on the specified target IP with stealth scanning techniques,
    including OS and version detection.
    """
    print(f"\n[+] Scanning {target_ip} with Nmap...\n")

    # Use sudo for privileged scans and faster timing
    command = f"sudo nmap -sS -sV -O -T4 --max-retries 2 --host-timeout 30s -p {port_range} {target_ip}"

    if decoy:
        command += " -D RND:5"  # Use 5 random decoys for stealth

    if randomize:
        command += " --randomize-hosts"

    # Execute the Nmap command
    result = subprocess.run(command, shell=True, capture_output=True, text=True)

    # Print any errors for debugging
    if result.stderr:
        print(f"[!] Nmap Error: {result.stderr}")

    # Return scan results or display error message
    return result.stdout if result.stdout else "[!] No output received or no hosts found."


def scan_multiple_targets(targets, port_range='22-443', decoy=False, randomize=False, max_threads=5):
    """
    Scans multiple targets concurrently with stealthy options.
    Limits concurrency to prevent overload.
    """
    results = []

    # Use ThreadPoolExecutor with limited threads
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        future_to_target = {
            executor.submit(run_nmap_scan, target, port_range, "1s", decoy, randomize): target
            for target in targets
        }

        for future in concurrent.futures.as_completed(future_to_target):
            target = future_to_target[future]

            try:
                result = future.result()
                if not result:
                    result = f"[!] No output for {target}"
                results.append((target, result))

            except Exception as e:
                print(f"[!] Error scanning {target}: {e}")
                results.append((target, f"[!] Scan failed with error: {e}"))

    return results


def get_ip_range(start_ip, end_ip):
    """
    Returns a list of IP addresses in the specified range.
    """
    try:
        start = ipaddress.IPv4Address(start_ip)
        end = ipaddress.IPv4Address(end_ip)

        if start > end:
            print("[!] Invalid IP range: Start IP is greater than End IP.")
            return []

        ip_list = []
        current_ip = start
        while current_ip <= end:
            ip_list.append(str(current_ip))
            current_ip += 1

        return ip_list

    except ValueError as e:
        print(f"[!] Invalid IP format: {e}")
        return []


def get_network_ips(network):
    """
    Returns a list of IP addresses in the given network.
    """
    try:
        return [str(ip) for ip in ipaddress.IPv4Network(network, strict=False).hosts()]
    except ValueError as e:
        print(f"[!] Invalid network format: {e}")
        return []


if __name__ == "__main__":
    # Ask the user for the scanning method (single IP, range, or network)
    scan_type = input("\nChoose scan type (1: Single IP, 2: IP Range, 3: Network): ")

    targets = []

    if scan_type == '1':
        target = input("Enter target IP address: ").strip()
        targets.append(target)

    elif scan_type == '2':
        start_ip = input("Enter start IP address of the range: ").strip()
        end_ip = input("Enter end IP address of the range: ").strip()
        targets = get_ip_range(start_ip, end_ip)

        if not targets:
            print("[!] No valid IPs in range. Exiting.")
            exit(1)

    elif scan_type == '3':
        network = input("Enter the network (e.g., 192.168.1.0/24): ").strip()
        targets = get_network_ips(network)

        if not targets:
            print("[!] No valid IPs in the network. Exiting.")
            exit(1)

    else:
        print("[!] Invalid choice. Exiting.")
        exit(1)

    # Optionally, allow the user to specify port range
    port_range = input("Enter the port range to scan (default is 22-443): ") or '22-443'

    # Set the save directory for results
    save_directory = "scan_results"

    # Create the directory if it doesn't exist
    if not os.path.exists(save_directory):
        os.makedirs(save_directory)
        print(f"[+] Directory '{save_directory}' created.")

    # Ask if the user wants to use stealth features
    decoy = input("Use decoy (yes/no, default is no): ").lower() == 'yes'
    randomize = input("Randomize host order (yes/no, default is no): ").lower() == 'yes'

    # Run the scan concurrently with a max of 5 threads
    max_threads = 5
    scan_results = scan_multiple_targets(targets, port_range, decoy, randomize, max_threads)

    # Print and save scan results
    valid_results = 0

    for target, result in scan_results:
        print(f"\n[+] Scan Results for {target}:")
        print(result)

        # Save each result to a separate file in the specified directory
        if result.strip() and "[!]" not in result:
            valid_results += 1
            result_file_path = os.path.join(save_directory, f"nmap_scan_results_{target.replace('.', '_')}.txt")

            with open(result_file_path, "w") as file:
                file.write(result)

            print(f"[+] Results for {target} saved to '{result_file_path}'")
        else:
            print(f"[!] No valid output for {target}. Skipping save.")

    print(f"\n[✅] Scan complete! {valid_results} valid results saved.")
