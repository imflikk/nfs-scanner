import subprocess
import os
import time
import argparse
import colorama

from colorama import Fore, Back, Style

### TODO
# - Add multithreading
# - Implement file extension filtering (right now the arg does nothing)
###



def check_nfs_exports(nfs_host):
    try:
        result = subprocess.run(['showmount', '-e', nfs_host], capture_output=True, text=True, timeout=10)
        if result.returncode != 0:
            print(f"[-] Error checking NFS exports on {nfs_host}: {result.stderr.strip()}")
            return None
        exports = result.stdout.strip().split('\n')[1:]  # Skip the first line which is a header
        return [export.split()[0] for export in exports]
    except subprocess.TimeoutExpired:
        print(f"[-] Timeout expired while checking NFS exports on {nfs_host}")
        return None
    except Exception as e:
        print(f"[-] An error occurred: {e}")
        return None

def mount_nfs_share(nfs_host, nfs_share, mount_point):
    try:
        subprocess.run(['mount', '-t', 'nfs', f'{nfs_host}:{nfs_share}', mount_point], check=True)
        #print(f"[+] Successfully mounted {nfs_share} from {nfs_host} to {mount_point}")
        return True
    except subprocess.CalledProcessError as e:
        print(Fore.RED + f"[-] Failed to mount {nfs_share} from {nfs_host}")
        return False
    except Exception as e:
        print(Fore.RED + f"[-] An error occurred: {e}")
        return False

def unmount_nfs_share(mount_point):
    try:
        subprocess.run(['umount', mount_point], check=True)
        #print(f"[+] Successfully unmounted {mount_point}")
    except subprocess.CalledProcessError as e:
        print(Fore.RED + f"[-] Failed to unmount {mount_point}: {e}")
    except Exception as e:
        print(Fore.RED + f"[-] An error occurred: {e}")

def list_files(mount_point, depth):
    root_depth = mount_point.rstrip('/').count('/')
    files_to_check = []
    for dirpath, dirnames, filenames in os.walk(mount_point):
        current_depth = dirpath.rstrip('/').count('/')
        if current_depth - root_depth < depth:
            for filename in filenames:
                #print("[*] ", os.path.join(dirpath, filename))
                files_to_check.append(os.path.join(dirpath, filename))

    return files_to_check

def check_for_keywords(files, keywords, keywords_found, filesize_to_check):


    for file_path in files:
        try:
            # Get each file size and only check those smaller than 10MB
            file_size_mb = os.path.getsize(file_path) / (1024 * 1024)
            if file_size_mb > filesize_to_check:
                continue

            with open(file_path, 'r', errors='ignore') as f:
                content = f.read()
                for keyword in keywords:
                    if keyword in content:
                        print(Fore.GREEN + f"[!] Found keyword '{keyword}' in file: {file_path}")
                        keywords_found[file_path] = keyword
        except Exception as e:
            print(Fore.RED + f"[-] Could not read file {file_path}: {e}")

    return keywords_found
    
def main():

    colorama.init(autoreset=True)

    start_time = time.time()

    # Make sure we're running as root/sudo, otherwise mounting/unmounting will fail
    print("[*] Checking for sudo permissions...")
    if os.geteuid() != 0:
        print(Fore.RED + "This script requires sudo privileges. Please run as root or with sudo.")
        return
    else:
        print("[+] Running as sudo, let's go!.")

    # Parse command line args
    parser = argparse.ArgumentParser(description='NFS Export Scanner')
    parser.add_argument('-t', '--target', help='NFS server hostname or IP address')
    parser.add_argument('-x', '--extensions', help='File extensions to look for (comma-separated)', default='')
    # Default depth set to 2, which is the root directory and any immediate subdirectories
    parser.add_argument('-d', '--depth', help='Directory depth to search for files', type=int, default=2)
    parser.add_argument('-k', '--keywords', help='Keywords to search for in files (comma-separated)', default='password,credential')
    parser.add_argument('-f', '--file', help='File containing hosts to check', default=None)
    parser.add_argument('-fs', '--filesize', help='Maximum file size to check in MB', type=int, default=10)
    parser.add_argument('-o', '--output', help='Output file to save results (keyword hits and list of exports)', default=None)

    args = parser.parse_args()

    # Validate and set variables for command line args
    nfs_hosts = []

    if args.target is None and args.file is None:
        print("[-] Please specify a target NFS server using the -t or -f option.")
        return
    else:
        if args.target:
            nfs_hosts.append(args.target)
        else:
            try:
                with open(args.file, 'r') as f:
                    nfs_hosts = [line.strip() for line in f]
            except Exception as e:
                print(Fore.RED + f"[-] Could not read file {args.file}: {e}")
                return

    if args.extensions != '':
        extensions = args.extensions

    keywords = args.keywords.split(',')

    filesize_to_check = args.filesize

    # dict to track keyword data
    keywords_found = {}

    # Use a dictionary for host data.  The next line shows what the format should be
    # {'host': {'allowed': [], 'denied': []}}
    dict_of_exports = {}

    # Start iterating through each host to check for exports and try to mount
    for host in nfs_hosts:
        # Initialize the dict for the host with the correct structure
        dict_of_exports[host] = {'allowed': [], 'denied': []}
        exports = check_nfs_exports(host)
        if exports is None:
            print(Fore.RED + f"[-] Failed to retrieve NFS exports for {host}")
        elif not exports:
            print(f"[*] No NFS exports found on {host}.")
        else:
            # If we get here then we have a list of exports to try and mount
            print("="*40)
            print(f"[*] Attempting to mount exports for {host}...")
            for export in exports:
                print("-"*40)
                print("[*] Trying to mount: ", export)
                # This returns true if mount was successful
                mnt_point = f"/mnt/{host.replace('.', '_')}_{export.strip('/').replace('/', '_')}"
                os.makedirs(mnt_point, exist_ok=True)
                
                # If successfully mounted, check files for keywords
                if mount_nfs_share(host, export, mnt_point):
                    files_to_check = list_files(mnt_point, args.depth)

                    keywords_found = check_for_keywords(files_to_check, keywords, keywords_found, filesize_to_check)

                    time.sleep(2)  # Wait for a few seconds to be sure the unmount works correctly
                    print("[*] Unmounting: ", export)
                    unmount_nfs_share(mnt_point)
                    os.rmdir(mnt_point)

                    # If we got here, everything else was successful and we add to the allowed list for this host
                    dict_of_exports[host]['allowed'].append(export)
                else:
                    # Else, mount failed and add to the denied list for the host
                    dict_of_exports[host]['denied'].append(export)




    print("="*40)

    end_time = time.time()
    total_scan_time = end_time - start_time

    # Print summary of keyword results
    print("\n[*] Scan complete in {:.2f} seconds.\n".format(total_scan_time))
    if keywords_found:
        print("[!] Keywords found in the following files:")
        for file_path, keyword in keywords_found.items():
            print(Fore.GREEN + f"    - {file_path}: '{keyword}'")
    else:
        print("[*] No keywords found in scanned files.")


    # Print summary of exports by host (allowed/denied)
    for host, exports in dict_of_exports.items():
        print(f"\n[*] NFS Exports for {host}:")
        allowed = exports.get('allowed', [])
        denied = exports.get('denied', [])
        if allowed:
            print(Fore.GREEN + "  Allowed Exports:")
            for exp in allowed:
                print(Fore.GREEN + f"    - {exp}")
        else:
            print("  No allowed exports mounted.")

        if denied:
            print(Fore.RED + "  Denied Exports:")
            for exp in denied:
                print(Fore.RED + f"    - {exp}")
        else:
            print("  No denied exports.")

    # Save results to output file.  Includes both keyword hits and all exports seen for each host
    if args.output:
        try:
            with open(args.output, 'w') as out_file:
                out_file.write(f"Scan completed in {total_scan_time:.2f} seconds.\n\n")
                
                if keywords_found:
                    out_file.write("Keywords found in the following files:\n")
                    for file_path, keyword in keywords_found.items():
                        out_file.write(f"    - {file_path}: '{keyword}'\n")
                else:
                    out_file.write("No keywords found in scanned files.\n")

                out_file.write("\nNFS Exports Summary:\n")
                for host, exports in dict_of_exports.items():
                    out_file.write(f"\nNFS Exports for {host}:\n")
                    allowed = exports.get('allowed', [])
                    denied = exports.get('denied', [])
                    if allowed:
                        out_file.write("  Allowed Exports:\n")
                        for exp in allowed:
                            out_file.write(f"    - {exp}\n")
                    else:
                        out_file.write("  No allowed exports mounted.\n")

                    if denied:
                        out_file.write("  Denied Exports:\n")
                        for exp in denied:
                            out_file.write(f"    - {exp}\n")
                    else:
                        out_file.write("  No denied exports.\n")

            print(Fore.GREEN + f"\n[+] Results saved to {args.output}")
        except Exception as e:
            print(Fore.RED + f"\n[-] Could not write to output file {args.output}: {e}")

            
            
        

        

if __name__ == "__main__":
    main()

