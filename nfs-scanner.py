import subprocess
import os
import time
import argparse
import colorama

from colorama import Fore, Back, Style

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
    except subprocess.CalledProcessError as e:
        print(f"[-] Failed to mount {nfs_share} from {nfs_host}: {e}")
    except Exception as e:
        print(f"[-] An error occurred: {e}")

def unmount_nfs_share(mount_point):
    try:
        subprocess.run(['umount', mount_point], check=True)
        #print(f"[+] Successfully unmounted {mount_point}")
    except subprocess.CalledProcessError as e:
        print(f"[-] Failed to unmount {mount_point}: {e}")
    except Exception as e:
        print(f"[-] An error occurred: {e}")

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

def check_for_keywords(files, keywords, keywords_found):


    for file_path in files:
        try:
            with open(file_path, 'r', errors='ignore') as f:
                content = f.read()
                for keyword in keywords:
                    if keyword in content:
                        print(Fore.GREEN + f"[!] Found keyword '{keyword}' in file: {file_path}")
                        keywords_found[file_path] = keyword
        except Exception as e:
            print(f"[-] Could not read file {file_path}: {e}")

    return keywords_found
    
def main():

    colorama.init(autoreset=True)

    start_time = time.time()

    # Make sure we're running as root/sudo, otherwise mounting/unmounting will fail
    print("[*] Checking for sudo permissions...")
    if os.geteuid() != 0:
        print("This script requires sudo privileges. Please run as root or with sudo.")
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
                print(f"[-] Could not read file {args.file}: {e}")
                return

    if args.extensions != '':
        extensions = args.extensions

    keywords = args.keywords.split(',')


    keywords_found = {}

    for host in nfs_hosts:

        exports = check_nfs_exports(host)
        if exports is None:
            print("[-] Failed to retrieve NFS exports.")
        elif not exports:
            print(f"[*] No NFS exports found on {host}.")
        else:
            print("="*40)
            print(f"[*] Attempting to mount exports for {host}...")
            for export in exports:
                print("-"*40)
                print("[*] Trying to mount: ", export)
                mnt_point = f"/mnt/{host.replace('.', '_')}_{export.strip('/').replace('/', '_')}"
                os.makedirs(mnt_point, exist_ok=True)
                mount_nfs_share(host, export, mnt_point)

                files_to_check = list_files(mnt_point, args.depth)

                keywords_found = check_for_keywords(files_to_check, keywords, keywords_found)

                time.sleep(2)  # Wait for a moment to ensure mount is stable
                print("[*] Unmounting: ", export)
                unmount_nfs_share(mnt_point)
                os.rmdir(mnt_point)


    print("="*40)

    end_time = time.time()
    total_scan_time = end_time - start_time

    print("\n[*] Scan complete in {:.2f} seconds.".format(total_scan_time))
    if keywords_found:
        print("[!] Keywords found in the following files:")
        for file_path, keyword in keywords_found.items():
            print(Fore.GREEN + f"    - {file_path}: '{keyword}'")
    else:
        print("[*] No keywords found in scanned files.")

            
            
        

        

if __name__ == "__main__":
    main()

