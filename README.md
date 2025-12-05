# Overview
Python tool that can be used to scan NFS shares for sensitive data.  Nothing complicated here, just something to save time in engagements with a large number of NFS shares to check.

It works by using the `showmount -e` system command to check for exports for a given host and then trying to mount each export in the /mnt directory.  If the mount is successful, it continues on to iterate through files in the mount point for matching extensions/keywords and saves all of the results to a log file (if specified).

## Usage

```
usage: nfs-scanner.py [-h] [-t TARGET] [-x EXTENSIONS] [-d DEPTH] [-k KEYWORDS] [-f FILE] [-fs FILESIZE] [-o OUTPUT]

NFS Export Scanner

options:
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
                        NFS server hostname or IP address
  -e EXTENSIONS, --extensions EXTENSIONS
                        File extensions to look for (comma-separated)
  -d DEPTH, --depth DEPTH
                        Directory depth to search for files
  -k KEYWORDS, --keywords KEYWORDS
                        Keywords to search for in files (comma-separated)
  -f FILE, --file FILE  File containing hosts to check
  -fs FILESIZE, --filesize FILESIZE
                        Maximum file size to check in MB
  -o OUTPUT, --output OUTPUT
                        Output file to save results (keyword hits and list of exports)
```


## Current output example

<img width="2020" height="1685" alt="image" src="https://github.com/user-attachments/assets/d078ffef-05e2-44fa-af4c-455236b5bf1b" />

## TODO

- Add multithreading/asynchonous checks per host