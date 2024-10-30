# CapAMDB.py

## About

This tool is designed to parse the CapabilityAccessManager.db file in Windows 11. See [Capability Access Manager Forensics in Windows 11](https://medium.com/@cyber.sundae.dfir/capability-access-manager-forensics-in-windows-11-f586ef8aac79) for more information.

## Command Line

This script is written in Python 3. To run it, you could use something like the following, assuming the script and database are in the current directory:

Windows:
`py.exe .\CapAMDB.py -d .\CapabilityAccessManager.db`

Linux:
`python3 CapAMDB.py -d CapabilityAccessManager.db`

The command line options are as follows:
```
-h, --help            
        show the help message and exit

-d DATABASE.db, --database DATABASE.db
        Path to the CapabilityAccessManager.db file

-w, --wal
        Adding this argument will merge the WAL file into   the database, which may not be preferred in some situations (e.g. on a live system). The WAL file must be in the same directory as the database.
        
-o OUTPUT_FOLDER, --out OUTPUT_FOLDER
        Adding this argument will output the results in the listed folder
```