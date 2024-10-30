# Created 2024 by Cyber Sundae #

import argparse # Support command line arguments
import sqlite3 # You aren't going to get very far in an SQLite3 database without something that can run SQLite3...
import os # Rather than just throw errors at a user when they supply an invalid database file, let's be nice, check for them, then provide more meaningful errors
import sys # Allow the program to terminate early
import datetime # Oh boy, I sure do love Windows FILETIME! I hope it isn't a pain to convert!
import csv # Allow the program to write to CSVs


# Establish command line arguments
def argParse():
    parser = argparse.ArgumentParser(description = "This tool is used to parse the CapabilityAccessManager.db artifact. The tool can optionally merge the WAL file into the DB.")
    parser.add_argument("-d", "--database", help = "Path to the CapabilityAccessManager.db file", required = True, metavar="DATABASE.db")
    parser.add_argument("-w", "--wal", help = "Adding this argument will merge the WAL file into the database, which may not be preferred in some situations (e.g. on a live system). The WAL file must be in the same directory as the database.", required = False, action='store_true')
    parser.add_argument("-o", "--out", help = "Adding this argument will output the results in the listed folder", required = False, metavar="OUTPUT_FOLDER")
    args = parser.parse_args() # Command line arguments aren't very useful if we never tell the program it should use them...
    return vars(args)


# Test the database to ensure it both exists and is SQLite 3. This is necessary since the sqlite3 connect function will sometimes create a database if it doesn't find one. As this is undesirable behavior in forensic analysis, we will break the Python recommendation and "ask permission instead of forgiveness," so to speak.
# "Wait a minute," you say, "can't the uri=True method in the sqlite3.connect() statement prevent that kind of behavior?" Yes it can, but in this case I believe that clearly identifying the likely errors matches The Rule of Readability better than implicitly relying on the sqlite3 library's internal functionality (see bottom of code).
def dbVerify(db_path):
    try:
        if not os.path.isfile(db_path): # Make sure the file exists before continuing
            print(f"Error: the provided database file \"{db_path}\" is not found. Please check the file path.")
            sys.exit(3) # Remember folks, exit code 2 is reserved for command line syntax errors. Skip exit code 1 for the sake of pretending we just like starting at 3, then continue sequentially
        size = os.path.getsize(db_path)
        if size < 100: # SQLite 3 documentation states the first 100 bytes of the file is reserved for header information. Anything smaller than 100 bytes is not SQLite 3.
            print(f"Error: the provided database file \"{db_path}\" is not large enough to be a valid SQLite 3 database.")
            sys.exit(4)
        with open(db_path, 'rb') as db:
            header = db.read(100)
        signature = header[:16]
        if not (signature == b'SQLite format 3\x00'): # SQLite 3 documentation lists this as the only valid SQLite 3 signature at the time of this script's creation
            print(f"Error: the provided database file \"{db_path}\" does not have a valid SQLite 3 file signature.")
            sys.exit(5)
        else:
            return True
    except OSError as e: 
        if isinstance(e, PermissionError):
            print(f"Error: permission denied for the provided database file \"{db_path}\". You may not have rights to view the file, or it may be locked. If you are running this on a live system, consider making a copy of the CapabilityAccessManager.db file(s) and running the tool against that.")
            sys.exit(6)
        else:
            print(e)
            sys.exit(7)
        return False # How did you get here? How could the code possibly find an exception that was both a PermissionError and not a PermissionError? If you ever get to this point, may the tech overlords have more mercy on you than they had on me.


# Connect to the database
def dbConnect(db_path):
    try:
        con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True) # Play nice with the database and don't write anything to it. See Python SQLite3 documentation for why this is formatted as a URI for read-only mode.
        return con
    except Exception as e:
        print(e)
        sys.exit(8)


# Merge the WAL file into the database. Only to be run if the -w/--wal option was supplied.
def walMerge(con):
    cursor = con.cursor()
    cursor.execute("PRAGMA wal_checkpoint") # PRAGMA commands in SQLite are kind of like meta commands that change the way SQLite behaves. In this case, it merges the WAL file into the database.
    con.commit()


# Extract the PackagedUsageHistory information.
def packagedUsageHistory(con):
    packaged_usage_history_list = [["ID", "StartTime", "EndTime", "AccessBlocked", "Capability", "PackageName", "UserSID"]]
    cursor = con.cursor()
    sqlite_result = cursor.execute("""
        SELECT PackagedUsageHistory.ID, PackagedUsageHistory.LastUsedTimeStart, PackagedUsageHistory.LastUsedTimeStop, PackagedUsageHistory.AccessBlocked, Capabilities.StringValue as Capability, PackageFamilyNames.StringValue as PackageName, Users.StringValue as UserSID
        FROM PackagedUsageHistory
        LEFT JOIN Capabilities ON PackagedUsageHistory.Capability = Capabilities.ID
        LEFT JOIN PackageFamilyNames ON PackagedUsageHistory.PackageFamilyName = PackageFamilyNames.ID
        LEFT JOIN Users ON PackagedUsageHistory.UserSid = Users.ID;
    """)
    packaged_usage_history = sqlite_result.fetchall()
    for row in packaged_usage_history:
        packaged_usage_history_list.append(list(row)) # If you are wondering why I didn't do this with list comprehension, see The Rule of Readability.
    return packaged_usage_history_list


# Extract the NonPackagedUsageHistory information
def nonPackagedUsageHistory(con):
    non_packaged_usage_history_list = [["ID", "StartTime", "EndTime", "AccessBlocked", "Capability", "FileID", "ProgramID", "BinaryFullPath", "UserSID"]]
    cursor = con.cursor()
    sqlite_result = cursor.execute("""
        SELECT NonPackagedUsageHistory.ID, NonPackagedUsageHistory.LastUsedTimeStart, NonPackagedUsageHistory.LastUsedTimeStop, NonPackagedUsageHistory.AccessBlocked, Capabilities.StringValue as Capability, FileIDs.StringValue as FileID, ProgramIDs.StringValue as ProgramID, BinaryFullPaths.StringValue as BinaryFullPath, Users.StringValue as UserSID 
        FROM NonPackagedUsageHistory
        LEFT JOIN Capabilities ON NonPackagedUsageHistory.Capability = Capabilities.ID
        LEFT JOIN FileIDs ON NonPackagedUsageHistory.FileID = FileIDs.ID
        LEFT JOIN ProgramIDs ON NonPackagedUsageHistory.ProgramID = ProgramIDs.ID
        LEFT JOIN BinaryFullPaths ON NonPackagedUsageHistory.BinaryFullPath = BinaryFullPaths.ID
        LEFT JOIN Users ON NonPackagedUsageHistory.UserSid = Users.ID;
    """)
    non_packaged_usage_history = sqlite_result.fetchall()
    for row in non_packaged_usage_history:
        non_packaged_usage_history_list.append(list(row)) # If you are wondering why I didn't do this with list comprehension, see The Rule of Readability.
    return non_packaged_usage_history_list


# Extract the NonPackagedIdentityRelationship information
def nonPackagedIdentityRelationship(con):
    non_packaged_identity_relationship_list = [["ID", "LastObservedTime", "FileID", "ProgramID", "BinaryFullPath"]]
    cursor = con.cursor()
    sqlite_result = cursor.execute("""
        SELECT NonPackagedIdentityRelationship.ID, NonPackagedIdentityRelationship.LastObservedTime, FileIDs.StringValue as FileID, ProgramIDs.StringValue as ProgramID, BinaryFullPaths.StringValue as BinaryFullPath
        FROM NonPackagedIdentityRelationship
        LEFT JOIN FileIDs ON NonPackagedIdentityRelationship.FileID = FileIDs.ID
        LEFT JOIN ProgramIDs ON NonPackagedIdentityRelationship.ProgramID = ProgramIDs.ID
        LEFT JOIN BinaryFullPaths ON NonPackagedIdentityRelationship.BinaryFullPath = BinaryFullPaths.ID;
    """)
    non_packaged_identity_relationship = sqlite_result.fetchall()
    for row in non_packaged_identity_relationship:
        non_packaged_identity_relationship_list.append(list(row)) # If you are wondering why I didn't do this with list comprehension, see The Rule of Readability.
    return non_packaged_identity_relationship_list


# Convert timestamps from Windows FILETIME to a human-readable format. The reason this is not done in the SQLite 3 queries is because SQLite 3 is generally harder to understand than simple functions. See The Rule of Readability.
def filetimeToHumanReadable(timestamp):
    if timestamp != 0: # If time = 0, that means the activity was blocked! Leave it at 0, no need to be silly and report January 1, 1970 as the time.
        time = datetime.datetime(1601, 1, 1,tzinfo=datetime.timezone.utc) + datetime.timedelta(seconds=timestamp/10000000) # Since the datetime class doesn't know what filetime is, we have to get the number of seconds from the FILETIME and add it to January 1, 1601 (the FILETIME structure is the number of 100-nanosecond intervals since January 1, 1601 UTC)
        time = time.strftime("%Y-%m-%d %H:%M:%S.%fZ") # Force the date and time into a common format
    else:
        time = 0
    return time


# Convert timestamps in a list, passing in both the list and the index that should be changed
def convertTimestamps(convert_list, index):
    for row in convert_list[1:]: # The reason we include the [1:] in convert_list[1:] is because that skips the first list item/row. We want to skip the first row since the first row is the column header names.
        row[index] = filetimeToHumanReadable(row[index])
    return convert_list


# Open a CSV file for writing
def csvWrite(filepath, csv_list):
    try:
        with open(filepath,'x',encoding='UTF-8',newline='') as out_file: # Create each output file, then write to it. Fail if the files already exist: we don't want to overwrite another case's data!
            csv_writer = csv.writer(out_file, delimiter=',')
            csv_writer.writerows(csv_list)
    except OSError as e:
        if isinstance(e,FileExistsError):
            print(f"Error: \"{filepath}\" already exists in selected output folder. Please delete this file or choose another output folder.")
            sys.exit(9)
        else:
            print(e)
            sys.exit(10)


"""
There is an exceptionally unlikely event that someone will one day look at this code and think, "gee, this would be a great
addition to my project! I'm going to import this whole thing because of how nifty it is!"
To that person, I say: you chose to spend part of your limited lifetime to go through my code and somehow make it work
with whatever you have written. You spent minutes, hours, or days just to make sure this would function the way you wanted
it to. Out of all the time in your life, you chose to dedicate some to my code.

...I'm sorry for your loss.


Anyways, here's my nice 'if __name__ = "__main__"' line so that it doesn't start running on its own and break everything!
"""
# Here lies the main program
if __name__ == "__main__":
    # Step 1: get the command line arguments
    args = argParse()
    # Step 2: grab the data from the command line arguments
    db_path = args["database"]
    # Step 3: make sure the code won't break anything when it tries to open the database
    dbVerify(db_path)
    # Step 4: connect to the database
    con = dbConnect(db_path)
    # Optional step: if the user wants to merge the WAL file, merge the WAL file
    if args["wal"]: # in other words, if the user included the -w/--wal option
        walMerge(con)
    # Step 5: get the "packaged" data from the CapabilityAccessManager.db database
    packaged_usage_history_list = packagedUsageHistory(con)
    # Step 6: get the "nonpackaged" data from the CapabilityAccessManager.db database
    non_packaged_usage_history_list = nonPackagedUsageHistory(con)
    # Step 7: get the "nonpackaged" identity relationship (the part of the nonpackaged data that ties binary paths to file IDs; also includes the last observed time)
    non_packaged_identity_relationship_list = nonPackagedIdentityRelationship(con)
    # Step 8: convert all the timestamps from Windows FILETIME to a human readable format, using yyyy-mm-dd hh:mm:ss.000000Z
    convertTimestamps(packaged_usage_history_list, 1)
    convertTimestamps(packaged_usage_history_list, 2)
    convertTimestamps(non_packaged_usage_history_list, 1)
    convertTimestamps(non_packaged_usage_history_list, 2)
    convertTimestamps(non_packaged_identity_relationship_list, 1)
    # Step 9: prep the filepaths for writing to CSVs
    if args["out"]: # in other words, if the user provided a value to the -o/--out option
        out_folder = args["out"]
    else: # the user did not provide a value to the -o/--out option
        out_folder = ""
    packaged_usage_history_filepath = os.path.join(out_folder, "PackagedUsageHistory.csv")
    non_packaged_usage_history_filepath = os.path.join(out_folder, "NonPackagedUsageHistory.csv")
    non_packaged_identity_relationship_filepath = os.path.join(out_folder, "NonPackagedIdentityRelationship.csv")
    # Step 10: write to CSVs
    csvWrite(packaged_usage_history_filepath, packaged_usage_history_list)
    csvWrite(non_packaged_usage_history_filepath, non_packaged_usage_history_list)
    csvWrite(non_packaged_identity_relationship_filepath, non_packaged_identity_relationship_list)


### THE RULE OF READABILITY ###
# This code is meant to be understood, not fully optimized. Before suggesting an improvement to the code, please ask yourself this question:
# "If I was a digital forensic examiner with only a few online Python/SQLite courses to guide me, could I still understand this code well 
# enough to explain it to a nontechnical audience if I absolutely needed to?"
# 
# Some examples of "improvements" that I deliberately ignored:
# - Global/scoped variables. Even though passing the sqlite3.connection() object around is weird and unoptimized, it is simple.
# - One-liners/list comprehension/advanced operators. Elegant ways to write some of the code require advanced understanding.
# - Organization. This code is organized in a manner that is easy to read, not necessarily one that is as fast as possible.
# 
# If you still feel that your recommended improvement would be easy to understand for someone with a cursory knowledge of
# Python, feel free to make the recommendation! Please be prepared for me to ask you if it maintains readability, however. :)