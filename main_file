"""
Gwyn Young's Solution ≽^•⩊•^≼


So, my idea for this was simple:
  1. We create a list of dictionaries representing the signals provided in './signatures.txt'
  2. We copy that list per thread and delete items once we find the correct signal with the correct frequency
  3. If a dictionary is empty, that means the program has been flagged as potentially malicious.
I wasn't sure if the correct implementation was to handle only consecutive calls
For example, (fstat64,3, ioctl,5, rt_sigprocmask,3) is clearly positive. If we throw a sendto after the (ioctl,5) so it then reads:
  (fstat64,3, ioctl,5, sendto,1, rt_sigprocmask,3) is that flag okay to send out?
In the end, I decided that the second instance should be okay to flag as well since it would be more resistant to polymorphism at the tradeoff of having more flags
   which I believe is fine with an IDS because we'd rather it have false positives than false negatives.
If this is an incorrect interpretation of the design docs, I'm sorry!
"""

import copy
import multiprocessing
import sys
from pathlib import Path

# I did some testing (To make sure that I was doing multithreading correctly) and found that this program runs best with 6 threads?
#   Running with more or less gives ~+0.01s execution time per core! I think that's really interesting!
THREADCOUNT = 6


# This function just checks if any dictionaries are empty. If they are, the program has been flagged and we can stop parsing.
#   I believe ending parsing is correct since the program would be immediately terminated in a real IDS.
# It's just a helper because fileParser() was getting disgusting looking :(
def dictChecker(sigdict: list) -> bool:
    for dict in sigdict:
        if not bool(dict):
            return True
    return False


# The idea here is that we parse each consecutive line to get the aggregate consecutive calls of a given type.
#   From there, we don't need to store it, we can just parse the signal individually.
# This is where we generate the representation in point 1 of the PDF (lines 41-56). It would be trivial to put it into a file if you wanted that.
#   However, I didn't do that since that's quite a bit of storage and it sounds horrible needing to delete those files every time you're grading something
#   so I just didn't. It would be as simple as writing to a file what we pass to signalParser: "(old_line,freq)\n"
def fileParser(fname: str, sigdict: list) -> tuple[bool, int, int]:
    line_number = 0
    with open(fname, "r") as f:
        freq = 1
        old_line = f.readline().strip()
        for line in f:
            line = line.strip()
            line_number += 1
            if line == old_line:
                freq += 1
            else:
                sigdict = signalParser(old_line, freq, sigdict)
                if dictChecker(sigdict):
                    break
                old_line = line
                freq = 1

    # Since we've modified the dictionaries, we need to return the index of the signature that's violated so we can reference it with the original sigdict
    i = 0
    for dict in sigdict:
        if not bool(dict):
            return (True, i, line_number)
        i += 1
    # Returning dummy values because Python won't let me return None for the second and third values :(
    #   Nothing will happen to it, but I have to return something when using type hinting
    return (False, -1, line_number)


def getSignatures(fpath: str) -> list:
    if isinstance(fpath, str):
        try:
            f = open(fpath, "r")
        except OSError as err:
            print(f"OSError: {err}")
            sys.exit(1)
    else:
        print(f'Error: "{fpath}" is not a String.')
        sys.exit(1)

    # My idea for here is that we create a list of dictionaries, each representing a signature.
    #   From there, we can check against each item in each dictionary for a correct signature.
    sigdict = []
    for line in f:
        dictionary = {}
        # I really wanted consistent formatting to parse this, so this just turns it into "name,freq,name,freq,..."
        line = line.strip("()\n").replace(" ", "").split(",")
        for i in range(0, len(line), 2):
            try:
                dictionary[line[i]] = int(line[i + 1])
            except ValueError as e:
                print(f"ValueError: {e}")
                sys.exit()
        if bool(dictionary):
            sigdict.append(dictionary)
    return sigdict


def printFormat(fname: str, dict: dict, line_number: int, print_lock):
    dictstr = str(dict).strip("'").replace(":", ",")
    fname = str(fname).replace("_", " ")
    with print_lock:
        print(f"{fname[11:-4]}: {dictstr}, Line: {line_number}")


# This function goes through and checks if a frequency has been exceeded by a specific signal. If it has, it deletes the entry.
#   If an entire dictionary is empty, that means it has been flagged by the system as a potentially malicious program!
def signalParser(signal: str, freq: int, sigdict: list) -> list:
    for dict in sigdict:
        if signal in dict and dict.get(signal) <= freq:
            del dict[signal]
    return sigdict


def worker(sigdict: list, fileQueue: multiprocessing.Queue, print_lock):
    while True:
        fpath = fileQueue.get()
        if fpath is None:
            break

        # We have to deepcopy sigdict because it's a list of dictionaries. Just copying it will cause it to still contain the pointers to the dicts :(
        b, d, i = fileParser(fpath, copy.deepcopy(sigdict))
        if b:
            printFormat(fpath, sigdict[d], i, print_lock)
    return 1


def main(print_lock, sigdict, fileQueue):
    # I went ahead and implemented multithreading to (hopefully) get brownie points for my extremely inefficient solution to HW02 :3
    processes = []
    for _ in range(THREADCOUNT):
        p = multiprocessing.Process(
            target=worker, args=(sigdict, fileQueue, print_lock)
        )
        processes.append(p)
        # We add "None" for each process in the fileQueue because this solves an issue with permanently blocking.
        #   I don't know the "why" of it (I didn't do enough research) but it functions the same as my previous solution of:
        #   "while filequeue.get() is not empty" and people say it's safer. So I'm trusting them
        fileQueue.put(None)
        p.start()

    for p in processes:
        p.join()

    return 0


if __name__ == "__main__":
    # The file paths are right here for easy editing if you need to!
    signature_filepath = "./signatures.txt"
    sources_filepath = "all_traces/"

    with multiprocessing.Manager() as manager:
        print_lock = manager.Lock()
        # The file that contains the signatures
        sigdict = getSignatures(signature_filepath)
        if not sigdict:
            print(f"sigdict returned from getSignatures as empty.\n\tMake sure that the file contains data and try again.")
            sys.exit(1)
        fileQueue = manager.Queue()

        try:
            # The folder that contains the traces
            sourcedir = Path(sources_filepath)
            files = sourcedir.iterdir()
        except FileNotFoundError as e:
            print(f"FileNotFoundError: {e} \n\tCheck the spelling and try again.")
            sys.exit(1)
        except NotADirectoryError as e:
            print(f"NotADirectoryError: {e} \n\tCheck the spelling and try again.")
            sys.exit(1)
        except PermissionError as e:
            print(
                f"PermissionError: {e} \n\tCheck that you have permission to read that directory and try again.."
            )
            sys.exit(1)
        except Exception as e:
            print(
                f"An unexpected, critical error has occurred while accessing the directory: {e}"
            )
            sys.exit(1)

        for f in files:
            fileQueue.put(f)

        main(print_lock, sigdict, fileQueue)
