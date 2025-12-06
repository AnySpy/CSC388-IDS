# CSC388-IDS
An IDS developed for my secure computing class at Missouri State University

# Ideas
1. We create a list of dictionaries (sigdict) that parses files stored in ./signatures.txt
2. We (deep) copy the list per thread and delete the dictionary entries that contain the signal with the correct frequency (>=)
3. We check dictionaries to see if they're empty. If they are, the program has been flagged as potentially malicious

# Findings
* I learned some basics on using the multithreading library (manager calls need to be done in the `if __name__ is "__main__"` section, etc)
* I used Ruff for linting and formatting guidance
* I learned how to use cProfile to do profiling (not included in this repo, but it's super simple)
* I re-discovered that, when multithreading, there's an "optimal" core count and I shouldn't just default to "what feels good"
* Error handling is important! Even if it's just giving feedback on issues and closing the program.

# Notes
A lot of my comments on discovery/thought process are in this file. Hope any viewers have fun looking at it, I had a good time developing it :)
