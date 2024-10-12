# File-Similarity

Comparing TLSH hashes to find similar files. It supports external lists in CSV as well as files badlisted in the
AssemblyLine system. Both are updated periodically, as native AL update services. Not recommended for use with large
number of badlisted files, it's just a linear comparison.

The `Badlist` update source is reserved for files badlisted in the AssemblyLine system.
If removed, the service will not use the badlist.
