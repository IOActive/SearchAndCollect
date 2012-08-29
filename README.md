SearchAndCollect
================

Search and collect executable files (Windows PE file format only) recursively from a parent directory and store in one centralized directory.

Within that centralized directory you will find all files named by their associated SHA256 hash value and a map file that maps filepaths and filenames to the associated SHA256 hash.

Syntax is as follows:

	SearchAndCollect -d "C:\Windows" 
or

	SearchAndCollect.exe -d "%ProgramFiles%"

The output would be something like this:

	c:\>SearchAndCollect.exe -d "%ProgramFiles%"
	SearchAndCollect - Search Directory and Copy Files to Centralized Directory
	Copyright (C) 2012 IOActive, Inc. All rights reserved.
	Written by Stephan Chenette @StephanChenette
	Searching C:\Program Files...
	Copying all files to directory c:\\SearchAndCollect...
	Failed to copy file C:\Program Files/Duplicati/Duplicati.exe
	Error: Access is denied.
	Done. Please check directory for copied files
