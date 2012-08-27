
/*
 * SearchAndCollect 
 * Purpose: search and collect all binaries from the system windows directory and copy into current working directory 
 *
 * Copyright (c) 2012 by Stephan Chenette, IOActive, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <windows.h>
#include <iostream>

#include <stdio.h>

#include <wincrypt.h>	// CryptoAPI definitions
#include <strsafe.h>	// String safe functions
#include <shlwapi.h>	// PathFileExistsA

#include <string>
#include <vector>

#include <openssl/sha.h>

using namespace std;

#pragma comment( lib, "shlwapi.lib" ) // PathFileExistsA

#define ARRAY_SIZE(array) (sizeof((array))/sizeof((array[0])))

//
// for debug logging
// use DebugView from SysInternals to see debug statements
// http://technet.microsoft.com/en-us/sysinternals/bb896647.aspx
//
int DebugMsg( const char* format, ... )
{
	#define MAX_DEBUG_STRING 10000 // must be >= 4 (see below)

	char buffer[MAX_DEBUG_STRING];
	buffer[MAX_DEBUG_STRING-1] = 0;

	HRESULT hr = StringCchPrintf( buffer, MAX_DEBUG_STRING, "SearchAndCollect - PID %lu Thread %lu: ",
							GetCurrentProcessId(), GetCurrentThreadId() );
	if( FAILED(hr) ) 
	{
		return -1;
	}

	va_list arglist;
	va_start( arglist, format );

	try
	{
		HRESULT hr = StringCchVPrintf( (buffer+strlen(buffer)), MAX_DEBUG_STRING - 4 - strlen(buffer), format, arglist );
		if( FAILED(hr) ) 
		{
			return -1;
		}
	}
	catch(...)
	{
		OutputDebugStringA( "DebugMsg threw exception while processing a debug message");
		return -1;
	}

	va_end( arglist );

	// force a NULL in case string was larger than MAX_DEBUG_STRING
	buffer[MAX_DEBUG_STRING - 4] = 0;
	StringCchCat( buffer, MAX_DEBUG_STRING, "\r\n" );
	OutputDebugStringA( buffer );

	return 0;
}

//
// get currrent path
//
void GetCurrentPath(char* path, unsigned int len)
{
	HMODULE hmod = GetModuleHandle( NULL );
	CHAR modulePath[MAX_PATH];

	modulePath[MAX_PATH-1] = 0;
	DWORD moduleLen = GetModuleFileName( hmod, modulePath, MAX_PATH ); 

	char drive[_MAX_DRIVE];
	char dir[_MAX_DIR];
	char fname[_MAX_FNAME];
	char ext[_MAX_EXT];

	_splitpath( modulePath, drive, dir, fname, ext ); 

	StringCbPrintf( path, len, "%s%s", drive, dir );

	return;
}

//
// create a string for windows LastError function
//
void GetStrForLastError( string& err ) 
{
	DWORD lastError = ::GetLastError();

	LPVOID lpMsgBuf;

	::FormatMessage( 
		FORMAT_MESSAGE_ALLOCATE_BUFFER | 
		FORMAT_MESSAGE_FROM_SYSTEM | 
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		lastError,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
		(LPTSTR) &lpMsgBuf,
		0,
		NULL);

		err.assign((LPCSTR)lpMsgBuf);

		// Free the buffer.
		LocalFree( lpMsgBuf );
}

//
// map original filepath to hash
//
void WriteFilePathAndHash( const char* format, ... )
{
	#define MAX_STRING 10000 // must be >= 4 (see below)

	HANDLE fileHandle;
	DWORD dwBytesToWrite;
	DWORD dwBytesWritten;

	string collectionDir;
	string collectionDirName;
	string logFile;
	string logFileName;

	CHAR cwd[MAX_PATH];
	memset(cwd, 0x0, MAX_PATH);

	GetCurrentPath(cwd, MAX_PATH);

	// ensure NULL termination
	cwd[MAX_PATH-1] = 0;

	char buffer[MAX_STRING];
	buffer[MAX_STRING-1] = 0;

	va_list arglist;
	va_start( arglist, format );

	try
	{
		HRESULT hr = StringCchVPrintf( buffer, MAX_STRING - 4, format, arglist );
		if( FAILED(hr) ) 
		{
			return;
		}
	}
	catch(...)
	{
		OutputDebugStringA( "WriteFilePathAndHash threw exception while processing a debug message");
		return;
	}

	va_end( arglist );

	// force a NULL in case string was larger than MAX_DEBUG_STRING
	buffer[MAX_STRING - 1] = 0;
	OutputDebugStringA( buffer );

	collectionDirName.assign( "\\SearchAndCollect" );
	collectionDir.assign( cwd );
	collectionDir.append( collectionDirName );

	logFileName = "\\map.txt";
	logFile.append(collectionDir);
	logFile.append(logFileName);

	fileHandle = CreateFile( logFile.c_str(), FILE_APPEND_DATA , FILE_SHARE_WRITE, NULL, 
		OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0 );
                    
    if ( fileHandle == INVALID_HANDLE_VALUE )
    {   
 		DebugMsg( "Couldn't open file with CreateFile()" );
        return; 
	}

	dwBytesToWrite = strlen(buffer);
	if( !WriteFile(fileHandle, buffer, strlen(buffer), &dwBytesWritten, NULL) ) 
	{
		string err;
		GetStrForLastError(err);
		DebugMsg( "Couldn't write to file %s", err.c_str() );
	}

	CloseHandle(fileHandle);
	return;
}

//
// check if file is a valdi PE file
//
BOOL IsValidPEFile( char* fileName )
{
    HANDLE fileHandle;
    HANDLE fileMapping;
    LPVOID fileBase;
    PIMAGE_DOS_HEADER dosHeader;

	int isPEFile = 0;
    
	DebugMsg( "Analyzing file: %s", fileName );

    fileHandle = CreateFile( fileName, GENERIC_READ, FILE_SHARE_READ, NULL,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0 );
                    
    if ( fileHandle == INVALID_HANDLE_VALUE )
    {   
		DebugMsg( "Couldn't open file with CreateFile()" );
		DebugMsg( "PE File Check: NO file: %s", fileName );
        return isPEFile; 
	}
    
    fileMapping = CreateFileMapping( fileHandle, NULL, PAGE_READONLY, 0, 0, NULL );
    if ( fileMapping == 0 )
    {   
		CloseHandle(fileHandle);
        DebugMsg( "Couldn't open file mapping with CreateFileMapping()" );
		DebugMsg( "PE File Check: NO file: %s", fileName );
        return isPEFile; 
	}
    
    fileBase = MapViewOfFile( fileMapping, FILE_MAP_READ, 0, 0, 0 );
    if ( fileBase == 0 )
    {
        CloseHandle( fileMapping );
        CloseHandle( fileHandle );
        DebugMsg( "Couldn't map view of file with MapViewOfFile()" );
		DebugMsg( "PE File Check: NO file: %s", fileName );
        return isPEFile;
    }
    
    dosHeader = (PIMAGE_DOS_HEADER)fileBase;
    if ( dosHeader->e_magic == IMAGE_DOS_SIGNATURE )
	{ 
		isPEFile = 1; 
		DebugMsg( "PE File Check: YES file: %s", fileName );
	}
    else
	{
		isPEFile = 0;
		DebugMsg( "PE File Check: NO file: %s", fileName );
	}

    UnmapViewOfFile( fileBase );
    CloseHandle( fileMapping );
    CloseHandle( fileHandle );

	return isPEFile;
}

//
// calculate SHA265 using openssl functions
// reference: http://www.openssl.org/source/
//
int CreateSHA256Hash( const void* buffer, unsigned long bufferSize, string& hash ) 
{
	SHA256_CTX context;
	unsigned char md[SHA256_DIGEST_LENGTH];

	SHA256_Init( &context );
	SHA256_Update( &context, (unsigned char*)buffer, bufferSize );
	SHA256_Final( md, &context );

	// SHA256 is 256bits = 32bytes = 64chars
	char chHashArray[64+1];
	memset(chHashArray, 0x0, 64+1);
	
	int i, j;
	for(i = 0, j = 0; i < 32; i++, j+=2) 
	{
		int c = ARRAY_SIZE(chHashArray); 
		StringCchPrintf( (chHashArray+j), (ARRAY_SIZE(chHashArray) - strlen(chHashArray)), "%2.2x", md[i] );
	}

	hash.append(string ( (const char*)chHashArray, 64 ) );

	return 0;
 } 

//
// calculate hash of file
//
int GetHashofFile(char* fileName, string& sha1)
{
	HANDLE fileHandle;
    HANDLE fileMapping;
    LPVOID fileBase;
	LPVOID fileBuffer;
	LARGE_INTEGER fileSize;
    
	DebugMsg( "Calculating hash file: %s", fileName );

    fileHandle = CreateFile( fileName, GENERIC_READ, FILE_SHARE_READ, NULL,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0 );
                    
    if ( fileHandle == INVALID_HANDLE_VALUE )
    {   DebugMsg( "Couldn't open file with CreateFile()" );
        return -1; 
	}

    if( !GetFileSizeEx( fileHandle, &fileSize ) )
	{
		CloseHandle(fileHandle);
        DebugMsg( "Couldn't determine file size with GetFileSizeEx()" );
        return -1; 
	}
    
    fileMapping = CreateFileMapping( fileHandle, NULL, PAGE_READONLY, 0, 0, NULL );
    if ( fileMapping == 0 )
    {   CloseHandle(fileHandle);
        DebugMsg( "Couldn't open file mapping with CreateFileMapping()" );
        return -1; 
	}
    
    fileBase = MapViewOfFile( fileMapping, FILE_MAP_READ, 0, 0, 0 );
    if ( fileBase == 0 )
    {
        CloseHandle( fileMapping );
        CloseHandle( fileHandle );
        DebugMsg( "Couldn't map view of file with MapViewOfFile()" );
        return -1;
    }

	if( CreateSHA256Hash( fileBase, fileSize.LowPart, sha1 ) != 0 ) 
	{
		UnmapViewOfFile( fileBase );
		CloseHandle( fileMapping );
		CloseHandle( fileHandle );
		DebugMsg( "Error calculating hash of file" );
		return -1;
	}

	UnmapViewOfFile( fileBase );
    CloseHandle( fileMapping );
    CloseHandle( fileHandle );

	return 0;
}

//
// worker function that iterates through directories to find each file
//
void FindF( std::vector<string> &out, const string &directory )
{
    HANDLE dir;
    WIN32_FIND_DATA fileData;

    if ( (dir = FindFirstFile( (directory + "/*").c_str(), &fileData) ) == INVALID_HANDLE_VALUE )
	{
        return; /* No files found */
	}

    do 
	{
        const string fileName = fileData.cFileName;
        const string fullFileName = directory + "/" + fileName;
        const bool isDirectory = ( fileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY ) != 0;

        if ( fileName[0] == '.' )
                continue;

        if ( !isDirectory )
		{
			if( IsValidPEFile( (LPSTR)fullFileName.c_str() ) )
			{
				out.push_back( fullFileName );
			}
		}
		else 
		{
				FindF( out, fullFileName );
		}

    } while ( FindNextFile( dir, &fileData ) );

    FindClose( dir );

	return;
}

//
// given a list of files copies all files to local working directory
//
int CopyAllFilesToDirInCwd( std::vector<string> out )
{
	string collectionDirName;
	string collectionDir;

	// get currently running path
	CHAR cwd[MAX_PATH];

	DebugMsg( "Copying all files to separate directory" );

	memset(cwd, 0x0, MAX_PATH);

	GetCurrentPath(cwd, MAX_PATH);

	// ensure NULL termination
	cwd[MAX_PATH-1] = 0;

	collectionDirName.assign( "\\SearchAndCollect" );

	collectionDir.assign( cwd );
	collectionDir.append( collectionDirName );

	// check running directory to see if directory named "SearchAndCollect" exists already
	if( (GetFileAttributes( collectionDir.c_str()) ) == INVALID_FILE_ATTRIBUTES ) {
		
		DebugMsg( "%s directory does not exist", collectionDirName.c_str() );

		// if it does NOT create one
		if( !CreateDirectory( collectionDir.c_str(), NULL ) ) 
		{
			string err;
			GetStrForLastError(err);
			printf( "Failed to create directory %s\n", collectionDirName.c_str() );
			printf( "Error: %s\n", err.c_str() );

			DebugMsg( "Failed to create directory %s", collectionDir.c_str() );
			return -1;
		}
		else
		{
			DebugMsg( "Successfully created directory %s", collectionDir.c_str() );
		}
	}
	else
	{
		DebugMsg("Verified directory %s does exist", collectionDir.c_str());
	}

	// assume directory exists...
	printf( "Copying all files to directory %s...\n", collectionDir.c_str() );
	
	// for each file copy the file (if access restrictions allow) to the local folder
	for( std::vector<string>::iterator it = out.begin(); it != out.end(); ++it ) 
	{
		// current filepath
		string filePath = (*it).c_str();

		// copied filename should be unique since there can be overlap in filenames 
		string sha1;
		if( GetHashofFile( (LPSTR)filePath.c_str(), sha1) != 0 ) 
		{
			DebugMsg( "Unable to calculate hash for file: %s", filePath.c_str() );
			continue;
		}

		DebugMsg( "File: %s, SHA256: %s", filePath.c_str(), sha1.c_str() );
		WriteFilePathAndHash( "%s\r\n%s\r\n", filePath.c_str(), sha1.c_str() );

		string newFileName;
		newFileName.assign( collectionDir );
		newFileName.append( "\\" );
		newFileName.append(sha1);

		if( !CopyFile( (*it).c_str(), newFileName.c_str(), FALSE) )
		{
			string err;
			GetStrForLastError(err);

			DebugMsg( "Failed to copy file %s", filePath.c_str() );
			DebugMsg( "Error %s", err.c_str() );

			printf( "Failed to copy file %s\n", filePath.c_str() );
			printf( "Error: %s\n", err.c_str() );

			continue;
		}
		else 
		{
			DebugMsg( "File %s copied to %s", (*it).c_str(), newFileName.c_str() );
		}
	}

	return 0;
}

//
// main 
//
int main( int argc, char* argv[] ) {

	string target;
	vector<string> out;

	char drive[_MAX_DRIVE];
	char dir[_MAX_DIR];
	char fname[_MAX_FNAME];
	char ext[_MAX_EXT];

	_splitpath( argv[0], drive, dir, fname, ext );

	string programName;
	programName.assign( fname );
	programName.append( ext );

	if( argc < 3 ) 
	{
		printf( "Please provide a directory to search\n" );
		printf( "Example usage: %s -d C:\\Windows\n", programName.c_str() );
		printf( "Press any key to exit\n" );
		getchar();
		return -1;
	}

	for( int i=1; i<argc; i++ )
	{
		string param( argv[i] );
		if( (param.compare( "-d" ) == 0) && (target.compare( "" ) == 0) ) 
		{
			if( (i+1) <= argc ) 
			{
				target.assign( argv[i+1] );		
			}
		}
	}
	
	// verify the path exist
	if( !PathFileExistsA( target.c_str() ) )
	{
		printf( "Directory provided: %s does not exist. Please provide a valid directory\n", target.c_str() );
		printf( "Press any key to exit\n" );
		getchar();
		return -1;
	}

	printf( "SearchAndCollect - Search Directory and Copy Files to Centralized Directory\n" );
	printf( "Copyright (C) 2012 IOActive, Inc. All rights reserved.\n" );
	printf( "Written by Stephan Chenette @StephanChenette\n" );
	printf( "Searching %s...\n", target.c_str() );
	
	DebugMsg( "Dir: %s", target.c_str() );

	// get a list of all executable files
	FindF( out, target );
	if( out.size() > 0 ) 
	{
		if( CopyAllFilesToDirInCwd( out ) != 0 ) 
		{
			DebugMsg( "SearchAndCollect was not able to complete the task" );
			printf( "SearchAndCollect was not able to complete the task\n" );
			return -1;
		}
		else
		{
			printf( "Done. Please check directory for copied files\n" );
			return 0;
		}
	}

	return 0;
}