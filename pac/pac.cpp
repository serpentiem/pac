#pragma region Global

#include <stdio.h>
#include <Windows.h>

typedef unsigned char      uint8;
typedef unsigned short     uint16;
typedef unsigned long      uint32;
typedef unsigned long long uint64;

typedef unsigned char      byte8;
typedef unsigned short     byte16;
typedef unsigned long      byte32;
typedef unsigned long long byte64;

template <typename T>
constexpr uint32 countof(T & var)
{
	return static_cast<uint32>(sizeof(var) / sizeof(var[0]));
}

#pragma warning(disable: 4102)
#pragma warning(disable: 4477)

byte8 * LoadFile(const char * fileName, uint32 * size, byte8 * dest = 0)
{
	//printf("%s\n", __FUNCTION__);

	//printf
	//(
	//	"%s %s %llX %llX\n",
	//	__FUNCTION__,
	//	fileName,
	//	size,
	//	dest
	//);



	byte8 * addr = dest;
	byte32 error = 0;
	SetLastError(0);
	HANDLE file = CreateFileA(fileName, GENERIC_READ, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	error = GetLastError();
	if (file == INVALID_HANDLE_VALUE)
	{
		printf("CreateFile failed. %s error %X\n", fileName, error);
		return 0;
	}
	BY_HANDLE_FILE_INFORMATION fi = {};
	GetFileInformationByHandle(file, &fi);

	if (fi.nFileSizeLow == 0)
	{

		printf("File exists, but is empty.\n");

		return 0;
	}






	SetLastError(0);
	if (!addr)
	{
		// @Todo: Create custom allocator.
		addr = (byte8 *)VirtualAlloc(0, fi.nFileSizeLow, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		error = GetLastError();
		if (!addr)
		{
			printf("VirtualAlloc failed. error %X\n", error);
			return 0;
		}
	}
	uint32 bytesRead = 0;
	OVERLAPPED overlap = {};
	ReadFile(file, addr, fi.nFileSizeLow, &bytesRead, &overlap);
	CloseHandle(file);
	if (size)
	{
		*size = fi.nFileSizeLow;
	}
	return addr;
}

// @Todo: Put fileName first.

bool SaveFile(byte8 * addr, uint32 size, const char * fileName)
{
	//printf("%s\n", __FUNCTION__);


	//printf
	//(
	//	"%s %llX %u %s\n",
	//	__FUNCTION__,
	//	addr,
	//	size,
	//	fileName
	//);


	





	byte32 error = 0;
	SetLastError(0);
	HANDLE file = CreateFileA(fileName, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	error = GetLastError();
	if (file == INVALID_HANDLE_VALUE)
	{
		printf("CreateFile failed. %s error %X\n", fileName, error);
		return false;
	}
	uint32 bytesWritten = 0;
	OVERLAPPED overlap = {};
	WriteFile(file, addr, size, &bytesWritten, &overlap);
	CloseHandle(file);
	return true;
}

#pragma endregion

constexpr bool debug = true;

char directory[256] = {};


// @Todo: Make boolean.

void ChangeDirectory(const char * dest)
{
	if constexpr (debug)
	{
		printf("Changing directory from %s to ", directory);
	}
	SetCurrentDirectoryA(dest);
	GetCurrentDirectoryA(sizeof(directory), directory);
	if constexpr (debug)
	{
		printf("%s.\n", directory);
	}
}

void List()
{
	WIN32_FIND_DATAA fd;
	HANDLE find;
	find = FindFirstFileA("*", &fd);
	do
	{
		LoopStart:
		{
			if (strcmp(fd.cFileName, ".") == 0)
			{
				goto LoopEnd;
			}
			if (strcmp(fd.cFileName, "..") == 0)
			{
				goto LoopEnd;
			}
			printf("%s\n", fd.cFileName);
			if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			{
				ChangeDirectory(fd.cFileName);
				List();
				ChangeDirectory("..");
			}
		}
		LoopEnd:;
	}
	while (FindNextFileA(find, &fd));
}



bool CreateEmptyFile(const char * fileName)
{

	HANDLE file = CreateFileA(fileName, GENERIC_WRITE, 0, 0, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, 0);


	if (file == INVALID_HANDLE_VALUE)
	{
		return false;
	}

	CloseHandle(file);

	return true;




}








byte8 * Alloc(uint32 size)
{
	byte8 * addr = 0;
	byte32 error = 0;

	SetLastError(0);
	addr = (byte8 *)VirtualAlloc(0, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	error = GetLastError();
	if (!addr)
	{
		printf("VirtualAlloc failed. %X\n", error);
		return 0;
	}

	return addr;
}


template <typename T>
void Align(T & pos, T boundary, byte8 * addr = 0, byte8 pad = 0)
{
	T remainder = (pos % boundary);
	if (remainder)
	{
		T size = (boundary - remainder);
		if (addr)
		{
			memset((addr + pos), pad, size);
		}
		pos += size;
	}
}













bool SignatureMatch(byte8 * addr, byte8 * signature, uint8 count)
{
	for (uint8 index = 0; index < count; index++)
	{
		if (addr[index] != signature[index])
		{
			return false;
		}
	}
	return true;
}

byte8 signature1[] = { 'P', 'A', 'C' };
byte8 signature2[] = { 'P', 'N', 'S','T' };

byte8 * signature[] =
{
	signature1,
	signature2,
};

uint8 signatureCount[] =
{
	(uint8)countof(signature1),
	(uint8)countof(signature2),
};

const char * signatureString[] =
{
	"PAC",
	"PNST",
};

const char * CheckSignature(byte8 * addr)
{
	for (uint8 index = 0; index < (uint8)countof(signature); index++)
	{
		if (SignatureMatch(addr, signature[index], signatureCount[index]))
		{
			return signatureString[index];
		}
	}
	return 0;
}








// CheckArchive
// ExtractFiles






bool CheckArchive
(
	byte8 * archive,
	uint32 archiveSize,
	const char * directoryName
);

void ExtractFiles
(
	byte8 * archive,
	uint32 archiveSize
);


















bool CheckArchive
(
	byte8 * archive,
	uint32 archiveSize,
	const char * directoryName
)
{
	const char * match = CheckSignature(archive);
	if (!match)
	{
		return false;
	}


	CreateDirectoryA(directoryName, 0);
	ChangeDirectory(directoryName);


	if (!CreateEmptyFile(match))
	{
		printf("CreateEmptyFile failed.\n");
		ChangeDirectory("..");
		return false;
	}

	ExtractFiles(archive, archiveSize);

	ChangeDirectory("..");

	return true;
}








void ExtractFiles
(
	byte8 * archive,
	uint32 archiveSize
)
{
	auto & fileCount = *(uint32 *)(archive + 4);

	for (uint32 fileIndex = 0; fileIndex < fileCount; fileIndex++)
	{
		char dest[64];

		uint32   fileOff = 0;
		uint32   nextFileOff = 0;
		byte8  * file = 0;
		uint32   fileSize = 0;

		snprintf(dest, sizeof(dest), "%.4u", fileIndex);

		fileOff = ((uint32 *)(archive + 8))[fileIndex];
		if (!fileOff)
		{
			CreateEmptyFile(dest);
			continue;
		}

		{
			uint32 index = fileIndex;
			do
			{
				if (index == (fileCount - 1))
				{
					nextFileOff = archiveSize;
					break;
				}
				nextFileOff = ((uint32 *)(archive + 8))[(index + 1)];
				if (nextFileOff)
				{
					break;
				}
				else
				{
					index++;
					continue;
				}
			}
			while (index < fileCount);
		}

		file = (archive + fileOff);

		fileSize = (nextFileOff - fileOff);

		if constexpr (debug)
		{
			printf("file     %llX\n", file);
			printf("fileOff  %X\n", fileOff);
			printf("fileSize %u\n", fileSize);
		}

		if (CheckArchive(file, fileSize, dest))
		{
			continue;
		}

		SaveFile(file, fileSize, dest);
	}
}

















































void Extract
(
	byte8 * archive,
	uint32 archiveSize,
	const char * directory,
	const char * signature = 0
)
{
	if (!signature)
	{
		printf("No signature passed.\n");
		signature = CheckSignature(archive);
		if (!signature)
		{
			printf("CheckSignature failed.\n");
			return;
		}
	}

	CreateDirectoryA(directory, 0);
	ChangeDirectory(directory);

	if (!CreateEmptyFile(signature))
	{
		printf("CreateEmptyFile failed.\n");
		ChangeDirectory("..");
		return;
	}







	auto & fileCount = *(uint32 *)(archive + 4);

	for (uint32 fileIndex = 0; fileIndex < fileCount; fileIndex++)
	{
		char dest[64];

		uint32   fileOff = 0;
		uint32   nextFileOff = 0;
		byte8  * file = 0;
		uint32   fileSize = 0;

		snprintf(dest, sizeof(dest), "%.4u", fileIndex);

		fileOff = ((uint32 *)(archive + 8))[fileIndex];
		if (!fileOff)
		{
			CreateEmptyFile(dest);
			continue;
		}

		{
			uint32 index = fileIndex;
			do
			{
				if (index == (fileCount - 1))
				{
					nextFileOff = archiveSize;
					break;
				}
				nextFileOff = ((uint32 *)(archive + 8))[(index + 1)];
				if (nextFileOff)
				{
					break;
				}
				else
				{
					index++;
					continue;
				}
			}
			while (index < fileCount);
		}

		file = (archive + fileOff);

		fileSize = (nextFileOff - fileOff);

		if constexpr (debug)
		{
			printf("file     %llX\n", file);
			printf("fileOff  %X\n", fileOff);
			printf("fileSize %u\n", fileSize);
		}

		const char * match = CheckSignature(file);
		if (match)
		{
			printf("match %s\n", match);


			Extract(file, fileSize, dest);
			continue;
		}

		SaveFile(file, fileSize, dest);
	}



	


	ChangeDirectory("..");
}







byte8 * CreateArchive(uint32 * saveSize = 0)
{

	
	printf("%s\n", __FUNCTION__);




	byte32 error = 0;

	byte8 * head = 0;
	uint32 headPos = 0;

	byte8 * data = 0;
	uint32 dataPos = 0;

	head = Alloc(4096);
	if (!head)
	{
		printf("Alloc failed.\n");
		return 0;
	}

	data = Alloc((8 * 1024 * 1024));

	if (!data)
	{
		printf("Alloc failed.\n");
		return 0;
	}

	auto & fileCount = *(uint32 *)(head + 4);
	auto   fileOff   =  (uint32 *)(head + 8);

	












	WIN32_FIND_DATAA fd;
	HANDLE find;
	find = FindFirstFileA("*", &fd);
	if (find == INVALID_HANDLE_VALUE)
	{
		return 0;
	}





	do
	{

		// @Todo: Replace with continue.

		LoopStart:
		{
			if (strcmp(fd.cFileName, ".") == 0)
			{
				goto LoopEnd;
			}
			if (strcmp(fd.cFileName, "..") == 0)
			{
				goto LoopEnd;
			}



			if (strcmp(fd.cFileName, "PAC") == 0)
			{
				head[0] = 'P';
				head[1] = 'A';
				head[2] = 'C';
				continue;
			}

			if (strcmp(fd.cFileName, "PNST") == 0)
			{
				head[0] = 'P';
				head[1] = 'N';
				head[2] = 'S';
				head[3] = 'T';
				continue;
			}






			if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) // @Todo: Add empty check.
			{
				ChangeDirectory(fd.cFileName);

				byte8 * archive = 0;
				uint32 archiveSize = 0;

				archive = CreateArchive(&archiveSize);
				if (!archive)
				{
					printf("CreateArchive failed.\n");

					// @Todo: Make prettier.

					ChangeDirectory("..");
					continue;
				}

				fileOff[fileCount] = dataPos;
				printf("directory fileOff[%u] = %X\n", fileCount, dataPos);


				fileCount++;

				memcpy((data + dataPos), archive, archiveSize);
				dataPos += archiveSize;
				Align<uint32>(dataPos, 0x10);

				VirtualFree(archive, 0, MEM_RELEASE);



				ChangeDirectory("..");
				continue;
			}

			byte8 * file = 0;
			uint32 fileSize = 0;

			file = LoadFile(fd.cFileName, &fileSize);
			//if (!file)
			//{
			//	printf("LoadFile failed.\n");
			//	continue;
			//}


			// @Todo: More continue!


			fileOff[fileCount] = 0xFFFFFFFF;

			if (file)
			{


				fileOff[fileCount] = dataPos;
				printf("fileOff[%u] = %X\n", fileCount, dataPos);

				

				memcpy((data + dataPos), file, fileSize);
				dataPos += fileSize;
				Align<uint32>(dataPos, 0x10);






				VirtualFree(file, 0, MEM_RELEASE);


			}

			fileCount++;


		}
		LoopEnd:;
	}
	while (FindNextFileA(find, &fd));

	// All files compiled.

	byte8 * archive = 0;
	uint32 archivePos = 0;

	archive = Alloc((8 * 1024 * 1024));
	if (!archive)
	{
		printf("Alloc failed.\n");
		return 0;
	}


	// @Todo: Ye, ye, ye.
	headPos = (8 + (fileCount * 4));

	Align<uint32>(headPos, 0x10);



	for (uint32 index = 0; index < fileCount; index++)
	{

		
		auto & off = fileOff[index];

		if (off == 0xFFFFFFFF)
		{
			off = 0;

			continue;
		}



		off += headPos;
	}



	//head[0] = 'P';
	//head[1] = 'A';
	//head[2] = 'C';


	memcpy(archive, head, headPos);
	archivePos += headPos;
	Align<uint32>(archivePos, 0x10);


	memcpy((archive + archivePos), data, dataPos);
	archivePos += dataPos;
	Align<uint32>(archivePos, 0x10);



	VirtualFree(head, 0, MEM_RELEASE); // @Research: Why is size 0 correct again?
	VirtualFree(data, 0, MEM_RELEASE);

	if (saveSize)
	{
		*saveSize = archivePos;
	}

	return archive;
}

















int main(int argc, char ** argv)
{





	//for (uint32 index = 4; index < 4; index++)
	//{
	//	printf("index %u\n", index);
	//}

	//return 1;











	GetCurrentDirectoryA(sizeof(directory), directory);

	if (argc == 1)
	{
		printf("help\n");
		return 0;
	}



	if (strcmp(argv[1], "r") == 0)
	{
		if (argc < 3)
		{
			return 0;
		}





		const char * dest = argv[2];

		ChangeDirectory(dest);


		
		
		byte8 * archive = 0;
		uint32 archiveSize = 0;

		archive = CreateArchive(&archiveSize);



		printf("archive     %llX\n", archive);
		printf("archiveSize %u\n", archiveSize);





		ChangeDirectory("..");
		


		
		char fileName[128];

		snprintf(fileName, sizeof(fileName), "new_%s.pac", argv[2]);

		auto result = SaveFile(archive, archiveSize, fileName);

		printf("result %u\n", result);






	}





	if (strcmp(argv[1], "e") == 0)
	{
		if (argc < 3)
		{
			return 0;
		}

		char   * fileName          = argv[2];
		byte8  * file              = 0;
		uint32   fileSize          = 0;
		char     directoryName[64] = {};

		file = LoadFile(fileName, &fileSize);
		if (!file)
		{
			printf("LoadFile failed.\n");
			return 0;
		}

		memcpy(directoryName, fileName, (strlen(fileName) - 4)); // @Todo: A bit too optimistic. Add length check.


		//Extract(file, fileSize, directoryName);

		CheckArchive(file, fileSize, directoryName);


		//CreateDirectoryA(directoryName, 0);
		//ChangeDirectory(directoryName);

		//if (SignatureMatch
		//(
		//	file,
		//	signaturePac,
		//	(uint8)countof(signaturePac)
		//))
		//{
		//	if (!CreateEmptyFile("PAC"))
		//	{
		//		printf("CreateEmptyFile failed.\n");
		//	}
		//}
		//else if (SignatureMatch
		//(
		//	file,
		//	signaturePnst,
		//	(uint8)countof(signaturePnst)
		//))
		//{
		//	if (!CreateEmptyFile("PNST"))
		//	{
		//		printf("CreateEmptyFile failed.\n");
		//	}
		//}

		//Extract(file, fileSize);

		//ChangeDirectory("..");

		return 1;
	}







	//system("pause");



	return 1;
}
