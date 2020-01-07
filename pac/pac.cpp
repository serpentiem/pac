constexpr bool debug = true;

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

#define PrintFunction() printf("%s\n", __FUNCTION__)

char directory[256] = {};

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

byte8 * LoadFile(const char * fileName, uint32 * size, byte8 * dest = 0)
{
	byte8 * addr = dest;
	HANDLE file = 0;
	BY_HANDLE_FILE_INFORMATION fi = {};
	uint32 bytesRead = 0;
	OVERLAPPED overlap = {};
	byte32 error = 0;

	SetLastError(0);
	file = CreateFileA(fileName, GENERIC_READ, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	error = GetLastError();
	if (file == INVALID_HANDLE_VALUE)
	{
		printf("CreateFile failed. %X\n", error);
		return 0;
	}

	GetFileInformationByHandle(file, &fi);
	if (fi.nFileSizeLow == 0)
	{
		printf("File exists, but is empty.\n");
		return 0;
	}

	if (!addr)
	{
		addr = Alloc(fi.nFileSizeLow);
		if (!addr)
		{
			printf("Alloc failed.\n");
			return 0;
		}
	}

	ReadFile(file, addr, fi.nFileSizeLow, &bytesRead, &overlap);
	CloseHandle(file);

	if (size)
	{
		*size = fi.nFileSizeLow;
	}

	return addr;
}

bool SaveFile(const char * fileName, byte8 * addr, uint32 size)
{
	HANDLE file = 0;
	uint32 bytesWritten = 0;
	OVERLAPPED overlap = {};
	byte32 error = 0;

	SetLastError(0);
	file = CreateFileA(fileName, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	error = GetLastError();
	if (file == INVALID_HANDLE_VALUE)
	{
		printf("CreateFile failed. %X\n", error);
		return false;
	}

	WriteFile(file, addr, size, &bytesWritten, &overlap);
	CloseHandle(file);

	return true;
}

bool CreateEmptyFile(const char * fileName)
{
	HANDLE file = 0;
	byte32 error = 0;

	SetLastError(0);
	file = CreateFileA(fileName, GENERIC_WRITE, 0, 0, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, 0);
	error = GetLastError();
	if (file == INVALID_HANDLE_VALUE)
	{
		printf("CreateFile failed. %X\n", error);
		return false;
	}

	CloseHandle(file);

	return true;
}

bool ChangeDirectory(const char * dest)
{
	bool result = false;
	byte32 error = 0;

	SetLastError(0);
	result = (bool)SetCurrentDirectoryA(dest);
	error = GetLastError();
	if (!result)
	{
		printf("SetCurrentDirectory failed. %X\n", error);
		return false;
	}

	if constexpr (debug)
	{
		printf("Changed directory from %s to ", directory);
	}
	GetCurrentDirectoryA(sizeof(directory), directory);
	if constexpr (debug)
	{
		printf("%s.\n", directory);
	}

	return true;
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

#pragma endregion

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

		SaveFile(dest, file, fileSize);
	}
}

byte8 * CreateArchive(uint32 * saveSize = 0)
{
	PrintFunction();

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
		if (strcmp(fd.cFileName, ".") == 0)
		{
			continue;
		}
		if (strcmp(fd.cFileName, "..") == 0)
		{
			continue;
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
				ChangeDirectory("..");
				continue;
			}

			fileOff[fileCount] = dataPos;

			if constexpr (debug)
			{
				printf("directory fileOff[%u] = %X\n", fileCount, dataPos);
			}

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

		fileOff[fileCount] = 0xFFFFFFFF;

		if (file)
		{
			fileOff[fileCount] = dataPos;

			if constexpr (debug)
			{
				printf("fileOff[%u] = %X\n", fileCount, dataPos);
			}

			memcpy((data + dataPos), file, fileSize);
			dataPos += fileSize;
			Align<uint32>(dataPos, 0x10);

			VirtualFree(file, 0, MEM_RELEASE);
		}

		fileCount++;
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

void PrintHelp()
{
	printf("Extract\n");
	printf("\n");
	printf("  pac e archive\n");
	printf("\n");
	printf("Repack\n");
	printf("\n");
	printf("  pac r directory archive\n");
	printf("\n");
	printf("Examples\n");
	printf("\n");
	printf("  pac e plwp_newvergilsword.pac\n");
	printf("  pac r plwp_sword2 new_plwp_sword2.pac");
	printf("\n");
}

int main(int argc, char ** argv)
{
	GetCurrentDirectoryA(sizeof(directory), directory);

	if (argc < 2)
	{
		PrintHelp();
		return 0;
	}

	if (strcmp(argv[1], "e") == 0)
	{
		if (argc < 3)
		{
			PrintHelp();
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

		CheckArchive(file, fileSize, directoryName);
	}
	else if (strcmp(argv[1], "r") == 0)
	{
		if (argc < 4)
		{
			PrintHelp();
			return 0;
		}

		char * directoryName = argv[2];
		byte8 * archive = 0;
		uint32 archiveSize = 0;
		char * fileName = argv[3];
		bool result = false;

		if (!ChangeDirectory(directoryName))
		{
			printf("ChangeDirectory failed.\n");
			return 0;
		}

		archive = CreateArchive(&archiveSize);
		if (!archive)
		{
			printf("CreateArchive failed.\n");
			ChangeDirectory("..");
			return 0;
		}

		if constexpr (debug)
		{
			printf("archive     %llX\n", archive);
			printf("archiveSize %u\n", archiveSize);
		}

		ChangeDirectory("..");

		result = SaveFile(fileName, archive, archiveSize);
		if (!result)
		{
			printf("SaveFile failed.\n");
			return 0;
		}
	}
	else
	{
		PrintHelp();
		return 0;
	}

	return 1;
}
