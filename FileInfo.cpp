
#include "stdafx.h"
#include "ntfs.h"
#include <windows.h>
#include <stdlib.h>
#include <wchar.h>
#include <string>
#include <iostream>
#include <vector>
using namespace std;

// 全局变量
ULONG BytesPerFileRecord; // LoadMFT()
HANDLE hVolume;           // main()
BOOT_BLOCK bootb;         // main().ReadFile()
PFILE_RECORD_HEADER MFT; // LoadMFT()				 
WCHAR drive[] = L"\\\\.\\C:"; // Default primary partition

// Template for padding
template <class T1, class T2> inline T1* Padd(T1* p, T2 n)
{
	return (T1*)((char *)p + n);
}

ULONG RunLength(PUCHAR run)
{
	return (*run & 0xf) + ((*run >> 4) & 0xf) + 1;
}

// 读起始簇号
LONGLONG RunLCN(PUCHAR run)
{
	LONG i = 0;
	UCHAR n1 = 0, n2 = 0;
	LONGLONG lcn = 0;

	// run字节的低4位表示连续多少簇
	n1 = *run & 0xf;
	// run字节的高4位表示起始逻辑簇LCN
	n2 = (*run >> 4) & 0xf;

	lcn = n2 == 0 ? 0 : CHAR(run[n1 + n2]);
	// 字节按 little endian 存放，低字节存放在低位，读起始簇号
	for (i = n1 + n2 - 1; i > n1; i--)
		lcn = (lcn << 8) + run[i];
	// 返回起始簇
	return lcn;
}

// 读簇数
ULONGLONG RunCount(PUCHAR run)
{
	UCHAR n = *run & 0xf;
	ULONGLONG count = 0;
	ULONG i;

	for (i = n; i > 0; i--)
		count = (count << 8) + run[i];

	return count;
}

BOOL FindRun(PNONRESIDENT_ATTRIBUTE attr, ULONGLONG vcn, PULONGLONG lcn, PULONGLONG count)
{
	PUCHAR run = NULL;
	*lcn = 0;
	ULONGLONG base = attr->LowVcn;

	if (vcn < attr->LowVcn || vcn > attr->HighVcn)
		return FALSE;

	for (run = PUCHAR(Padd(attr, attr->RunArrayOffset)); *run != 0; run += RunLength(run))
	{
		// 读起始簇号***************lcn重要***************
		*lcn += RunLCN(run);
		// 读簇数***************count重要***************
		*count = RunCount(run);

		if (base <= vcn && vcn < base + *count)
		{
			*lcn = RunLCN(run) == 0 ? 0 : *lcn + vcn - base;
			*count -= ULONG(vcn - base);
			return TRUE;
		}
		else
			base += *count;
	}
	return FALSE;
}

PATTRIBUTE FindAttribute(PFILE_RECORD_HEADER file, ATTRIBUTE_TYPE type, PWSTR name)
{
	PATTRIBUTE attr = NULL;

	for (attr = PATTRIBUTE(Padd(file, file->AttributesOffset));
		attr->AttributeType != -1; attr = Padd(attr, attr->Length))
	{
		if (attr->AttributeType == type)
		{
			/*if (name == 0 && attr->NameLength == 0)
				return attr;
			if (name != 0 && wcslen(name) == attr->NameLength && _wcsicmp(name, PWSTR(Padd(attr, attr->NameOffset))) == 0)*/
				return attr;
		}
	}
	return 0;
}

VOID FixupUpdateSequenceArray(PFILE_RECORD_HEADER file)
{
	ULONG i = 0;
	PUSHORT usa = PUSHORT(Padd(file, file->Ntfs.UsaOffset));
	PUSHORT sector = PUSHORT(file);

	for (i = 1; i < file->Ntfs.UsaCount; i++)
	{
		sector[255] = usa[i];
		sector += 256;
	}
}

// 读扇区数据到buffer
VOID ReadSector(ULONGLONG sector, ULONG count, PVOID buffer)
{
	ULARGE_INTEGER offset;
	OVERLAPPED overlap = { 0 };
	ULONG n;

	offset.QuadPart = sector * bootb.BytesPerSector;
	overlap.Offset = offset.LowPart;
	overlap.OffsetHigh = offset.HighPart;
	ReadFile(hVolume, buffer, count * bootb.BytesPerSector, &n, &overlap);
}

// 读逻辑簇
VOID ReadLCN(ULONGLONG lcn, ULONG count, PVOID buffer)
{
	ReadSector(lcn * bootb.SectorsPerCluster, count * bootb.SectorsPerCluster, buffer);
}

// 读非常驻属性
VOID ReadExternalAttribute(PNONRESIDENT_ATTRIBUTE attr, ULONGLONG vcn, ULONG count, string &clus, PVOID buffer)
{
	ULONGLONG lcn, runcount;
	ULONG readcount, left;
	PUCHAR bytes = PUCHAR(buffer);

	for (left = count; left > 0; left -= readcount)
	{
		FindRun(attr, vcn, &lcn, &runcount);
		readcount = ULONG(min(runcount, left));
		// readcount * 簇字节
		ULONG n = readcount * bootb.BytesPerSector * bootb.SectorsPerCluster;

		if (lcn == 0)
			memset(bytes, 0, n);
		else
		{
			printf("起始簇:%lld    簇数:%ld\n", lcn, readcount);
			clus.append(to_string(lcn));  // ULONGLONG 转换为 string
			clus.append(",");
			clus.append(to_string(readcount));
			clus.append(",");
			// 读连续readcount个簇的数据到内存空间bytes
			ReadLCN(lcn, readcount, bytes);
		}
		vcn += readcount;
		bytes += n;
	}
}

ULONG AttributeLength(PATTRIBUTE attr)
{
	return attr->Nonresident == FALSE ? PRESIDENT_ATTRIBUTE(attr)->ValueLength : ULONG(PNONRESIDENT_ATTRIBUTE(attr)->DataSize);
}

ULONG AttributeLengthAllocated(PATTRIBUTE attr)
{
	return attr->Nonresident == FALSE ? PRESIDENT_ATTRIBUTE(attr)->ValueLength : ULONG(PNONRESIDENT_ATTRIBUTE(attr)->AllocatedSize);
}

VOID ReadAttribute(PATTRIBUTE attr, string &clus, PVOID buffer)
{
	PRESIDENT_ATTRIBUTE rattr = NULL;
	PNONRESIDENT_ATTRIBUTE nattr = NULL;

	if (attr->Nonresident == FALSE) // 常驻属性
	{
		rattr = PRESIDENT_ATTRIBUTE(attr);
		memcpy(buffer, Padd(rattr, rattr->ValueOffset), rattr->ValueLength); // 忽略属性头，只读属性体
	}
	else // 非常驻属性
	{
		nattr = PNONRESIDENT_ATTRIBUTE(attr);
		// 起始vcn = 0, count = ULONG(nattr->HighVcn) + 1（总的虚拟簇数）
		ReadExternalAttribute(nattr, 0, ULONG(nattr->HighVcn) + 1, clus, buffer);
	}
}

// 读虚拟簇
VOID ReadVCN(PFILE_RECORD_HEADER file, ATTRIBUTE_TYPE type, ULONGLONG vcn, ULONG count, string clus, PVOID buffer)
{
	PATTRIBUTE attrlist = NULL;
	PNONRESIDENT_ATTRIBUTE attr = PNONRESIDENT_ATTRIBUTE(FindAttribute(file, type, 0));

	if (attr == 0 || (vcn < attr->LowVcn || vcn > attr->HighVcn))
	{
		// Support for huge files
		attrlist = FindAttribute(file, AttributeAttributeList, 0);
		DebugBreak();
	}
	ReadExternalAttribute(attr, vcn, count, clus, buffer);
}

// 将MFT记录号为index的文件记录读到内存空间file中
VOID ReadFileRecord(ULONG index, PFILE_RECORD_HEADER file)
{
	// 每条文件记录有多少个簇
	ULONG clusters = bootb.ClustersPerFileRecord;

	if (clusters > 0x80)
		clusters = 1;
	// 申请内存空间为clusters个簇（一条文件记录的簇或1个簇）大小的字节数
	PUCHAR p = new UCHAR[bootb.BytesPerSector* bootb.SectorsPerCluster * clusters];
	// MFT 记录号为 index 的记录，在MFT中的起始VCN
	ULONGLONG vcn = ULONGLONG(index) * BytesPerFileRecord / bootb.BytesPerSector / bootb.SectorsPerCluster;
	// 将起始VCN为vcn，连续clusters个簇读到内存空间p中（将index文件记录读到p中）
	ReadVCN(MFT, AttributeData, vcn, clusters,"",p);
	// m = 每个簇可以包含的文件记录数 - 1
	LONG m = (bootb.SectorsPerCluster * bootb.BytesPerSector / BytesPerFileRecord) - 1;
	// 在MFT中，记录号为index的文件记录在该簇中偏移的文件记录数
	ULONG n = m > 0 ? (index & m) : 0;
	// 将p（一个簇）中的偏移n个文件记录的那条文件记录数据复制到file中，大小为一个文件记录的大小
	memcpy(file, p + n * BytesPerFileRecord, BytesPerFileRecord);
	delete[] p;
	FixupUpdateSequenceArray(file);
}

VOID LoadMFT()
{
	wprintf(L"In LoadMFT() - Loading MFT...\n");

	BytesPerFileRecord = bootb.ClustersPerFileRecord < 0x80
		? bootb.ClustersPerFileRecord* bootb.SectorsPerCluster
		* bootb.BytesPerSector : 1 << (0x100 - bootb.ClustersPerFileRecord);

	// 分配内存空间，并将空间解释为 PFILE_RECORD_HEADER 类型
	MFT = PFILE_RECORD_HEADER(new UCHAR[BytesPerFileRecord]);
	// 读 $MFT 
	ReadSector((bootb.MftStartLcn)*(bootb.SectorsPerCluster), (BytesPerFileRecord) / (bootb.BytesPerSector), MFT);
	FixupUpdateSequenceArray(MFT);
}

BOOL bitset(PUCHAR bitmap, ULONG i)
{
	return (bitmap[i >> 3] & (1 << (i & 7))) != 0;
}

VOID Initiate(WCHAR *disk)
{
	ULONG n;
	// Read the user input
	drive[4] = *disk;
	// Get the handle to the primary partition/volume/physical disk
	hVolume = CreateFile(
		drive,
		GENERIC_READ,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		0,
		OPEN_EXISTING,
		0,
		0);

	if (hVolume == INVALID_HANDLE_VALUE)
	{
		wprintf(L"CreateFile() failed, error %u\n", GetLastError());
		exit(1);
	}

	// Reads data from the specified input/output (I/O) device - volume/physical disk
	// 读boot sector的数据，填充数据结构BOOT_BLOCK的实例bootb？
	if (ReadFile(hVolume, &bootb, sizeof bootb, &n, 0) == 0)
	{
		wprintf(L"ReadFile() failed, error %u\n", GetLastError());
		exit(1);
	}

	LoadMFT();
}

/*WCHAR* CharToWchar(UCHAR* c)
{
	//char* to wchar_t*
	size_t size = strlen(c) + 1;
	wchar_t* w_arr_name = new wchar_t[size];
	mbstowcs(w_arr_name, c, size);
	return m_wchar;
}*/

WCHAR* StringToWchar(const string& str)
{
	WCHAR* m_wchar = NULL;
	LPCSTR p = str.c_str();
	int len = MultiByteToWideChar(CP_ACP, 0, p, strlen(p), NULL, 0);
	m_wchar = new WCHAR[len + 1];
	MultiByteToWideChar(CP_ACP, 0, p, strlen(p), m_wchar, len);
	m_wchar[len] = '\0';
	return m_wchar;
}

// 找到目标索引项后，读MFT记录号，4 个字节表示？
ULONG ReadIndex(PUCHAR entry)
{
	ULONG index = 0;

	for (int i = 3; i >= 0; i--)
		index = (index << 8) + entry[i];

	return index;
}

// 根据目录名或文件名，遍历索引项，返回目录或文件的MFT记录号
ULONG TraverseIndexEntry(ATTRIBUTE_TYPE type, PVOID buf, WCHAR *dir)
{
	ULONG index = 0;
	if (type == AttributeIndexRoot) // 遍历90属性内的索引项，buf中是90属性从第一个索引项开始的属性体，直接遍历索引项
	{ 
		PINDEX_ROOT indexRoot = PINDEX_ROOT(buf);;
		PDIRECTORY_ENTRY entry = PDIRECTORY_ENTRY(Padd(indexRoot, 0x20));  // entry指向了第一个索引项
		USHORT indexEntryLen = entry->Length;                   // 第一个索引项长度
		while (indexEntryLen != 0x18 && indexEntryLen != 0x10)  // 若索引项长度为0x18或0x10，结束遍历该簇
		{
			PFILENAME_ATTRIBUTE indexEntryFileName = PFILENAME_ATTRIBUTE(Padd(entry, 0x10));  // indexEntryFileName指向索引项中的FILENAME_ATTRIBUTE
			WCHAR *fileName = new WCHAR[indexEntryFileName->NameLength + 1];     // 第一个索引项的文件名
			UCHAR nameLen = indexEntryFileName->NameLength;
			wmemcpy(fileName, PCWSTR(Padd(indexEntryFileName, 0x42)), nameLen); // 读索引项中的文件名
			fileName[indexEntryFileName->NameLength] = '\0';
			if (wcscmp(fileName, dir) == 0) // 相等
			{
				index = ReadIndex(PUCHAR(entry));
				return index;
			}
			else {
				entry = PDIRECTORY_ENTRY(Padd(entry, indexEntryLen));  // 指向下一个索引项
				indexEntryLen = entry->Length;                             // 下一个索引项大小
			}
		}
	}
	else if (type == AttributeIndexAllocation) { 
	/* 遍历A0属性指向的索引节点中的索引项，buf中是一个个以INDX开始的索引节点（簇） ，先按索引节点遍历；
	再在节点内部遍历索引项，当遍历到索引项大小为0x10或0x18时表示该节点的索引项已遍历完，接着遍历下一个节点（簇）*/
		PINDEX_BLOCK_HEADER indexBlock = PINDEX_BLOCK_HEADER(buf);
		while (indexBlock->Ntfs.Type == 'XDNI')
		{
			ULONG firstEntryOffset = indexBlock->DirectoryIndex.EntriesOffset;  // 第一条索引项（DIRECTORY_ENTRY）在该结构内部的字节偏移量
			PDIRECTORY_ENTRY entry = PDIRECTORY_ENTRY(Padd(indexBlock, 0x18 + firstEntryOffset));  // entry指向了第一个索引项
			USHORT indexEntryLen = entry->Length;                   // 第一个索引项长度
			while (indexEntryLen != 0x18 || indexEntryLen != 0x10)  // 若索引项长度为0x18或0x10，结束遍历该簇
			{
				PFILENAME_ATTRIBUTE indexEntryFileName = PFILENAME_ATTRIBUTE(Padd(entry, 0x10));  // indexEntryFileName指向索引项中的FILENAME_ATTRIBUTE
				WCHAR *fileName = new WCHAR[indexEntryFileName->NameLength + 1];     // 第一个索引项的文件名
				UCHAR nameLen = indexEntryFileName->NameLength;
				PCWSTR source = PCWSTR(Padd(indexEntryFileName, 0x42));
				wmemcpy(fileName, source, nameLen); // 读索引项中的文件名
				fileName[indexEntryFileName->NameLength] = '\0';
				if (wcscmp(fileName, dir) == 0) // 相等
				{
					index = ReadIndex(PUCHAR(entry));
					delete[]fileName;
					return index;
				}
				else {
					entry = PDIRECTORY_ENTRY(Padd(entry, indexEntryLen));  // 指向下一个索引项
					indexEntryLen = entry->Length;                             // 下一个索引项大小
				}
				delete[]fileName;
			}
			indexBlock = Padd(indexBlock, bootb.SectorsPerCluster * bootb.BytesPerSector);  // 指向下一个索引节点
		}
	}
}

ULONG FindMFTRecNum(string filepath)
{
	// string -> const char* -> char*
	LPSTR cpath = new CHAR[filepath.length() + 1];
	strcpy_s(cpath, strlen(cpath), filepath.c_str());

	// 分解路径，目录和文件名保存在WCHAR **dir中
	vector<string> str_vec;
	CHAR seps[] = "\\";
	PCHAR next_token = NULL;
	PCHAR token = NULL;
	token = strtok_s(cpath, seps, &next_token);
	while ((token != NULL))
	{
		str_vec.push_back(token);
		token = strtok_s(NULL, seps, &next_token);
	}
	WCHAR **dir = new WCHAR *[str_vec.size()];
	for (unsigned int i = 0; i < str_vec.size(); i++)
	{
		dir[i] = StringToWchar(str_vec[i]);
		//wprintf(L"%x\n", dir[i]);
	}

	// LoadMFT
	Initiate(dir[0]);

	// 遍历目录名和文件名
	ULONG index = 5;
	PFILE_RECORD_HEADER file = NULL;
	PATTRIBUTE attr90 = NULL;
	for (unsigned int i = 1; i < str_vec.size(); i++)
	{
		file = PFILE_RECORD_HEADER(new UCHAR[BytesPerFileRecord]);
		ReadFileRecord(index, file); // 将MFT记录号为index的文件记录读到内存空间file中
		if (file->Ntfs.Type != 'ELIF')
			return 0;
		PWSTR name = _wcsdup(L"$I30");
		attr90 = FindAttribute(file, AttributeIndexRoot, name); // 在内存空间file中找90属性
		if (attr90 == 0)
			return 0;
		PUCHAR buffer1 = new UCHAR[AttributeLengthAllocated(attr90)]; // 申请90属性大小的内存空间
		string clus = "";
		ReadAttribute(attr90, clus, buffer1); // 将内存空间file中的90属性写到buf1中

		PRESIDENT_ATTRIBUTE rattr90 = PRESIDENT_ATTRIBUTE(attr90);  // 90属性为常驻属性

		if (FindAttribute(file, AttributeIndexAllocation, 0) == 0) // 90属性第一种情况，无A0、B0属性   
		{
			index = TraverseIndexEntry(AttributeIndexRoot, buffer1, dir[i]);
			delete[]buffer1;
			continue;
		}
		else if (rattr90->ValueLength == 0x38){ // 90属性第二、四种情况，为大索引，有A0、B0属性
			PATTRIBUTE attrA0 = FindAttribute(file, AttributeIndexAllocation, 0); //在内存file中找A0属性 
			PUCHAR buffer2 = new UCHAR[AttributeLengthAllocated(attrA0)]; // 申请A0属性大小的内存空间
			/***** 待补充：在ReadAttribute时，需要读B0属性，过滤掉无效的索引节点 */
			ReadAttribute(attrA0, clus, buffer2); // 将内存空间file中的A0属性写到buf2中，A0是非常驻属性，所以索引节点的数据全被写入buf2
			index = TraverseIndexEntry(AttributeIndexAllocation, buffer2, dir[i]); // 遍历buf2中索引节点的索引项，找到下一个目录的MFT记录号
			delete[]buffer2;
			continue;
		}
		else if (rattr90->ValueLength > 0x38){ // 90属性第三种情况
			ULONG indexTemp = TraverseIndexEntry(AttributeIndexRoot, buffer1, dir[i]); // 分别遍历90内的索引项和A0指向的索引节点，找目标文件名
			if (indexTemp == 0) 
			{
				PATTRIBUTE attrA0 = FindAttribute(file, AttributeIndexAllocation, 0);//在内存file中找A0属性
				PUCHAR buffer2 = new UCHAR[AttributeLengthAllocated(attrA0)]; // 申请A0属性大小的内存空间
				ReadAttribute(attrA0, clus, buffer2);
				index = TraverseIndexEntry(AttributeIndexAllocation, buffer2, dir[i]);
				delete[]buffer2;
				continue;
			}
			else {
				index = indexTemp;
				continue;
			}
		}
	}

	// delete **dir
	for (unsigned int i = 0; i<str_vec.size(); i++)
	{
		delete[] dir[i];
	}
	delete dir;

	//delete[] cpath;  // 释放内存出错

	return index;
}

// 主要功能函数1，输入路径、簇字符串、内存buf、buf的大小
UCHAR* DumpClusNum(string path, string &clus, ULONG *attributeLengthAllocated)
{
	ULONG index = FindMFTRecNum(path);
	PATTRIBUTE attr = NULL;
	PFILE_RECORD_HEADER file = PFILE_RECORD_HEADER(new UCHAR[BytesPerFileRecord]);
	ReadFileRecord(index, file);// 将记录号为index的文件记录读到内存空间file中
	if (file->Ntfs.Type != 'ELIF')
		return NULL;
	attr = FindAttribute(file, AttributeData, 0); // 在内存空间file中找80属性
	if (attr == 0)
		return NULL;
	*attributeLengthAllocated = AttributeLengthAllocated(attr);
	UCHAR *buf = new UCHAR[*attributeLengthAllocated];
	wprintf(L"dump clus and data starts...\n");
	ReadAttribute(attr, clus, buf); // 将内存空间file中的80属性写到buf中,同时将簇号写到clus
	return buf;
}

// 主要功能函数2，输入逻辑簇号、簇数、内存buf
VOID DumpData(WCHAR *disk, ULONGLONG lcn, ULONG readcount, PVOID buffer)
{

	// LoadMFT
	Initiate(disk);
	wprintf(L"dump data starts...\n");
	ReadLCN(lcn, readcount, buffer);  // 读簇，存入buffer
}

int wmain(int argc, WCHAR **argv)
{
	// 测试：根据MFT记录号获取文件的簇和数据
	string path = "F:\\JavaWeb\\new.txt";
	PVOID bufFileData = NULL; //定义为全局变量?
	string clus = "";
	ULONG n;
	ULONG *fileLengthAllocated = new ULONG;
	bufFileData = DumpClusNum(path,clus, fileLengthAllocated);
	//wprintf(L"%.*s\n", clus);

	// 创建文件filename
	LPCWSTR filename = L"f:\\new.txt";
	HANDLE hFile = CreateFile(filename, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, 0, 0);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		wprintf(L"CreateFile() failed, error %u\n", GetLastError());
		return 0;
	}
	// 将bufFileData（文件的80属性）写到filename文件中
	if (WriteFile(hFile, bufFileData, *fileLengthAllocated, &n, 0) == 0)
	{
		wprintf(L"WriteFile() failed, error %u\n", GetLastError());
		return 0;
	}

	CloseHandle(hFile);
	delete[] bufFileData;

	// 测试：输入起始簇和簇数，输出簇内容


	getchar();
	return 0;
}