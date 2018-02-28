#include "stdafx.h"
#include <windows.h>
#include <winnls.h>
#include <stdlib.h>
#include "ntfs.h"
#include <iostream>
#include <string>
#include <vector>


// 全局变量
ULONG BytesPerFileRecord; // LoadMFT()
HANDLE hVolume;           // main()
BOOT_BLOCK bootb;         // main().ReadFile()
PFILE_RECORD_HEADER MFT; // LoadMFT()

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

	for (attr = PATTRIBUTE(Padd(file, file->AttributeOffset));
		attr->AttributeType != -1; attr = Padd(attr, attr->AttributeLength))
	{
		if (attr->AttributeType == type)
		{
			if (name == 0 && attr->NameLength == 0)
				return attr;
			if (name != 0 && wcslen(name) == attr->NameLength && _wcsicmp(name,
				PWSTR(Padd(attr, attr->NameOffset))) == 0)
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
VOID ReadExternalAttribute(PNONRESIDENT_ATTRIBUTE attr, ULONGLONG vcn, ULONG count, string clus, PVOID buffer)
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
			clus.append(to_string(readcount));
			// 读连续readcount个簇的数据到内存空间bytes
			ReadLCN(lcn, readcount, bytes);
		}
		vcn += readcount;
		bytes += n;
	}
}

ULONG AttributeLength(PATTRIBUTE attr)
{
	return attr->Nonresident == FALSE ? PRESIDENT_ATTRIBUTE(attr)->ContentLength : ULONG(PNONRESIDENT_ATTRIBUTE(attr)->StreamRealSize);
}

ULONG AttributeLengthAllocated(PATTRIBUTE attr)
{
	return attr->Nonresident == FALSE ? PRESIDENT_ATTRIBUTE(attr)->ContentLength : ULONG(PNONRESIDENT_ATTRIBUTE(attr)->StreamAllocSize);
}

VOID ReadAttribute(PATTRIBUTE attr, string clus, PVOID buffer)
{
	PRESIDENT_ATTRIBUTE rattr = NULL;
	PNONRESIDENT_ATTRIBUTE nattr = NULL;

	if (attr->Nonresident == FALSE) // 常驻属性
	{
		rattr = PRESIDENT_ATTRIBUTE(attr);
		memcpy(buffer, Padd(rattr, rattr->ContentOffset), rattr->ContentLength); // 忽略属性头，只读属性体
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
	ReadVCN(MFT, AttributeData, vcn, clusters, 0, p);
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
	// Default primary partition
	WCHAR drive[] = L"\\\\.\\C:";
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

VOID DumpClusNum(ULONG index, string clus, PVOID buf)
{
	PATTRIBUTE attr = NULL;
	PFILE_RECORD_HEADER file = PFILE_RECORD_HEADER(new UCHAR[BytesPerFileRecord]);
	ReadFileRecord(index, file);// 将记录号为index的文件记录读到内存空间file中
	if (file->Ntfs.Type != 'ELIF')
		return;
	attr = FindAttribute(file, AttributeData, 0); // 在内存空间file中找80属性
	if (attr == 0)
		return;
	ReadAttribute(attr, clus, buf); // 将内存空间file中的80属性写到buf中,同时将簇号写到clus
}

VOID DumpData(ULONGLONG lcn, ULONG readcount, PVOID buffer)
{
	ReadLCN(lcn, readcount, buffer);  // 读簇，存入buffer
}

WCHAR* CharToWchar(WCHAR* m_wchar, LPCSTR c)
{
	int len = MultiByteToWideChar(CP_ACP, 0, c, strlen(c), NULL, 0);
	m_wchar = new WCHAR[len + 1];
	MultiByteToWideChar(CP_ACP, 0, c, strlen(c), m_wchar, len);
	m_wchar[len] = '\0';
	return m_wchar;
}

WCHAR* StringToWchar(const string& str)
{
	WCHAR* m_wchar = NULL;
	LPCSTR p = str.c_str();
	return CharToWchar(m_wchar, p);
}

// 根据目录名或文件名，遍历索引项，返回目录或文件的MFT记录号
ULONG TraverseIndexEntry(ATTRIBUTE_TYPE type, PUCHAR buf, WCHAR *dir)
{
	if (type == AttributeIndexRoot) // 遍历90属性内的索引项，buf中是90属性从第一个索引项开始的属性体，直接遍历索引项
	{

	}
	else if (type == AttributeIndexAllocation) {
		/* 遍历A0属性指向的索引节点中的索引项，buf中是一个个以INDX开始的索引节点（簇） ，先按索引节点遍历；
		再在节点内部遍历索引项，当遍历到索引项大小为0x10或0x18时表示该节点的索引项已遍历完，接着遍历下一个节点（簇）*/

	}
}

VOID FindMFTRecNum(string filepath)
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
	for (int i = 0; i < str_vec.size(); i++)
	{
		dir[i] = StringToWchar(str_vec[i]);
		wprintf(L"%x\n", dir[i]);
	}

	// LoadMFT
	Initiate(dir[0]);

	// 遍历目录名和文件名
	ULONG MFTIndex = 5;
	PFILE_RECORD_HEADER file = NULL;
	PATTRIBUTE attr90 = NULL;
	for (int i = 1; i < str_vec.size(); i++)
	{
		file = PFILE_RECORD_HEADER(new UCHAR[BytesPerFileRecord]);
		ReadFileRecord(MFTIndex, file); // 将MFT记录号为index的文件记录读到内存空间file中
		if (file->Ntfs.Type != 'ELIF')
			return;
		attr90 = FindAttribute(file, AttributeIndexRoot, 0); // 在内存空间file中找90属性
		if (attr90 == 0)
			return;
		PUCHAR buffer1 = new UCHAR[AttributeLengthAllocated(attr90)]; // 申请90属性大小的内存空间
		ReadAttribute(attr90, 0, buffer1); // 将内存空间file中的90属性写到buf1中
		if (FindAttribute(file, AttributeIndexAllocation, 0) == 0) // 90属性第一种情况，无A0、B0属性
		{
			MFTIndex = TraverseIndexEntry(AttributeIndexRoot, buffer1, dir[i]);
			continue;
		}
		else if (第一个索引项偏移4@0x30 == 0 && 2@3C == 1) { // 90属性第二、四种情况，为大索引，有A0、B0属性
			PATTRIBUTE attrA0 = FindAttribute(file, AttributeIndexAllocation, 0); //在内存file中找A0属性 
			PUCHAR buffer2 = new UCHAR[AttributeLengthAllocated(attrA0)]; // 申请A0属性大小的内存空间
																		  /***** 待补充：在ReadAttribute时，需要读B0属性，过滤掉无效的索引节点 */
			ReadAttribute(attrA0, 0, buffer2); // 将内存空间file中的A0属性写到buf2中，A0是非常驻属性，所以索引节点的数据全被写入buf2
			MFTIndex = TraverseIndexEntry(AttributeIndexAllocation, buffer2, dir[i]); // 遍历buf2中索引节点的索引项，找到下一个目录的MFT记录号
			continue;
		}
		else if (偏移4@0x30 == 0x10 && 2@3C == 1) { // 90属性第三种情况
			ULONG indexTemp = TraverseIndexEntry(AttributeIndexRoot, buffer1, dir[i]); // 分别遍历90内的索引项和A0指向的索引节点，找目标文件名
			if (indexTemp == 0)
			{
				PATTRIBUTE attrA0 = FindAttribute(file, AttributeIndexAllocation, 0);//在内存file中找A0属性
				PUCHAR buffer2 = new UCHAR[AttributeLengthAllocated(attrA0)]; // 申请A0属性大小的内存空间
				ReadAttribute(attrA0, 0, buffer2);
				MFTIndex = TraverseIndexEntry(AttributeIndexAllocation, buffer2, dir[i]);
				continue;
			}
			else {
				MFTIndex = indexTemp;
				continue;
			}
		}
	}

	// delete **dir
	for (int i = 0; i<str_vec.size(); i++)
	{
		delete[] dir[i];
	}
	delete dir;
	delete[] cpath;
}









































































#define DEBUG

using namespace std;

ULONG BytesPerFileRecord; // 每个MFT entry的大小，通常为1K
HANDLE hVolume;           // 文件句柄
BOOT_BLOCK bootb;
PFILE_RECORD_HEADER MFT; // 存储MFT的内容
						 // Template for padding
template <class T1, class T2> inline T1* Padd(T1* p, T2 n)
{
	return (T1*)((char *)p + n);
}

ULONG RunLength(PUCHAR run)
{
	
	wprintf(L"In RunLength()...\n");
	return (*run & 0xf) + ((*run >> 4) & 0xf) + 1;
}

// 读起始簇号
LONGLONG RunLCN(PUCHAR run)
{
	LONG i = 0;
	UCHAR n1 = 0, n2 = 0;
	LONGLONG lcn = 0;

	wprintf(L"In RunLCN()...\n");
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

	wprintf(L"In RunCount()...\n");

	for (i = n; i > 0; i--)
		count = (count << 8) + run[i];

	return count;
}

BOOL FindRun(PNONRESIDENT_ATTRIBUTE attr, ULONGLONG vcn, PULONGLONG lcn, PULONGLONG count)
{
	PUCHAR run = NULL;
	*lcn = 0;
	ULONGLONG base = attr->LowVcn;

	wprintf(L"In FindRun()...\n");

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

	wprintf(L"FindAttribute() - Finding attributes...\n");

	for (attr = PATTRIBUTE(Padd(file,file->AttributeOffset));
		attr->AttributeType != -1; attr = Padd(attr,attr->AttributeLength))
	{
		if (attr->AttributeType == type)
		{
			if (name == 0 && attr->NameLength == 0)
				return attr;
			if (name != 0 && wcslen(name) == attr->NameLength && _wcsicmp(name,
				PWSTR(Padd(attr, attr->NameOffset))) == 0)
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

	wprintf(L"In FixupUpdateSequenceArray()...\n");
	for (i = 1; i < file->Ntfs.UsaCount; i++)
	{
		sector[255] = usa[i];
		sector += 256;
	}
}

VOID ReadSector(ULONGLONG sector, ULONG count, PVOID buffer)
{
	ULARGE_INTEGER offset;
	OVERLAPPED overlap = { 0 };
	ULONG n;

	wprintf(L"ReadSector() - Reading the sector...\n");
	wprintf(L"Sector: %lu\n", sector);

	offset.QuadPart = sector * bootb.BytesPerSector;
	overlap.Offset = offset.LowPart;
	overlap.OffsetHigh = offset.HighPart;
	ReadFile(hVolume, buffer, count * bootb.BytesPerSector, &n, &overlap);
}

// 读逻辑簇
VOID ReadLCN(ULONGLONG lcn, ULONG count, PVOID buffer)
{
	wprintf(L"\nReadLCN() - Reading the LCN, LCN: 0X%.8X\n", lcn);
	ReadSector(lcn * bootb.SectorsPerCluster, count * bootb.SectorsPerCluster, buffer);
}

// Non resident attributes
VOID ReadExternalAttribute(PNONRESIDENT_ATTRIBUTE attr, ULONGLONG vcn, ULONG count, PVOID buffer)
{
	ULONGLONG lcn, runcount;
	ULONG readcount, left;
	PUCHAR bytes = PUCHAR(buffer);

	wprintf(L"ReadExternalAttribute() - Reading the Non resident attributes...\n");

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
			// 读连续readcount个簇的数据到内存空间bytes
			ReadLCN(lcn, readcount, bytes);
			wprintf(L"LCN: 0X%.8X\n", lcn);
		}
		vcn += readcount;
		bytes += n;
	}
}

ULONG AttributeLength(PATTRIBUTE attr)
{
	wprintf(L"In AttributeLength()...\n");
	return attr->Nonresident == FALSE ? PRESIDENT_ATTRIBUTE(attr)->ContentLength : ULONG(PNONRESIDENT_ATTRIBUTE(attr)->StreamRealSize);
}

ULONG AttributeLengthAllocated(PATTRIBUTE attr)
{
	wprintf(L"\nIn AttributeLengthAllocated()...\n");
	return attr->Nonresident == FALSE ? PRESIDENT_ATTRIBUTE(attr)->ContentLength : ULONG(PNONRESIDENT_ATTRIBUTE(attr)->StreamAllocSize);
}

VOID ReadAttribute(PATTRIBUTE attr, PVOID buffer)
{
	PRESIDENT_ATTRIBUTE rattr = NULL;
	PNONRESIDENT_ATTRIBUTE nattr = NULL;

	wprintf(L"ReadAttribute() - Reading the attributes...\n");

	if (attr->Nonresident == FALSE) // 常驻属性
	{
		wprintf(L"Resident attribute...\n");
		rattr = PRESIDENT_ATTRIBUTE(attr);
		memcpy(buffer, Padd(rattr, rattr->ContentOffset), rattr->ContentLength);
	}
	else // 非常驻属性
	{
		wprintf(L"Non-resident attribute...\n");
		nattr = PNONRESIDENT_ATTRIBUTE(attr);
		// 起始vcn = 0, count = ULONG(nattr->HighVcn) + 1, ULONG(nattr->HighVcn) + 1 表示总的虚拟簇数
		ReadExternalAttribute(nattr, 0, ULONG(nattr->HighVcn) + 1, buffer);
	}
}

// 读虚拟簇
VOID ReadVCN(PFILE_RECORD_HEADER file, ATTRIBUTE_TYPE type, ULONGLONG vcn, ULONG count, PVOID buffer)
{
	PATTRIBUTE attrlist = NULL;
	PNONRESIDENT_ATTRIBUTE attr = PNONRESIDENT_ATTRIBUTE(FindAttribute(file, type, 0));

	wprintf(L"In ReadVCN()...\n");
	if (attr == 0 || (vcn < attr->LowVcn || vcn > attr->HighVcn))
	{
		// Support for huge files
		attrlist = FindAttribute(file, AttributeAttributeList, 0);
		DebugBreak();
	}
	ReadExternalAttribute(attr, vcn, count, buffer);
}

// 将MFT记录号为index的文件记录读到内存空间file中
VOID ReadFileRecord(ULONG index, PFILE_RECORD_HEADER file)
{
	// 每条文件记录有多少个簇
	ULONG clusters = bootb.ClustersPerFileRecord;
	wprintf(L"ReadFileRecord() - Reading the file records..\n");

	if (clusters > 0x80)
		clusters = 1;
	// 申请内存空间为clusters个簇（一条文件记录的簇或1个簇）大小的字节数
	PUCHAR p = new UCHAR[bootb.BytesPerSector* bootb.SectorsPerCluster * clusters];
	// MFT 记录号为 index 的记录，在MFT中的起始VCN
	ULONGLONG vcn = ULONGLONG(index) * BytesPerFileRecord / bootb.BytesPerSector / bootb.SectorsPerCluster;
	// 将起始VCN为vcn，连续clusters个簇读到内存空间p中（将index文件记录读到p中）？？？
	ReadVCN(MFT, AttributeData, vcn, clusters, p);
	// m = 每个簇可以包含的文件记录数 - 1
	LONG m = (bootb.SectorsPerCluster * bootb.BytesPerSector / BytesPerFileRecord) - 1;
	// 在MFT中记录号为index的文件记录在该簇中偏移的文件记录数
	ULONG n = m > 0 ? (index & m) : 0;
	// 将p（一个簇）中的偏移n个文件记录的那条文件记录数据复制到file中，大小为一个文件记录的大小
	memcpy(file, p + n * BytesPerFileRecord, BytesPerFileRecord);
	delete[] p;
	FixupUpdateSequenceArray(file);
}

VOID LoadMFT()
{
	BytesPerFileRecord = bootb.ClustersPerFileRecord < 0x80
		? bootb.ClustersPerFileRecord* bootb.SectorsPerCluster
		* bootb.BytesPerSector : 1 << (0x100 - bootb.ClustersPerFileRecord);

#ifdef DEBUG
	wprintf(L"In LoadMFT() - Loading MFT...\n");
	wprintf(L"\nBytes Per File Record = %u\n\n", BytesPerFileRecord);
	wprintf(L"bootb.BootSectors = %u\n", bootb.BootSectors);
	wprintf(L"bootb.BootSignature = %u\n", bootb.BootSignature);
	wprintf(L"bootb.BytesPerSector = %u\n", bootb.BytesPerSector);
	wprintf(L"bootb.ClustersPerFileRecord = %u\n", bootb.ClustersPerFileRecord);
	wprintf(L"bootb.ClustersPerIndexBlock = %u\n", bootb.ClustersPerIndexBlock);
	wprintf(L"bootb.Code = %u\n", bootb.Code);
	wprintf(L"bootb.Format = %u\n", bootb.Format);
	wprintf(L"bootb.Jump = %u\n", bootb.Jump);
	wprintf(L"bootb.Mbz1 = %u\n", bootb.Mbz1);
	wprintf(L"bootb.Mbz2 = %u\n", bootb.Mbz2);
	wprintf(L"bootb.Mbz3 = %u\n", bootb.Mbz3);
	wprintf(L"bootb.MediaType = 0X%X\n", bootb.MediaType);
	wprintf(L"bootb.Mft2StartLcn = 0X%.8X\n", bootb.Mft2StartLcn);
	wprintf(L"bootb.MftStartLcn = 0X%.8X\n", bootb.MftStartLcn);
	wprintf(L"bootb.NumberOfHeads = %u\n", bootb.NumberOfHeads);
	wprintf(L"bootb.PartitionOffset = %lu\n", bootb.PartitionOffset);
	wprintf(L"bootb.SectorsPerCluster = %u\n", bootb.SectorsPerCluster);
	wprintf(L"bootb.SectorsPerTrack = %u\n", bootb.SectorsPerTrack);
	wprintf(L"bootb.TotalSectors = %lu\n", bootb.TotalSectors);
	wprintf(L"bootb.VolumeSerialNumber = 0X%.8X%.8X\n\n", bootb.VolumeSerialNumber.HighPart, bootb.VolumeSerialNumber.HighPart);
#endif // DEBUG

	MFT = PFILE_RECORD_HEADER(new UCHAR[BytesPerFileRecord]);
	ReadSector((bootb.MftStartLcn)*(bootb.SectorsPerCluster), (BytesPerFileRecord) / (bootb.BytesPerSector), MFT);
	FixupUpdateSequenceArray(MFT);
	Sleep(1000000);
}

BOOL bitset(PUCHAR bitmap, ULONG i)
{
	return (bitmap[i >> 3] & (1 << (i & 7))) != 0;
}

VOID FindDeleted()
{
	// 找MFT中第一个bitmap属性，即文件$MFT的$bitmap属性，显示哪个文件记录在用
	PATTRIBUTE attr = FindAttribute(MFT, AttributeBitmap, 0);
	PUCHAR bitmap = new UCHAR[AttributeLengthAllocated(attr)];
	// 将bitmap属性读到内存空间bitmap中
	ReadAttribute(attr, bitmap);
	// $MFT文件的$data属性就是MFT，n表示MFT有多少条文件记录
	ULONG n = AttributeLength(FindAttribute(MFT, AttributeData, 0)) / BytesPerFileRecord;

	wprintf(L"FindDeleted() - Finding the deleted files...\n");

	PFILE_RECORD_HEADER file = PFILE_RECORD_HEADER(new UCHAR[BytesPerFileRecord]);

	// 遍历MFT的文件记录，找到没在使用的文件记录
	for (ULONG i = 0; i < n; i++)
	{
		// 如果第i条文件记录正在使用，则继续查找下一条
		if (bitset(bitmap, i))
			continue;

		ReadFileRecord(i, file);

		// 如果文件记录以“FILE”开头，并且文件记录的Flags = 0，表示文件记录空闲，从未被使用？？？
		if (file->Ntfs.Type == 'ELIF' && (file->Flags & 1) == 0)
		{
			attr = FindAttribute(file, AttributeFileName, 0);
			if (attr == 0)
				continue;

			PFILENAME_ATTRIBUTE name = PFILENAME_ATTRIBUTE(Padd(attr, PRESIDENT_ATTRIBUTE(attr)->ContentOffset));

			// * means the width/precision was supplied in the argument list
			// ws ~ wide character string
			wprintf(L"\n%10u %u %.*s\n\n", i, int(name->NameLength), int(name->NameLength), name->Name);
			// To see the very long output short, uncomment the following line
			// _getwch();
		}
	}
}

VOID DumpData(ULONG index, WCHAR* filename)
{
	PATTRIBUTE attr = NULL;
	HANDLE hFile = NULL;
	PFILE_RECORD_HEADER file = PFILE_RECORD_HEADER(new UCHAR[BytesPerFileRecord]);
	ULONG n;

	// 将MFT记录号为index的文件记录读到内存空间file中
	ReadFileRecord(index, file);

	wprintf(L"Dumping the data...\n");

	if (file->Ntfs.Type != 'ELIF')
		return;

	// 在内存空间file中找80属性
	attr = FindAttribute(file, AttributeData, 0);
	if (attr == 0)
		return;
	// 申请80属性大小的内存空间
	PUCHAR buf = new UCHAR[AttributeLengthAllocated(attr)];
	// 将内存空间file中的80属性写到buf中
	ReadAttribute(attr, buf);

	// 创建文件filename
	hFile = CreateFile((LPCWSTR)filename, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, 0, 0);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		wprintf(L"CreateFile() failed, error %u\n", GetLastError());
		return;
	}
	// 将buf（80属性）写到filename文件中
	if (WriteFile(hFile, buf, AttributeLength(attr), &n, 0) == 0)
	{
		wprintf(L"WriteFile() failed, error %u\n", GetLastError());
		return;
	}
	CloseHandle(hFile);
	delete[] buf;
}

// utf8-unicode
bool Utf8ToUnicode(std::string &utf8_string, std::wstring &unicode_string)
{
	unicode_string = L"";

	if (utf8_string.compare("") == 0)
		return false;//原始字符串为空返回失败

	const char *temp_utf8_string = utf8_string.c_str();//将string类转换成C的char风格。
	int unicode_string_len = ::MultiByteToWideChar(CP_ACP,NULL,temp_utf8_string,strlen(temp_utf8_string),NULL,0);

	if (0 == unicode_string_len)
		return false;

	wchar_t *temp_unicode_string =  new wchar_t[unicode_string_len + 1];
	memset(temp_unicode_string, 0, sizeof(wchar_t) * (unicode_string_len + 1));

	if (0 == ::MultiByteToWideChar(CP_ACP, NULL, temp_utf8_string, strlen(temp_utf8_string), temp_unicode_string, unicode_string_len))
	{
		delete[] temp_unicode_string;
		temp_unicode_string = NULL;
		return false;
	}

	unicode_string = temp_unicode_string;
	delete[] temp_unicode_string;
	temp_unicode_string = NULL;
	return true;
}

/*分解字符串*/

//支持单个分隔符
void SplitString(const string& s, vector<string>& v, const string& c)
{
	string::size_type pos1, pos2;
	pos2 = s.find(c);
	pos1 = 0;
	while (string::npos != pos2)
	{
		v.push_back(s.substr(pos1, pos2 - pos1));

		pos1 = pos2 + c.size();
		pos2 = s.find(c, pos1);
	}
	if (pos1 != s.length())
		v.push_back(s.substr(pos1));
}

//支持多个分隔符
vector<string> split(const string &s, const string &seperator) {
	vector<string> result;
	typedef string::size_type string_size;
	string_size i = 0;

	while (i != s.size()) {
		//找到字符串中首个不等于分隔符的字母；
		int flag = 0;
		while (i != s.size() && flag == 0) {
			flag = 1;
			for (string_size x = 0; x < seperator.size(); ++x)
				if (s[i] == seperator[x]) {
					++i;
					flag = 0;
					break;
				}
		}

		//找到又一个分隔符，将两个分隔符之间的字符串取出；
		flag = 0;
		string_size j = i;
		while (j != s.size() && flag == 0) {
			for (string_size x = 0; x < seperator.size(); ++x)
				if (s[j] == seperator[x]) {
					flag = 1;
					break;
				}
			if (flag == 0)
				++j;
		}
		if (i != j) {
			result.push_back(s.substr(i, j - i));
			i = j;
		}
	}
	return result;
}

int main(int argc, char *argv[])
{
	string s = "C:\\git\\myDocumenty\\lora.pptx";
	vector<string> v = split(s, ":\\");

	vector<wstring> wstr(v.size());
	for (vector<string>::size_type i = 0; i != v.size(); ++i)
	{
//		cout << v[i] << "\t";
		Utf8ToUnicode(v[i], wstr[i]);
	}
//	cout << endl;
//	printf("%X,\t%X,\t%X,\n", wstr[0][0],wstr[1][0],wstr[1][1]);

	WCHAR driver[] = L"\\\\.\\C:";
	ULONG n;

	driver[4] = s[0];
	hVolume = CreateFile(driver, GENERIC_READ,
		FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);

	if (hVolume == INVALID_HANDLE_VALUE){
		wprintf(L"CreateFile() failed, error %u\n", GetLastError());
		exit(1);
	}

	// Reads data from the specified input/output (I/O) device - volume/physical disk
	if (ReadFile(hVolume, &bootb, sizeof bootb, &n, NULL) == FALSE){
		wprintf(L"ReadFile() failed, error %u\n", GetLastError());
		exit(1);
	}
	LoadMFT();

	// The primary partition supplied else
	// default C:\ will be used
	
	//if (argc == 2) FindDeleted();
	
	// Need to convert the recovered filename to long file name
	// Not implemented here. It is 8.3 file name format


	// The primary partition, index and file name to be recovered
	// are supplied
//strtoul(）函数用来将一个空终结符的字符串转化成unsigned long的形式

	CloseHandle(hVolume);
	return 0;
}





























#if 0
#include "stdafx.h"
#include <Windows.h>
#include <winioctl.h>

bool ReadDisk(unsigned char *&out, DWORD start, DWORD size);
int main()
{

	ZwFsControlFile();

	HANDLE handle = CreateFile(L"F:\\work\\cp210x.c",
		GENERIC_READ,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		NULL,
		NULL);
	if (handle == INVALID_HANDLE_VALUE)
	{
		printf("INVALID_HANDLE_VALUE\n");
		return 0;
	}
	BY_HANDLE_FILE_INFORMATION FileInformation;

	if (GetFileInformationByHandle(handle, &FileInformation) == 0) 
	{
		printf("get file infomation ERROR!");
		return false;
	}
	printf("file serial number %u!\n", FileInformation.dwVolumeSerialNumber);
	printf("file attributes %u!\n", FileInformation.dwFileAttributes);
	//若文件较小，只需获取nFileSizeLow，若文件很大，还需获取nFileSizeHigh
	printf("filesize %u!\n", FileInformation.nFileSizeLow);

	unsigned char *a;
	bool status = ReadDisk(a, 0, 512);

	if (status) {
		for (int i = 0; i<512; i++)
		{
			printf("%02X", a[i]);
		}
	}
	else {
		printf("status is false\n");
	}

	getchar();
    return 0;
}

bool ReadDisk(unsigned char *&out, DWORD start, DWORD size)
{
	OVERLAPPED over = { 0 };
	over.Offset = start;

//编译之后要用管理员权限运行程序才能够读磁盘
	HANDLE handle = CreateFile(TEXT("\\\\.\\PHYSICALDRIVE0"),
		GENERIC_READ,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		NULL,
		NULL);
	if (handle == INVALID_HANDLE_VALUE)
	{
		printf("INVALID_HANDLE_VALUE\n");
		return false;
	}
	BY_HANDLE_FILE_INFORMATION FileInformation;


	

//	GetLogicalDriveStrings();
	
//	SetFilePointer(handle, );

	unsigned char *buffer = new unsigned char[size + 1];
	DWORD readsize;
	if (ReadFile(handle, buffer, size, &readsize, &over) == 0)
	{
		printf("ReadFile\n");
		CloseHandle(handle);
		return false;
	}
	buffer[size] = 0;
	out = buffer;
	return true;
}
#endif