
#include "stdafx.h"
#include "ntfs.h"
#include <windows.h>
#include <stdlib.h>
#include <string>
#include <iostream>
#include <vector>
using namespace std;

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

	for (attr = PATTRIBUTE(Padd(file, file->AttributesOffset));
		attr->AttributeType != -1; attr = Padd(attr, attr->Length))
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
	return attr->Nonresident == FALSE ? PRESIDENT_ATTRIBUTE(attr)->ValueLength : ULONG(PNONRESIDENT_ATTRIBUTE(attr)->DataSize);
}

ULONG AttributeLengthAllocated(PATTRIBUTE attr)
{
	return attr->Nonresident == FALSE ? PRESIDENT_ATTRIBUTE(attr)->ValueLength : ULONG(PNONRESIDENT_ATTRIBUTE(attr)->AllocatedSize);
}

VOID ReadAttribute(PATTRIBUTE attr, string clus, PVOID buffer)
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
	ReadVCN(MFT, AttributeData, vcn, clusters,0,p);
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
	ULONG index = 5;
	PFILE_RECORD_HEADER file = NULL;
	PATTRIBUTE attr90 = NULL;
	for (int i = 1; i < str_vec.size(); i++)
	{
		file = PFILE_RECORD_HEADER(new UCHAR[BytesPerFileRecord]);
		ReadFileRecord(index, file); // 将MFT记录号为index的文件记录读到内存空间file中
		if (file->Ntfs.Type != 'ELIF')
			return;
		attr90 = FindAttribute(file, AttributeIndexRoot, 0); // 在内存空间file中找90属性
		if (attr90 == 0)
			return;
		PUCHAR buffer1 = new UCHAR[AttributeLengthAllocated(attr90)]; // 申请90属性大小的内存空间
		ReadAttribute(attr90, 0, buffer1); // 将内存空间file中的90属性写到buf1中
		if (FindAttribute(file, AttributeIndexAllocation, 0) == 0) // 90属性第一种情况，无A0、B0属性
		{
			index = TraverseIndexEntry(AttributeIndexRoot, buffer1, dir[i]);
			continue;
		}
		else if (第一个索引项偏移4@0x30 == 0 && 2@3C == 1){ // 90属性第二、四种情况，为大索引，有A0、B0属性
			PATTRIBUTE attrA0 = FindAttribute(file, AttributeIndexAllocation, 0); //在内存file中找A0属性 
			PUCHAR buffer2 = new UCHAR[AttributeLengthAllocated(attrA0)]; // 申请A0属性大小的内存空间
			/***** 待补充：在ReadAttribute时，需要读B0属性，过滤掉无效的索引节点 */
			ReadAttribute(attrA0, 0, buffer2); // 将内存空间file中的A0属性写到buf2中，A0是非常驻属性，所以索引节点的数据全被写入buf2
			index = TraverseIndexEntry(AttributeIndexAllocation, buffer2, dir[i]); // 遍历buf2中索引节点的索引项，找到下一个目录的MFT记录号
			continue;
		}
		else if (偏移4@0x30 == 0x10 && 2@3C == 1){ // 90属性第三种情况
			ULONG indexTemp = TraverseIndexEntry(AttributeIndexRoot, buffer1, dir[i]); // 分别遍历90内的索引项和A0指向的索引节点，找目标文件名
			if (indexTemp == 0) 
			{
				PATTRIBUTE attrA0 = FindAttribute(file, AttributeIndexAllocation, 0);//在内存file中找A0属性
				PUCHAR buffer2 = new UCHAR[AttributeLengthAllocated(attrA0)]; // 申请A0属性大小的内存空间
				ReadAttribute(attrA0, 0, buffer2);
				index = TraverseIndexEntry(AttributeIndexAllocation, buffer2, dir[i]);
				continue;
			}
			else {
				index = indexTemp;
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