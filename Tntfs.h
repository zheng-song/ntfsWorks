#pragma once

///ntfs.h

/* NTFS RECORD HEADER */
typedef struct {             // 16B
	ULONG Type;              // NTFS记录的类型，FILE/BAAD/INDX/CHKD/HOLE
	USHORT UsaOffset;        // Update Sequence Array 在该结构中的偏移量
	USHORT UsaCount;         // usa 中值的个数
	USN Usn;                 // The Update Sequence Number of the NTFS record
} NTFS_RECORD_HEADER, *PNTFS_RECORD_HEADER;

/* FILE RECORD_HEADER */
typedef struct {                   // 42B
	NTFS_RECORD_HEADER Ntfs;       // when Type = FILE
	USHORT SequenceNumber;         // MFT entry 被重用次数 
	USHORT LinkCount;              // The number of directory links to the MFT entry
	USHORT AttributesOffset;       // 第一个属性在此 MFT entry 中的偏移
	USHORT Flags;                  // 0x0001 = The MFT entry is InUse, 0x0002 = The MFT entry represents a Directory
	ULONG BytesInUse;              // 已被该 MFT entry 使用的字节数
	ULONG BytesAllocated;          // 分配给该 MFT entry 的字节数
	ULONGLONG BaseFileRecord; /*If the MFT entry contains attributes that overflowed a base MFT entry,
							  this member contains the file reference number of the base entry; otherwise , it contains zero.*/
	USHORT NextAttributeNumber;    // The number that will be assigned to the next attribute added to the MFT entry
} FILE_RECORD_HEADER, *PFILE_RECORD_HEADER;

/* 属性类型 */
typedef enum {
	AttributeStandardInformation = 0x10, // always resident
	AttributeAttributeList = 0x20,       //always nonresident
	AttributeFileName = 0x30,            // always resident

	/*一个文件或目录的64字节标识符，其中低16字节对于该卷来说是唯一的；
	NTFS提供了相应的API，因为文件和目录可以通过其对象ID，而不是通过其文件名打开*/ 
	AttributeObjectId = 0x40,            // always resident

	AttributeSecurityDescriptor = 0x50,

	/*保存了该卷的版本和label信息*/
	AttributeVolumeName = 0x60,
	AttributeVolumeInformation = 0x70,

	AttributeData = 0x80,

	/*用于实现大目录的文件名分配和位图索引*/
	AttributeIndexRoot = 0x90,
	AttributeIndexAllocation = 0xA0,
	AttributeBitmap = 0xB0,

	AttributeReparsePoint = 0xC0,

	/*以下两个为扩展属性，现已不再被主动使用，之所以提供是为与OS/2程序保持向后兼容*/
	AttributeEAInformation = 0xD0,
	AttributeEA = 0xE0,

	AttributePropertySet = 0xF0,
	AttributeLoggedUtilityStream = 0x100
} ATTRIBUTE_TYPE, *PATTRIBUTE_TYPE;

/* 属性 */
typedef struct {
	ATTRIBUTE_TYPE AttributeType;
	ULONG Length;           // 该属性常驻部分的字节大小
	BOOLEAN Nonresident;    // true = 非常驻属性
	UCHAR NameLength;       // 如果有属性名，属性名的字符大小
	USHORT NameOffset;      // 属性名的内部偏移，字节，属性名为Unicode
	USHORT Flags;           // 0x0001 = 属性被压缩
	USHORT AttributeNumber; // 该属性实例的数字标识符
} ATTRIBUTE, *PATTRIBUTE;

/* 常驻属性 */
typedef struct {
	ATTRIBUTE Attribute;
	ULONG ValueLength;      // 属性值的字节大小
	USHORT ValueOffset;     // 属性值的内部偏移，字节
	USHORT Flags;           // 0x0001 = The attribute is Indexed
} RESIDENT_ATTRIBUTE, *PRESIDENT_ATTRIBUTE;

/* 非常驻属性 */
typedef struct {
	ATTRIBUTE Attribute;
	ULONGLONG LowVcn;
	ULONGLONG HighVcn;
	USHORT RunArrayOffset;            // run array 的内部偏移量，run array 存储 VCN 与 LCN 之间的对应关系
	UCHAR CompressionUnit;            // 若该成员为0，该属性未被压缩
	UCHAR AlignmentOrReserved[5];
	ULONGLONG AllocatedSize;          // 分配了多少磁盘空间用于容纳该属性值，字节
	ULONGLONG DataSize;               // 属性值的字节大小，若属性值被压缩或很稀疏，可能会比 AllocatedSize 大
	ULONGLONG InitializedSize;        // 属性值的初始字节大小
	ULONGLONG CompressedSize;         // 属性值被压缩后的字节大小，只有当属性被压缩时，才有该成员
} NONRESIDENT_ATTRIBUTE, *PNONRESIDENT_ATTRIBUTE;

/* 文件标准信息属性 */
typedef struct {
	ULONGLONG CreationTime;
	ULONGLONG ChangeTime;
	ULONGLONG LastWriteTime;
	ULONGLONG LastAccessTime;
	ULONG FileAttributes;              // 文件的属性，包括只读、隐藏、归档、系统、加密等
	ULONG AlignmentOrReservedOrUnknown[3];
	ULONG QuotaId;                     // NTFS 3.0
	ULONG SecurityId;                  // NTFS 3.0
	ULONGLONG QuotaCharge;             // NTFS 3.0
	USN Usn;                           // NTFS 3.0
} STANDARD_INFORMATION, *PSTANDARD_INFORMATION;

/* 文件属性列表属性 */
/** 
*当单个MFT记录装不下文件的属性时，该文件才会有attribute list属性，装不下的可能原因：
* 1. The file has a large numbers of alternate names (文件有大量硬链接)
* 2. The attribute value is large, and the volume is badly fragmented（属性值太大，卷严重分散）
* 3. The file has a complex security descriptor (文件的安全描述符太复杂，但这个对NTFS 3.0没影响)
* 4. The file has many streams（文件有很多流）
**/
typedef struct {
	ATTRIBUTE_TYPE AttributeType;
	USHORT Length;                      // 属性列表条目的字节大小
	UCHAR NameLength;                   // 如果有属性名，属性名的字符大小
	UCHAR NameOffset;                   // 属性名的内部偏移，字节，属性名为Unicode
	ULONGLONG LowVcn;
	ULONGLONG FileReferenceNumber; 
	USHORT AttributeNumber;             // 该属性实例的数字标识符
	USHORT AlignmentOrReserved[3];
} ATTRIBUTE_LIST, *PATTRIBUTE_LIST;

/* 文件名属性 */
typedef struct {
	ULONGLONG DirectoryFileReferenceNumber; // 父节点的FRN
	ULONGLONG CreationTime;				    // 文件创建时间，该成员只在更改文件名时更新
	ULONGLONG ChangeTime;                   // 文件属性最近一次被修改的时间，该成员只在更改文件名时更新
	ULONGLONG LastWriteTime;                // 文件最近一次被写的时间，该成员只在更改文件名时更新
	ULONGLONG LastAccessTime;               // 文件最近一次被访问的时间，该成员只在更改文件名时更新
	ULONGLONG AllocatedSize;                // 分配多少磁盘空间用于容纳该属性值，该成员只在更改文件名时更新
	ULONGLONG DataSize;                     // 属性值的字节大小，该成员只在更改文件名时更新
	ULONG FileAttributes;                   // 文件的属性，该成员只在更改文件名时更新
	ULONG AlignmentOrReserved;    
	UCHAR NameLength;                       // 文件名长度，字符
	UCHAR NameType;                         // 文件名类型 0x01 = Long, 0x02 = Short（小于512字节）
	WCHAR Name[1];                          // 文件名，Unicode
} FILENAME_ATTRIBUTE, *PFILENAME_ATTRIBUTE;

/* 对象ID属性 */
typedef struct {
	GUID ObjectId;                // 分配给文件的唯一标识符
	union {
		struct {
			GUID BirthVolumeId;   // 文件第一次被创建，所在卷ID
			GUID BirthObjectId;   // 文件第一次被创建时，分配的ID
			GUID DomainId;        // 保留
		};
		UCHAR ExtendedInfo[48];
	};
} OBJECTID_ATTRIBUTE, *POBJECTID_ATTRIBUTE;

/* 卷信息 */
typedef struct {
	ULONG Unknown[2];
	UCHAR MajorVersion;   // NTFS主要版本号
	UCHAR MinorVersion;   // NTFS次要版本号
	USHORT Flags;         // 0x0001 = VolumeIsDirty 
} VOLUME_INFORMATION, *PVOLUME_INFORMATION;

/* 目录索引 */
typedef struct {
	ULONG EntriesOffset;     // 第一条记录（DIRECTORY_ENTRY）的内部字节偏移量
	ULONG IndexBlockLength;  // 这部分索引块在使用中的字节大小
	ULONG AllocatedSize;     // 分配了多少磁盘空间给这个索引块
	ULONG Flags;             // 0x00 = Small directory, index root能装下这个目录, 0x01 = Large directory, index root装不下这个目录
} DIRECTORY_INDEX, *PDIRECTORY_INDEX;

/* 目录条目 */
typedef struct {
	ULONGLONG FileReferenceNumber;  // 该条目描述的文件的FRN
	USHORT Length;                  // 该条目字节大小
	USHORT AttributeLength;         // 被索引的属性的字节大小

	/* 0x01 = Has trailing VCN, 0x02 = 目录块中最后一个条目
	若flags = 0x01,那么该 directory entry 最后8个字节表示包含此条目前一个条目的目录块的VCN */
	ULONG Flags; 
} DIRECTORY_ENTRY, *PDIRECTORY_ENTRY;

/* 根目录 */
typedef struct {
	ATTRIBUTE_TYPE Type;
	ULONG CollationRule;
	ULONG BytesPerIndexBlock;        // 每个索引块的字节数
	ULONG ClustersPerIndexBlock;     // 每个索引块的簇数
	DIRECTORY_INDEX DirectoryIndex;
} INDEX_ROOT, *PINDEX_ROOT;

/* 索引块头部 */
typedef struct {
	NTFS_RECORD_HEADER Ntfs;         // 类型为 INDX 的 NTFS_RECORD_HEADER
	ULONGLONG IndexBlockVcn;         // 该索引块的虚拟簇号VCN
	DIRECTORY_INDEX DirectoryIndex;
} INDEX_BLOCK_HEADER, *PINDEX_BLOCK_HEADER;

/* 重解析点 */
typedef struct {
	ULONG ReparseTag;
	USHORT ReparseDataLength;
	USHORT Reserved;
	UCHAR ReparseData[1];
} REPARSE_POINT, *PREPARSE_POINT;

/* extended attribute information */
typedef struct {
	ULONG EaLength;
	ULONG EaQueryLength;
} EA_INFORMATION, *PEA_INFORMATION;

typedef struct {
	ULONG NextEntryOffset;
	UCHAR Flags;
	UCHAR EaNameLength;
	USHORT EaValueLength;
	CHAR EaName[1];
	// UCHAR EaData[];
} EA_ATTRIBUTE, *PEA_ATTRIBUTE;

/* $AttrDef, 在 MFT 中的 Record number = 4*/
typedef struct {
	WCHAR AttributeName[64];
	ULONG AttributeNumber;
	ULONG Unknown[2];
	ULONG Flags;
	ULONGLONG MinimumSize;
	ULONGLONG MaximumSize;
} ATTRIBUTE_DEFINITION, *PATTRIBUTE_DEFINITION;

#pragma pack(push, 1)

typedef struct {
	UCHAR Jump[3];                   //跳过3个字节
	UCHAR Format[8];                 //‘N’'T' 'F' 'S' 0x20 0x20 0x20 0x20
	USHORT BytesPerSector;
	UCHAR SectorsPerCluster;
	USHORT BootSectors;
	UCHAR Mbz1;                      //保留0
	USHORT Mbz2;                     //保留0
	USHORT Reserved1;                //保留0
	UCHAR MediaType;                 //介质描述符，硬盘为0xf8
	USHORT Mbz3;                     //总为0
	USHORT SectorsPerTrack;          //每道扇区数，一般为0x3f
	USHORT NumberOfHeads;            //磁头数
	ULONG PartitionOffset;           //该分区的偏移（即该分区前的隐含扇区数 一般为磁道扇区数0x3f 63）
	ULONG Reserved2[2];
	ULONGLONG TotalSectors;          //该分区总扇区数
	ULONGLONG MftStartLcn;           //MFT表的起始簇号LCN
	ULONGLONG Mft2StartLcn;          //MFT备份表的起始簇号LCN
	ULONG ClustersPerFileRecord;     //每个MFT记录包含几个簇，记录的字节不一定为：ClustersPerFileRecord*SectorsPerCluster*BytesPerSector
	ULONG ClustersPerIndexBlock;     //每个索引块的簇数
	LARGE_INTEGER VolumeSerialNumber; //卷序列号
	UCHAR Code[0x1AE];
	USHORT BootSignature;
} BOOT_BLOCK, *PBOOT_BLOCK;

#pragma pack(pop)