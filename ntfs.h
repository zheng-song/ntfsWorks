
#ifndef NTFS_H_INCLUDED
#define NTFS_H_INCLUDED

// **NTFS RECORD HEADER**
typedef struct {
	ULONG Type;  		// 4B 'ELIF','XDNI','DAAB','ELOH','DKHC'
	USHORT UsaOffset;	// 更新序列号数组偏移
	USHORT UsaCount;	// 更新序列号的数组个数+1(N)，通常为3
	USN Usn; 			//USN == LONLONG 8B 每一次记录被修改，USN都会变化
}NTFS_RECORD_HEADER, *PNTFS_RECORD_HEADER; // 16B

//****FILE RECORD_HEADER****
typedef struct {
	NTFS_RECORD_HEADER Ntfs;   	// Ntfs.type 总是'ELIF'
	USHORT SequenceNumber;		// $LogFile Sequence Number  
	USHORT LinkCount;			// 记录硬连接的数目，只出现在基本文件记录中
	USHORT AttributeOffset;		// 第一个属性的偏移 
	USHORT Flags;				// 0x0000=deleted file; 0x0001=file, 0x0002=deleted dir; 0x0003= dir;
	ULONG BytesInUse;			// 已被该 MFT entry 使用的字节数
	ULONG BytesAllocated;		// 分配给该 MFT entry 的字节数
/*当前文件记录的基本文件记录的索引，如果当前文件记录是基本文件记录则该值为0，
 *否则指向基本文件记录的记录索引。注意该值的低6字节是MFT记录号，高2字节是该MFT记录的序列号。*/
	ULONGLONG BaseFileRecord;	
	USHORT NextAttributeNumber;	// 下一属性ID	
	UCHAR Unused[2];
	ULONG MFTRecordNo;			   // 该MFT的记录编号(起始编号0)
//	ULONGLONG Usa; //更新序列号的位置和大小由前面的 UsaOffset 和UsaCount来决定.
}FILE_RECORD_HEADER, *PFILE_RECORD_HEADER; // 42B


//文件记录中按属性非降序（因为有时连续多个相同的属性）排列，   
//属性的值即为 字节流   
typedef enum {
	//诸如只读、存档等文件属性；   
	//时间戳：文件创建时、最后一次修改时；   
	//多少目录指向该文件（硬链接计数hard link count）   
	AttributeStandardInformation = 0x10, //Resident_Attributes 常驻属性  
	//当一个文件要求多个MFT文件记录时 会有该属性   
	//属性列表，包括构成该文件的这些属性，以及每个属性所在的MFT文件记录的文件引用   
	AttributeAttributeList = 0x20,//由于属性值可能会增长，可能是非驻留属性  

	//文件名属性可以有多个：   
	//1.长文件名自动为其短文件名(以便MS-DOS和16位程序访问)   
	//2.当该文件存在硬链接时   
	AttributeFileName = 0x30, //常驻  

	//一个文件或目录的64字节标识符，其中低16字节对于该卷来说是唯一的   
	//链接-跟踪服务将对象ID分配给外壳快捷方式和OLE链接源文件。   
	//NTFS提供了相应的API，因为文件和目录可以通过其对象ID，而不是通过其文件名打开   
	AttributeObjectId = 0x40, //常驻  
																														   //为与NTFS以前版本保持向后兼容   
	//所有具有相同安全描述符的文件或目录共享同样的安全描述   
	//以前版本的NTFS将私有的安全描述符信息与每个文件和目录存储在一起   
	AttributeSecurityDescriptor = 0x50,//出现于$Secure元数据文件中  

	//保存了该卷的版本和label信息   
	AttributeVolumeName = 0x60, //仅出现于$Volume元数据文件中   
	AttributeVolumeInformation = 0x70,//仅出现于$Volume元数据文件中  

	//文件内容，一个文件仅有一个未命名的数据属性，但可有额外多个命名数据属性   
	//即一个文件可以有多个数据流，目录没有默认的数据属性，但可有多个可选的命名的数据属性   
	AttributeData = 0x80,//由于属性值可能会增长，可能是非驻留属性  

	//以下三个用于实现大目录的文件名分配和位图索引   
	AttributeIndexRoot = 0x90,//常驻   
	AttributeIndexAllocation = 0xA0,
	AttributeBitmap = 0xB0,

	//存储了一个文件的重解析点数据，NTFS的交接(junction)和挂载点包含此属性   
	AttributeReparsePoint = 0xC0,

	//以下两个为扩展属性，现已不再被主动使用，之所以提供是为与OS/2程序保持向后兼容   
	AttributeEAInformation = 0xD0,
	AttributeEA = 0xE0,

	AttributePropertySet = 0xF0,
	AttributeLoggedUtilityStream = 0x100,
	AttributeEnd = 0xFFFFFFFF
} ATTRIBUTE_TYPE, *PATTRIBUTE_TYPE;

/* 文件标准信息属性 */
typedef struct {
	ULONGLONG CreationTime;
	ULONGLONG ChangeTime;
	ULONGLONG LastWriteTime;
	ULONGLONG LastAccessTime;
	ULONG FileAttributes;              // 文件的属性，包括只读0001、隐藏0002、系统0004、加密4000等
	ULONG AlignmentOrReservedOrUnknown[3];
	ULONG QuotaId;                     // NTFS 3.0
	ULONG SecurityId;                  // NTFS 3.0
	ULONGLONG QuotaCharge;             // NTFS 3.0
	USN Usn;                           // NTFS 3.0
} STANDARD_INFORMATION, *PSTANDARD_INFORMATION;


typedef struct {
	ATTRIBUTE_TYPE AttributeType;
	ULONG AttributeLength; 			//本属性长度（包含属性值）
	BOOLEAN Nonresident;			//本属性是不是驻留属性 0x00=Resident, 0x01 = NonResident
	UCHAR NameLength;				//属性名的名称长度 长度为2*NameLength
	USHORT NameOffset;				//属性名偏移
	USHORT Flags;	 				// 压缩、加密、稀疏等的标识0x00FF=compressed  0x4000=encrypted  0x8000=Sparse
	USHORT AttributeID;				// 该属性实例的数字标识符
}ATTRIBUTE, *PATTRIBUTE;


typedef struct {
	ATTRIBUTE Attribute;
	ULONG ContentLength;	//属性体长度
	USHORT ContentOffset; 	//属性体偏移
// 属性是否被索引项所索引，索引项是一个索引(如目录)的基本组成索引标志 0x0001 = Indexed
	UCHAR IndexFlags;
	UCHAR Unused;
} RESIDENT_ATTRIBUTE, *PRESIDENT_ATTRIBUTE;

// 这个结构的定义和图片里结构的描述不一致
// TODO
typedef struct {
	ATTRIBUTE Attribute;
	ULONGLONG LowVcn;	   // 起始虚拟簇号VCN
	ULONGLONG HighVcn;	   // 结束虚拟簇号VCN
	USHORT RunArrayOffset; // run list运行列表的偏移量 常用值为40
	UCHAR CompressionUint; // 若该成员为0，该属性未被压缩
	UCHAR Reserved[5];			// 
	ULONGLONG StreamAllocSize;	// 为属性值分配的空间，单位为簇
	ULONGLONG StreamRealSize;	// 属性值实际使用的空间，单位为簇
	ULONGLONG InitializedSize;	// 属性的原始大小，
//	ULONGLONG CompressedSize;    // Only when compressed 压缩单位的大小，2的N次方   
//接下来是run list的信息。
} NONRESIDENT_ATTRIBUTE, *PNONRESIDENT_ATTRIBUTE;


/* 文件属性列表属性 */
/*
 * 当单个MFT记录装不下文件的属性时，该文件才会有attribute list属性，装不下的可能原因：
 * 1. The file has a large numbers of alternate names (文件有大量硬链接)
 * 2. The attribute value is large, and the volume is badly fragmented（属性值太大，卷严重分散）
 * 3. The file has a complex security descriptor (文件的安全描述符太复杂，但这个对NTFS 3.0没影响)
 * 4. The file has many streams（文件有很多流）
 */
typedef struct {
	ATTRIBUTE_TYPE AttributeType; 			//属性类型
	USHORT Length;							//本记录长度
	UCHAR NameLength;						//属性名长度(N,为0表示没有属性名)
	UCHAR NameOffset;						//属性名偏移
	ULONGLONG LowVcn;						//起始VCN(属性常驻时为0)
	ULONGLONG FileReferenceNumber;			//属性的文件参考号
	USHORT AttributeNumber;					//属性的ID(每一个属性都有一个唯一的ID号)
/*接下来的2N个字节表示属性名的Unicode码，如果有属性名的话。否则就填0对齐*/
	USHORT AlignmentOrReserved[3];
} ATTRIBUTE_LIST, *PATTRIBUTE_LIST;


typedef struct {  
	ULONGLONG DirectoryFileReferenceNumber; 	// 父目录的文件参考号   
	ULONGLONG CreateTime;						// 文件创建时间
	ULONGLONG ModifiedTime;						// 文件修改时间
	ULONGLONG LastWriteTime; 					// 最后一次MFT更新时间   
	ULONGLONG LastAccessTime;					// 最后一次的访问时间
	ULONGLONG AllocSize; 						// 文件分配的大小   
	ULONGLONG DataSize; 						// 文件使用的大小  
	ULONG Flags;								// 标志，如目录、压缩、隐藏等
	ULONG ReparseValue;							// 用于EAS和重点解析
	UCHAR NameLength;							// 以字符计的文件名长度，每个字符占用的字节数由命名空间决定
	UCHAR NameType; 							// 文件名的命名空间0x0  WIN32 0x01  DOS 0x02  WIN32&DOS 0x3   
//	WCHAR Name[1]; // 这部分是UNICODE方式表示的文件名，长度通常为2*NameLength。
} FILENAME_ATTRIBUTE, *PFILENAME_ATTRIBUTE;


typedef struct {
	GUID ObjectId;								// 分配给文件的唯一标识符
	union {
		struct {
			GUID BirthVolumeId;					// 文件第一次被创建，所在卷ID
			GUID BirthObjectId;					// 文件第一次被创建时，分配的ID
			GUID DomainId;						// 保留
		};
		UCHAR ExtendedInfo[48];
	};
} OBJECTID_ATTRIBUTE, *POBJECTID_ATTRIBUTE;


typedef struct {
	ULONG Unknown[2];
	UCHAR MajorVersion;	// NTFS主要版本号
	UCHAR MinorVersion;	// NTFS次要版本号
	USHORT Flags;		// 0x0001 = VolumeIsDirty
} VOLUME_INFORMATION, *PVOLUME_INFORMATION;



typedef struct {
	ULONGLONG MFTnum;		//文件的MFT参考号，前6B是改文件的MFT编号，用于定位此文件
	USHORT ItemLen;			//索引项的大小
	UCHAR IdxIdentifier[2];	//索引标志
	UCHAR IsNode[2];		//1--此索引包含一个子节点，0--此为最后一项
	UCHAR noUse[2];			//填充
	ULONGLONG FMFTnum;		//父目录的MFT参考号，0x05表示根目录。
	ULONGLONG	CreateTime;
	ULONGLONG FileModifyTime;
	ULONGLONG	MFTModifyTime;
	ULONGLONG LastVisitTime;
	ULONGLONG	FileAllocSize;
	ULONGLONG FileRealSize;
	UCHAR FileIdentifier[8];//文件标识
	UCHAR FileNameLen;		//文件名长度F
	UCHAR FileNameSpace;	//文件名命名空间
//---0x52--- 文件名，长度为2F，并在其后填充到8字节
//	ULONGLONG NextItemVCN;
}INDEXITEM, *PINDEXITEM;

/*目录条目*/
typedef struct {
	ULONGLONG FileReferenceNumber;	// 该条目描述的文件的FRN
	USHORT Length;					// 该条目字节大小
	USHORT AttributeLength;			// 被索引的属性的字节大小
	ULONG Flags; // 0x01 = Has trailing VCN, 0x02 = Last entry
				 // FILENAME_ATTRIBUTE Name;
				 // ULONGLONG Vcn; // VCN in IndexAllocation of earlier entries
} DIRECTORY_ENTRY, *PDIRECTORY_ENTRY;

typedef struct {
	ULONG EntriesOffset;	// 第一条记录（DIRECTORY_ENTRY）的内部字节偏移量
	ULONG IndexBlockLength;	// 这部分索引块在使用中的字节大小
	ULONG AllocatedSize;	// 分配了多少磁盘空间给这个索引块
	ULONG Flags;			// 0x00 = Small directory, index root能装下这个目录, 0x01 = Large directory, index root装不下这个目录
} DIRECTORY_INDEX, *PDIRECTORY_INDEX;


/*索引块头部*/
typedef struct {
	NTFS_RECORD_HEADER Ntfs;	// 类型为 INDX 的 NTFS_RECORD_HEADER
	ULONGLONG VcnIndex;			//本索引缓存在分配索引中的VCN
	ULONG ItemOffset;			//第一索引项的偏移
	ULONG ItemSize;				//索引项的实际大小(B)
	ULONG ItemAllocSize;		//索引项的分配大小(B，不包括头部)，略小于4K
	UCHAR IsNode;				//是节点则为1，否则表示有子节点。
	UCHAR Nouse[3];				//填充
//	UCHAR USN[2 * UsnUpdateArrSize];    //此处有一个使用Ntfs中的UsnUpdateArrSize*2大小的字节的USN号
};

/*根目录*/
typedef struct {
	ATTRIBUTE_TYPE Type;		// 4B 属性类型
	ULONG CollationRule;		// 4B 排序规则
	ULONG BytesPerIndexBlock;	// 4B 索引项分配大小
	UCHAR ClustersPerIndexBlock;// 每索引记录的簇数
	UCHAR noUse[3];
	DIRECTORY_INDEX DirectoryIndex;
} INDEX_ROOT, *PINDEX_ROOT;


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

#pragma pack(push,1)   
typedef struct { //512B   
	UCHAR Jump[3];			//跳过3个字节   
	UCHAR Format[8]; 		//‘N’'T' 'F' 'S' 0x20 0x20 0x20 0x20   
	USHORT BytesPerSector;	//每扇区有多少字节 一般为512B 0x200   
	UCHAR SectorsPerCluster;//每簇有多少个扇区   
	USHORT BootSectors;		//   
	UCHAR Mbz1;				//保留0   
	USHORT Mbz2;			//保留0   
	USHORT Reserved1;		//保留0   
	UCHAR MediaType;		//介质描述符，硬盘为0xf8   
	USHORT Mbz3;			//总为0   
	USHORT SectorsPerTrack;	//每道扇区数，硬盘一般为0x3f   
	USHORT NumberOfHeads;	//硬盘的磁头数   
	ULONG PartitionOffset;	//该分区的偏移（即该分区前的隐含扇区数 一般为一个磁道扇区数0x3f 63）   
	ULONG Reserved2[2];
	ULONGLONG TotalSectors;	//该分区总扇区数   
	ULONGLONG MftStartLcn;	//MFT表的起始簇号LCN   
	ULONGLONG Mft2StartLcn;	//MFT备份表的起始簇号LCN   
	ULONG ClustersPerFileRecord;//每个MFT记录包含几个簇  
	//记录的字节不一定为：ClustersPerFileRecord*SectorsPerCluster*BytesPerSector  
	ULONG ClustersPerIndexBlock;//每个索引块的簇数   
	LARGE_INTEGER VolumeSerialNumber;//卷序列号   
	UCHAR Code[0x1AE];
	USHORT BootSignature;			//总是 0xAA55
} BOOT_BLOCK, *PBOOT_BLOCK;

#pragma pack(pop) 
	
#endif	// NTFS_H_INCLUDED