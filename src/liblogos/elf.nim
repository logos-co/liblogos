import os, posix, memfiles, std/sequtils, std/strformat, strutils

proc `+`*(a: pointer, s: Natural): pointer = cast[pointer](cast[int](a) + s)

type
  EI_Class* = enum
    ELFCLASSNONE  = 0'u8   # Invalid class
    ELFCLASS32    = 1'u8   # 32-bit objects
    ELFCLASS64    = 2'u8   # 64-bit objects

  EI_Data* = enum
    ELFDATANONE = 0'u8  # Invalid data encoding
    ELFDATA2LSB = 1'u8  # Little-endian
    ELFDATA2MSB = 2'u8  # Big-endian

  ElfContext* = object
    file*: MemFile
    path*: string
    map_addr*: pointer  # Memory mapped file address
    map_size*: int64
    map_end*: pointer
    # elf*: ElfFile

  ElfIdentification* {.bycopy.} = object
    magic*: array[4, uint8]    # Magic number, should be 0x7F followed by "ELF"
    class*: EI_Class           # File class, identifies 32-bit or 64-bit architecture
    data*: EI_Data             # Data encoding, specifies endianness
    version*: uint8            # File version, should be 1 for the original version
    osabi*: uint8              # OS/ABI identification, specifies the target operating system and ABI
    abiversion*: uint8         # ABI version, further specifies the ABI version
    pad*: array[7, uint8]      # Padding, reserved for future use

  ElfHeader64* {.bycopy.} = object
    ident*: ElfIdentification  # Identification data, includes magic number and other metadata
    objtype*: uint16           # Object file type, e.g., executable, shared object, etc.
    machine*: uint16           # Machine architecture, specifies the required architecture
    version*: uint32           # Version of the ELF header, should be 1 for the original version
    entry*: uint64             # Entry point address, where the process starts executing
    phoff*: uint64             # Program header table offset, location of the program header table
    shoff*: uint64             # Section header table offset, location of the section header table
    flags*: uint32             # Processor-specific flags, architecture-specific flags
    ehsize*: uint16            # ELF header size, size of this header
    phentsize*: uint16         # Program header entry size, size of each entry in the program header table
    phnum*: uint16             # Number of program header entries, number of entries in the program header table
    shentsize*: uint16         # Section header entry size, size of each entry in the section header table
    shnum*: uint16             # Number of section header entries, number of entries in the section header table
    shstrndx*: uint16          # Section header string table index, index of the section header string table

  ProgramType* = enum
    PT_NULL = 0'u32,               # Unused entry
    PT_LOAD = 1'u32,               # Loadable segment
    PT_DYNAMIC = 2'u32,            # Dynamic linking tables
    PT_INTERP = 3'u32,             # Program interpreter path
    PT_NOTE = 4'u32,               # Note sections
    PT_SHLIB = 5'u32,              # Reserved
    PT_PHDR = 6'u32,               # Program header table
    PT_TLS = 7'u32,                # Thread local storage
    PT_GNU_EH_FRAME = 0x6474E550,  # GCC .eh_frame_hdr segment
    PT_GNU_STACK = 0x6474E551,     # Stack flags
    PT_GNU_RELRO = 0x6474E552      # Read-only after relocation

  ElfProgramHeader64* {.bycopy.} = object
    prgtype*: ProgramType      # Type of segment
    flags*: uint32             # Segment flags
    offset*: uint64            # Offset in file
    vaddr*: uint64             # Virtual address in memory
    paddr*: uint64             # Physical address (reserved)
    filesz*: uint64            # Size of segment in file
    memsz*: uint64             # Size of segment in memory
    align*: uint64             # Alignment of segment

  DynamicTag64* = enum
    DT_NULL = 0'u64            # Marks end of dynamic section
    DT_NEEDED = 1'u64          # Name of needed library
    DT_PLTRELSZ = 2'u64        # Size in bytes of PLT relocs
    DT_PLTGOT = 3'u64          # Processor defined value
    DT_HASH = 4'u64            # Address of symbol hash table
    DT_STRTAB = 5'u64          # Address of string table
    DT_SYMTAB = 6'u64          # Address of symbol table
    DT_RELA = 7'u64            # Address of Rela relocs
    DT_RELASZ = 8'u64          # Total size of Rela relocs
    DT_RELAENT = 9'u64         # Size of one Rela reloc
    DT_STRSZ = 10'u64          # Size of string table
    DT_SYMENT = 11'u64         # Size of one symbol table entry
    DT_INIT = 12'u64           # Address of init function
    DT_FINI = 13'u64           # Address of termination function
    DT_SONAME = 14'u64         # Name of shared object
    DT_RPATH = 15'u64          # Library search path (deprecated)
    DT_SYMBOLIC = 16'u64       # Start symbol search here
    DT_REL = 17'u64            # Address of Rel relocs
    DT_RELSZ = 18'u64          # Total size of Rel relocs
    DT_RELENT = 19'u64         # Size of one Rel reloc
    DT_PLTREL = 20'u64         # Type of reloc in PLT
    DT_DEBUG = 21'u64          # For debugging; unspecified
    DT_TEXTREL = 22'u64        # Reloc might modify .text
    DT_JMPREL = 23'u64         # Address of PLT relocs
    DT_BIND_NOW = 24'u64       # Process relocations of object
    DT_INIT_ARRAY = 25'u64     # Array with addresses of init fct
    DT_FINI_ARRAY = 26'u64     # Array with addresses of fini fct
    DT_INIT_ARRAYSZ = 27'u64   # Size in bytes of DT_INIT_ARRAY
    DT_FINI_ARRAYSZ = 28'u64   # Size in bytes of DT_FINI_ARRAY
    DT_RUNPATH = 29'u64        # Library search path
    DT_FLAGS = 30'u64          # Flags for the object being loaded
    DT_PREINIT_ARRAY = 32'u64  # Array with addresses of preinit fct
    DT_PREINIT_ARRAYSZ = 33'u64# Size in bytes of DT_PREINIT_ARRAY
    DT_SYMTAB_SHNDX = 34'u64   # Address of SYMTAB_SHNDX section
    DT_RELRSZ = 35'u64         # Size in bytes of DT_RELR
    DT_RELR = 36'u64           # Address of RELR relocs
    DT_RELRENT = 37'u64        # Size of one RELR reloc
    DT_ENCODING = 38'u64       # Start of encoded range
    DT_LOOS = 0x6000000D'u64   # Start of OS-specific
    DT_HIOS = 0x6fffffff'u64   # End of OS-specific
    DT_LOPROC = 0x70000000'u64 # Start of processor-specific
    DT_HIPROC = 0x7fffffff'u64 # End of processor-specific

  DynamicEntry64* {.bycopy.} = object
    tag*: DynamicTag64
    value*: uint64

  RelaEntry64* {.bycopy.} = object
    offset*: uint64    # Location to apply the relocation
    info*: uint64      # Symbol table index and type of relocation
    addend*: int64     # Constant addend used to compute value

  # SectionType* = enum
  #   SHT_NULL = 0,          # Inactive section header
  #   SHT_PROGBITS = 1,      # Program-defined contents
  #   SHT_SYMTAB = 2,        # Symbol table
  #   SHT_STRTAB = 3,        # String table
  #   SHT_RELA = 4,          # Relocation entries with addends
  #   SHT_HASH = 5,          # Symbol hash table
  #   SHT_DYNAMIC = 6,       # Dynamic linking tables
  #   SHT_NOTE = 7,          # Note information
  #   SHT_NOBITS = 8,        # Uninitialized space
  #   SHT_REL = 9,           # Relocation entries without addends
  #   SHT_SHLIB = 10,        # Reserved
  #   SHT_DYNSYM = 11        # Dynamic symbol table

  # ElfSectionHeader64* {.bycopy.} = object
  #   name*: uint32          # Section name (index into string table)
  #   shtype*: SectionType   # Section type
  #   flags*: uint64         # Section attributes
  #   vaddr*: uint64          # Virtual address in memory
  #   offset*: uint64        # Offset in file
  #   size*: uint64          # Size of section
  #   link*: uint32          # Link to other section
  #   info*: uint32          # Miscellaneous information
  #   addralign*: uint64     # Address alignment boundary
  #   entsize*: uint64       # Size of entries, if section has table

  SymbolBinding* = enum
    STB_LOCAL = 0'u32        # Local symbol
    STB_GLOBAL = 1'u32       # Global symbol
    STB_WEAK = 2'u32         # Weak symbol
    STB_LOOS = 10'u32        # Start of OS-specific
    STB_HIOS = 12'u32        # End of OS-specific
    STB_LOPROC = 13'u32      # Start of processor-specific
    STB_HIPROC = 15'u32      # End of processor-specific

  SymbolType* = enum
    STT_NOTYPE = 0'u32       # Symbol type is unspecified
    STT_OBJECT = 1'u32       # Symbol is a data object
    STT_FUNC = 2'u32         # Symbol is a code object
    STT_SECTION = 3'u32      # Symbol associated with a section
    STT_FILE = 4'u32         # Symbol's name is file name
    STT_COMMON = 5'u32       # Symbol is a common data object
    STT_TLS = 6'u32          # Symbol is thread-local data object
    STT_RELC = 8'u32         # Complex relocation expression
    STT_SRELC = 9'u32        # Signed Complex relocation expression
    STT_GNU_IFUNC = 10'u32   # GNU indirect function
    STT_HIOS = 12'u32        # End of OS-specific
    STT_LOPROC = 13'u32      # Start of processor-specific
    STT_HIPROC = 15'u32      # End of processor-specific

  RelocationType_x86_64* = enum
    R_X86_64_NONE = 0'u32            # No reloc
    R_X86_64_64 = 1'u32             # Direct 64 bit
    R_X86_64_PC32 = 2'u32           # PC relative 32 bit signed
    R_X86_64_GOT32 = 3'u32          # 32 bit GOT entry
    R_X86_64_PLT32 = 4'u32          # 32 bit PLT address
    R_X86_64_COPY = 5'u32           # Copy symbol at runtime
    R_X86_64_GLOB_DAT = 6'u32       # Create GOT entry
    R_X86_64_JUMP_SLOT = 7'u32      # Create PLT entry
    R_X86_64_RELATIVE = 8'u32       # Adjust by program base
    R_X86_64_GOTPCREL = 9'u32       # 32 bit signed PC relative offset to GOT
    R_X86_64_32 = 10'u32            # Direct 32 bit zero extended
    R_X86_64_32S = 11'u32           # Direct 32 bit sign extended
    R_X86_64_16 = 12'u32            # Direct 16 bit zero extended
    R_X86_64_PC16 = 13'u32          # 16 bit sign extended pc relative
    R_X86_64_8 = 14'u32             # Direct 8 bit sign extended
    R_X86_64_PC8 = 15'u32           # 8 bit sign extended pc relative
    R_X86_64_DTPMOD64 = 16'u32      # ID of module containing symbol
    R_X86_64_DTPOFF64 = 17'u32      # Offset in TLS block
    R_X86_64_TPOFF64 = 18'u32       # Offset in initial TLS block
    R_X86_64_TLSGD = 19'u32         # 32 bit signed PC relative offset to TLS
    R_X86_64_TLSLD = 20'u32         # 32 bit signed PC relative offset to TLS
    R_X86_64_DTPOFF32 = 21'u32      # Offset in TLS block
    R_X86_64_GOTTPOFF = 22'u32      # 32 bit signed PC relative offset to GOT
    R_X86_64_TPOFF32 = 23'u32       # Offset in initial TLS block

let pageSize = sysconf(SC_PAGESIZE)

template pageRoundDown(address: int): int = 
  (address div pageSize) * pageSize

template pageRoundUp(address: int): int = 
  ((address + (pageSize - 1)) div pageSize) * pageSize

proc cexecve(pathname: cstring, argv: ptr cstring, envp: ptr cstring): cint {.
        nodecl, importc: "execve", header: "<unistd.h>".}

proc c_memfd_create(name: cstring, flags: cint): cint {.header: "<sys/mman.h>",
        importc: "memfd_create".}

proc execveCmd(pathName: string, processName: string): int =
    when defined(linux):
        var pName: seq[string] = @[processName]
        var pNameArray: cStringArray = pName.allocCStringArray()
        let tmp = cexecve(pathName, pNameArray[0].addr, nil)
        result = if tmp == -1: tmp else: exitStatusLikeShell(tmp)
    else:
        result = cexecve(pathName)

proc launchWithCSyscall*(filePath : string) =
    # Read the binary into a buffer.
    let buffer = readFile(filePath)
    let fd = c_memfd_create("", 0)
    let handle: FileHandle = fd
    var memfdFile: File

    # Open the file for writing.
    let r = open(memfdFile, handle, fmReadWrite)
    # Write the buffer to memfdFile.
    write(memfdFile, buffer)

    # Build the anonymous file path from the fd cint.
    let proccessID: int = getCurrentProcessId()
    let pathName: string = fmt"/proc/{proccessID}/fd/{fd}"
    let procName: string = "[logos/mod:0]"

    var m = execveCmd(pathName, procName)

proc loadElf*(ctx: var ElfContext, path:string): bool =
  # TODO Fallback memfd, execve
  # TODO Fallback SHM

  ctx.path = path
  ctx.file = memfiles.open($path, mode=fmRead, allowRemap=true) # TODO revisit
  ctx.map_size = ctx.file.size.clong
  ctx.map_addr = ctx.file.mem
  ctx.map_end = ctx.map_addr + ctx.file.size

  let ident = cast[ptr ElfIdentification](ctx.map_addr)
  if ident.magic != [0x7F'u8, 0x45'u8, 0x4C'u8, 0x46'u8]:  # "\x7FELF"
    return false
  if ident.class != ELFCLASS64: # Only allow 64bit
    return false

  let header = cast[ptr ElfHeader64](ctx.map_addr)

  # Parse Program Headers
  let phStart = cast[int](ctx.map_addr) + int(header.phoff) # TODO double check this

  var programHeaders: seq[ElfProgramHeader64] = @[]
  for i in 0..<int(header.phnum):
    let offset = phStart + i * sizeof(ElfProgramHeader64)
    let prog_header = cast[ptr ElfProgramHeader64](offset)
    programHeaders.add(prog_header[])

  let loadableSegments = programHeaders.filter(proc(ph: ElfProgramHeader64): bool = ph.prgtype == PT_LOAD)
  
  # is PIE, bail
  if loadableSegments[0].vaddr == 0'u64:
    return false

  let interpreter = $cast[cstring](ctx.map_addr + programHeaders
    .filter(proc(ph: ElfProgramHeader64): bool = ph.prgtype == PT_INTERP and ph.filesz != 0'u64)
    .map(proc(ph: ElfProgramHeader64): uint64 = ph.offset)[0].int)

  echo "interpreter: ", interpreter
  # TODO load the interpreter loadElf(interpreter)
  # TODO consider patching the interpreter
  # TODO what if interpreter already loaded?

  let totalSize = loadableSegments
        .map(proc(ph: ElfProgramHeader64): uint64 = ph.vaddr + ph.memsz)
        .max()

  echo "total size: ", totalSize
  echo "page size ", pageSize

  let basePtr = mmap(
    nil,                    # addr
    totalSize.int,         # len needs to be int
    PROT_READ or PROT_WRITE,  # prot needs to be cint
    MAP_PRIVATE or MAP_ANONYMOUS,  # flags needs to be cint
    -1'i32,                # fd needs to be cint
    0'i64                  # offset needs to be Off (which is int64)
  )

  if basePtr == MAP_FAILED:
    raiseOSError(osLastError())

  let baseAddr = cast[int](basePtr)
  echo "baseAddr: ", $baseAddr

  let fh = ctx.file.handle

  for ph in loadableSegments:
    doAssert ph.memsz >= ph.filesz

    var size = ph.filesz.int
    # Convert ELF protection flags to mmap protection flags
    var prot = (ph.flags.uint32 shr 2) or ((ph.flags and 0b001'u32) shl 2) or (ph.flags and 0b010'u32)
    let offset = ph.offset.int
    let vaddr = ph.vaddr.int
    let unalignedAddr = baseAddr + vaddr
    let address = pageRoundDown(unalignedAddr)
    let alignDist = unalignedAddr - address
    size = size + alignDist
    let adjustedOffset = offset - alignDist

    let segmentPtr = mmap(
      cast[pointer](address),  # Fixed address
      size,
      prot.cint or PROT_WRITE,  # Add write permission temporarily
      MAP_PRIVATE or MAP_FIXED,
      fh,
      adjustedOffset.Off
    )

    if segmentPtr == MAP_FAILED:
      raiseOSError(osLastError())

    # Zero out the remaining bytes in the last page
    let fileEndAddr = address + size
    let remainingBytes = pageRoundUp(fileEndAddr) - fileEndAddr
    if remainingBytes > 0:
      zeroMem(cast[pointer](fileEndAddr), remainingBytes)
  

  # # Parse Section Headers
  # let shStart = cast[int](ctx.map_addr) + int(header.shoff)
  # let strTabHeader = cast[ptr ElfSectionHeader64](shStart + int(header.shstrndx) * sizeof(ElfSectionHeader64))
  # let strTab = cast[cstring](ctx.map_addr + strTabHeader.offset.int)

  # var sectionHeaders: seq[ElfSectionHeader64] = @[]
  # for i in 0..<int(header.shnum):
  #   let offset = shStart + i * sizeof(ElfSectionHeader64)
  #   let sect_header = cast[ptr ElfSectionHeader64](offset)
  #   sectionHeaders.add(sect_header[])
  #   let name = $cast[cstring](strTab + sect_header.name)
  #   echo "Section: ", name, " type: ", sect_header.shtype

  # # echo $sectionHeaders

  # TODO Relocations
  var relaAddr: uint64 = 0
  var relaSize: uint64 = 0
  let dynamicSegments = programHeaders.filter(proc(ph: ElfProgramHeader64): bool = ph.prgtype == PT_DYNAMIC)
  if dynamicSegments.len > 0:
    let dynamicSegment = dynamicSegments[0]
    let dynStart = cast[ptr UncheckedArray[DynamicEntry64]](ctx.map_addr + dynamicSegment.offset.int)
    let maxEntries = int(dynamicSegment.filesz) div sizeof(DynamicEntry64)
    for i in 0..<maxEntries:
        let entry = dynStart[i]
        case entry.tag
        of DT_RELA: relaAddr = entry.value
        of DT_RELASZ: relaSize = entry.value
        of DT_NULL: break
        else: discard

  echo "relaAddr: ", relaAddr, " relaSize: ", relaSize
  if relaAddr > 0 and relaSize > 0:
    let numRela = int(relaSize) div sizeof(RelaEntry64)
    let relaStart = cast[ptr UncheckedArray[RelaEntry64]](ctx.map_addr + relaAddr)
    echo "numRela: ", numRela
    
    for i in 0..<numRela:
      let entry = relaStart[i]
      # offset: where to apply the relocation
      # info: contains both symbol index and relocation type
      # addend: constant addend used to compute value
      
      let symbolIndex = uint32(entry.info shr 32)        # Top 32 bits are symbol index
      let relocationType = uint32(entry.info and 0xffffffff'u64)  # Bottom 32 bits are relocation type
      
      echo "Relocation at offset: ", entry.offset
      echo "  Symbol index: ", symbolIndex
      echo "  Type: ", relocationType 
      echo "  Addend: ", entry.addend

    #   # TODO: Apply the relocation based on type?
    #   # Common x64 relocation types:
    #   # R_X86_64_64 (1): S + A
    #   # R_X86_64_RELATIVE (8): B + A
    #   # R_X86_64_GLOB_DAT (6): S
    #   # R_X86_64_JUMP_SLOT (7): S



  return false # TODO return true