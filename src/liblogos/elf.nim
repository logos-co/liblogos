import memfiles, std/sequtils

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


proc loadElf*(ctx: var ElfContext, path:string): bool =
  ctx.path = path
  ctx.file = memfiles.open($path, mode=fmRead)
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
  let ph_start = cast[int](ctx.map_addr) + int(header.phoff) # TODO double check this

  var programHeaders: seq[ElfProgramHeader64] = @[]
  for i in 0..<int(header.phnum):
    let offset = ph_start + i * sizeof(ElfProgramHeader64)
    let prog_header = cast[ptr ElfProgramHeader64](offset)
    programHeaders.add(prog_header[])
  
  # TODO do this above to bail sooner
  let is_pie = programHeaders
        .filter(proc(ph: ElfProgramHeader64): bool = ph.prgtype == PT_LOAD)[0]
        .vaddr == 0'u64
  if is_pie:
    return false

  let interpreter = $cast[cstring](ctx.map_addr + programHeaders
    .filter(proc(ph: ElfProgramHeader64): bool = ph.prgtype == PT_INTERP and ph.filesz != 0'u64)
    .map(proc(ph: ElfProgramHeader64): uint64 = ph.offset)[0].int)

  echo "interpreter: ", interpreter

  let total_size: uint64 = programHeaders
        .filter(proc(ph: ElfProgramHeader64): bool = ph.prgtype == PT_LOAD)
        .map(proc(ph: ElfProgramHeader64): uint64 = ph.vaddr + ph.memsz)
        .max()

  echo "total size: ", total_size

  


  return false # TODO return true