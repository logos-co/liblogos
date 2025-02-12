import os, std/paths
import liblogos/loader/[elf, pe, macho]

when defined(macosx):
  proc NSGetEnviron(): ptr cstringArray {.importc: "_NSGetEnviron", header: "<crt_externs.h>".}
  var env = NSGetEnviron()[]
else:
  var env {.importc: "environ".}: cstringArray

proc load*(bytes: seq[byte], argv: cstringArray, env: cstringArray): bool =
  result = ul_execve(bytes)
  # when defined(linux): # TODO unix or posix?
  #   try:
  #     result = ul_execve(bytes)
  #   except:
  #     try:
  #       memfd_execve(bytes)
  #       result = true
  #     except:
  #       # TODO: implement shm_execve
  #       raise
  # elif defined(windows):
  #   # TODO: implement Windows PE loading
  #   raise newException(OSError, "Windows PE loading not yet implemented")
  # elif defined(macosx):
  #   # TODO: implement macOS Mach-O loading 
  #   raise newException(OSError, "macOS Mach-O loading not yet implemented")
  # else:
  #   raise newException(OSError, "Unsupported platform")

# TODO this is stupid use of typing and overloading because a string is seq[byte]
proc load*(path: string, argv: cstringArray, env: cstringArray): bool =
  if not fileExists(path):
    raise newException(IOError, "File does not exist: " & path)
  result = load(cast[seq[byte]](readFile(path)), argv, env)

proc load*(file: seq[byte] | string, argv: cstringArray): bool =
  result = load(file, argv, env)

proc load*(file: seq[byte] | string): bool =
  var defaultArgv = allocCStringArray(@[])
  result = load(file, defaultArgv, env)