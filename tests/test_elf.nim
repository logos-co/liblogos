import unittest
import liblogos/elf

test "load ELF":
  var ctx: ElfContext
  check loadElf(ctx, "/bin/ls")
