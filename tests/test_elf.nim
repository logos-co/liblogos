import unittest
import liblogos

test "load ELF":
  check liblogos.load("/bin/ls")
