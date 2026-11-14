#-------------------------------------------------------------------------------
# Test handling for compressed debug sections
#
# Pierre-Marie de Rodat (pmderodat@kawie.fr)
# This code is in the public domain
#-------------------------------------------------------------------------------

import os
import unittest
from contextlib import contextmanager
from io import BytesIO

from elftools.common.exceptions import ELFCompressionError
from elftools.elf.constants import SH_FLAGS
from elftools.elf.descriptions import describe_sh_flags
from elftools.elf.elffile import ELFFile


class TestCompressedSupport(unittest.TestCase):

    def test_compressed_32(self):
        with self.elffile('32') as elf:
            section = elf.get_section_by_name('.debug_info')
            self.assertTrue(section.compressed)
            self.assertEqual(describe_sh_flags(section['sh_flags']), 'C')
            self.assertEqual(section.data_size, 0x330)
            self.assertEqual(section.data_alignment, 1)

            self.assertEqual(self.get_cus_info(elf), ['CU 0x0: 0xb-0x322'])

    def test_compressed_64(self):
        with self.elffile('64') as elf:
            section = elf.get_section_by_name('.debug_info')
            self.assertTrue(section.compressed)
            self.assertEqual(describe_sh_flags(section['sh_flags']), 'C')
            self.assertEqual(section.data_size, 0x327)
            self.assertEqual(section.data_alignment, 1)
            self.assertEqual(self.get_cus_info(elf), ['CU 0x0: 0xb-0x319'])

    def test_compressed_and_excluded_flags(self):
        flags = SH_FLAGS.SHF_COMPRESSED | SH_FLAGS.SHF_EXCLUDE
        self.assertEqual(describe_sh_flags(flags), 'CE')

    def test_compressed_unknown_type(self):
        with self.elffile('unknown_type') as elf:
            section = elf.get_section_by_name('.debug_info')
            try:
                section.data()
            except ELFCompressionError as exc:
                self.assertEqual(
                    str(exc), 'Unknown compression type: 0x7ffffffe'
                )
            else:
                self.fail('An exception was exected')

    def test_compressed_bad_size(self):
        with self.elffile('bad_size') as elf:
            section = elf.get_section_by_name('.debug_info')
            try:
                section.data()
            except ELFCompressionError as exc:
                self.assertEqual(
                    str(exc),
                    'Decompressed data is 807 bytes long, should be 808 bytes'
                    ' long'
                )
            else:
                self.fail('An exception was exected')

    def test_compressed_gnu_style(self):
        """ A GNU-style .zdebug_ section is read like an SHF_COMPRESSED one.
        """
        path = os.path.join('test', 'testfiles_for_readelf', 'zdebug_mixed.so.elf')
        with open(path, 'rb') as f:
            elf = ELFFile(f)
            dwarf = elf.get_dwarf_info()
            self.assertEqual(dwarf.debug_info_sec.name, '.zdebug_info')
            self.assertEqual(dwarf.debug_info_sec.size, 147)
            self.assertEqual(
                [cu.cu_offset for cu in dwarf.iter_CUs()], [0])
            # Not every debug section of that file was compressed.
            line_str = elf.get_section_by_name('.debug_line_str')
            self.assertEqual(line_str.data(), b'/tmp\x00zdebug_mixed.c\x00')

    def test_compressed_gnu_style_truncated(self):
        """ Truncating the stored stream of a .zdebug_ section is reported
            instead of leaving partial DWARF data behind.
        """
        path = os.path.join('test', 'testfiles_for_readelf', 'zdebug_mixed.so.elf')
        with open(path, 'rb') as f:
            data = f.read()
        elf = ELFFile(BytesIO(data))
        section = elf.get_section_by_name('.zdebug_info')
        offset, size = section['sh_offset'], section['sh_size']
        # Wipe the tail of the compressed stream, then read it as .zdebug_info.
        corrupted = bytearray(data)
        corrupted[offset + size - 14: offset + size - 4] = b'\0' * 10
        elf = ELFFile(BytesIO(bytes(corrupted)))
        with self.assertRaises(ELFCompressionError):
            elf.get_dwarf_info()

    def test_compressed_gnu_style_bad_magic(self):
        """ A .zdebug_ section without the ZLIB magic is rejected.
        """
        path = os.path.join('test', 'testfiles_for_readelf', 'zdebug_mixed.so.elf')
        with open(path, 'rb') as f:
            data = f.read()
        elf = ELFFile(BytesIO(data))
        section = elf.get_section_by_name('.zdebug_info')
        offset = section['sh_offset']
        corrupted = bytearray(data)
        corrupted[offset:offset + 4] = b'XLIB'
        elf = ELFFile(BytesIO(bytes(corrupted)))
        with self.assertRaisesRegex(ELFCompressionError, 'Invalid compression type'):
            elf.get_dwarf_info()

    # Test helpers

    @contextmanager
    def elffile(self, name):
        """ Context manager to open and parse an ELF file.
        """
        with open(os.path.join('test', 'testfiles_for_unittests',
                               f'compressed_{name}.o'), 'rb') as f:
            yield ELFFile(f)

    def get_cus_info(self, elffile):
        """ Return basic info about the compile units in `elffile`.

        This is used as a basic sanity check for decompressed DWARF data.
        """
        result = []

        dwarf = elffile.get_dwarf_info()
        for cu in dwarf.iter_CUs():
            dies = []

            def traverse(die, dies=dies):
                dies.append(die.offset)
                for child in die.iter_children():
                    traverse(child)

            traverse(cu.get_top_DIE())
            result.append(f'CU {cu.cu_offset:#0x}: {dies[0]:#0x}-{dies[-1]:#0x}')

        return result
