"""Consistent truncation and bounds checks for section header table access.

These tests feed deliberately truncated and malformed ELF files to ELFFile and
verify that every entry point which touches the section header table
(counting sections, index and name access, DWARF extraction and string table
lookups) rejects input that does not fully fit inside the real file, instead
of treating trailing bytes as complete section headers.
"""
import io
import os
import struct
import unittest

from elftools.common.exceptions import ELFError, ELFParseError
from elftools.elf.elffile import ELFFile

TEST_DIR = os.path.join('test', 'testfiles_for_unittests')
# One 64-bit and one 32-bit little-endian object file, both carrying sections.
ELF64 = os.path.join(TEST_DIR, 'tls_relocs_x64_gcc.o')
ELF32 = os.path.join(TEST_DIR, 'compressed_32.o')


def _load(path):
    with open(path, 'rb') as f:
        return bytearray(f.read())


def _is_64bit(data):
    return data[4] == 2


def _field_offsets(data):
    """ Return the byte offsets of the section-related ELF header fields.
    """
    if _is_64bit(data):
        return {
            'e_shoff': 0x28,
            'e_shentsize': 0x3A,
            'e_shnum': 0x3C,
            'e_shstrndx': 0x3E,
            'word': 8,
            'shdr_size': 64,
            # Offsets of fields inside an Elf64_Shdr entry.
            'sh_offset': 24,
            'sh_size': 32,
        }
    return {
        'e_shoff': 0x20,
        'e_shentsize': 0x2E,
        'e_shnum': 0x30,
        'e_shstrndx': 0x32,
        'word': 4,
        'shdr_size': 40,
        # Offsets of fields inside an Elf32_Shdr entry.
        'sh_offset': 16,
        'sh_size': 20,
    }


def _elf_header_fields(data):
    off = _field_offsets(data)
    shoff = struct.unpack_from('<Q' if off['word'] == 8 else '<I',
                               data, off['e_shoff'])[0]
    shentsize, shnum, shstrndx = struct.unpack_from('<HHH', data,
                                                     off['e_shentsize'])
    return shoff, shentsize, shnum, shstrndx


def _open(data):
    return ELFFile(io.BytesIO(bytes(data)))


def _chain(exc):
    """ Yield an exception and its full __cause__/__context__ chain.
    """
    seen = set()
    while exc is not None and id(exc) not in seen:
        seen.add(id(exc))
        yield exc
        exc = exc.__cause__ or exc.__context__


def assert_rejected(testcase, data, needle):
    """ Assert that parsing rejects the data with a message containing needle.

    The section table is validated lazily on first access, so exercise the
    count and iteration entry points rather than merely constructing ELFFile.
    """
    try:
        elf = _open(data)
        elf.num_sections()
        list(elf.iter_sections())
    except ELFError as exc:
        messages = ' | '.join(str(e) for e in _chain(exc))
        testcase.assertIn(needle, messages,
                         f'error chain does not mention {needle!r}: {messages}')
        return
    testcase.fail('malformed ELF was accepted')


class TestSectionTableBounds(unittest.TestCase):
    def test_normal_files_unchanged(self):
        """ Valid files keep parsing exactly as before.
        """
        for path in (ELF64, ELF32):
            with self.subTest(path=path):
                data = _load(path)
                shoff, shentsize, shnum, _ = _elf_header_fields(data)
                elf = _open(data)
                self.assertEqual(elf.num_sections(), shnum)
                self.assertEqual(len(list(elf.iter_sections())), shnum)
                # Every declared header sits inside the file.
                self.assertLessEqual(shoff + shnum * shentsize, len(data))

    def test_no_section_table_still_works(self):
        """ e_shoff == 0 means zero sections and never touches the stream.
        """
        for path in (ELF64, ELF32):
            with self.subTest(path=path):
                data = _load(path)
                off = _field_offsets(data)
                struct.pack_into('<Q' if off['word'] == 8 else '<I',
                                 data, off['e_shoff'], 0)
                elf = _open(data)
                self.assertEqual(elf.num_sections(), 0)
                self.assertEqual(list(elf.iter_sections()), [])
                self.assertIsNone(elf.get_section_by_name('.text'))
                self.assertFalse(elf.has_section('.text'))

    def test_partial_section_header_table_rejected(self):
        """ A table cut off in the middle must not expose partial headers.
        """
        for path in (ELF64, ELF32):
            with self.subTest(path=path):
                data = _load(path)
                shoff, shentsize, shnum, _ = _elf_header_fields(data)
                # Keep two full headers plus a fragment of the third one.
                cut = shoff + 2 * shentsize + shentsize // 2
                self.assertLess(cut, shoff + shnum * shentsize)
                assert_rejected(self, data[:cut], 'declares')

    def test_huge_declared_count_rejected(self):
        """ An oversized e_shnum whose table overruns the file is rejected.
        """
        for path in (ELF64, ELF32):
            with self.subTest(path=path):
                data = _load(path)
                off = _field_offsets(data)
                struct.pack_into('<H', data, off['e_shnum'], 0xFFFF)
                assert_rejected(self, data, '65535')

    def test_shoff_past_eof_rejected(self):
        """ A section table starting beyond EOF is rejected with the range.
        """
        for path in (ELF64, ELF32):
            with self.subTest(path=path):
                data = _load(path)
                off = _field_offsets(data)
                struct.pack_into('<Q' if off['word'] == 8 else '<I',
                                 data, off['e_shoff'],
                                 len(data) + 0x1000)
                assert_rejected(self, data, '0 of')

    def test_extended_count_intact(self):
        """ e_shnum == 0 reads the real count from section 0's sh_size.
        """
        for path in (ELF64, ELF32):
            with self.subTest(path=path):
                data = _load(path)
                shoff, _, shnum, _ = _elf_header_fields(data)
                off = _field_offsets(data)
                struct.pack_into('<H', data, off['e_shnum'], 0)
                struct.pack_into('<Q' if off['word'] == 8 else '<I',
                                 data, shoff + off['sh_size'], shnum)
                elf = _open(data)
                self.assertEqual(elf.num_sections(), shnum)
                self.assertEqual(len(list(elf.iter_sections())), shnum)

    def test_extended_count_huge_rejected(self):
        """ A bogus count in section 0's sh_size is checked against bounds.
        """
        for path in (ELF64, ELF32):
            with self.subTest(path=path):
                data = _load(path)
                shoff, _, shnum, _ = _elf_header_fields(data)
                off = _field_offsets(data)
                struct.pack_into('<H', data, off['e_shnum'], 0)
                struct.pack_into('<Q' if off['word'] == 8 else '<I',
                                 data, shoff + off['sh_size'], 0xFFFFFFFF)
                self.assertNotEqual(shnum, 0xFFFFFFFF)
                assert_rejected(self, data, '4294967295')

    def test_extended_count_truncated_table_rejected(self):
        """ Extended numbering still requires every header in the file.
        """
        for path in (ELF64, ELF32):
            with self.subTest(path=path):
                data = _load(path)
                shoff, shentsize, shnum, _ = _elf_header_fields(data)
                off = _field_offsets(data)
                struct.pack_into('<H', data, off['e_shnum'], 0)
                struct.pack_into('<Q' if off['word'] == 8 else '<I',
                                 data, shoff + off['sh_size'], shnum)
                cut = shoff + shentsize + 3
                assert_rejected(self, bytes(data)[:cut], 'declares')

    def test_index_out_of_range_rejected(self):
        """ Index access past the validated count is refused explicitly.
        """
        for path in (ELF64, ELF32):
            with self.subTest(path=path):
                elf = _open(_load(path))
                count = elf.num_sections()
                for bad in (count, count + 10, -1):
                    with self.assertRaisesRegex(ELFParseError, 'out of range'):
                        elf.get_section(bad)

    def test_shstrndx_out_of_range_rejected(self):
        """ A section-name string table index past the table is rejected.
        """
        for path in (ELF64, ELF32):
            with self.subTest(path=path):
                data = _load(path)
                _, _, shnum, _ = _elf_header_fields(data)
                off = _field_offsets(data)
                struct.pack_into('<H', data, off['e_shstrndx'], shnum + 50)
                elf = _open(data)
                with self.assertRaises(ELFParseError):
                    elf.get_section_by_name('.text')

    def test_shrunken_string_table_index_rejected(self):
        """ sh_name offsets outside the declared string table are refused.
        """
        for path in (ELF64, ELF32):
            with self.subTest(path=path):
                data = _load(path)
                shoff, _, _, shstrndx = _elf_header_fields(data)
                off = _field_offsets(data)
                strtab_hdr = shoff + shstrndx * off['shdr_size']
                struct.pack_into('<Q' if off['word'] == 8 else '<I',
                                 data, strtab_hdr + off['sh_size'], 1)
                elf = _open(data)
                with self.assertRaisesRegex(ELFParseError, 'out of range'):
                    elf.get_section_by_name('.text')

    def test_string_table_past_eof_rejected(self):
        """ A string table whose bytes run past EOF cannot supply names.
        """
        for path in (ELF64, ELF32):
            with self.subTest(path=path):
                data = _load(path)
                shoff, _, _, shstrndx = _elf_header_fields(data)
                off = _field_offsets(data)
                strtab_hdr = shoff + shstrndx * off['shdr_size']
                fmt = '<Q' if off['word'] == 8 else '<I'
                struct.pack_into(fmt, data, strtab_hdr + off['sh_offset'],
                                 len(data) - 4)
                struct.pack_into(fmt, data, strtab_hdr + off['sh_size'],
                                 0x1000)
                elf = _open(data)
                with self.assertRaisesRegex(ELFParseError, 'exceeds file size'):
                    elf.get_section_by_name('.text')

    def test_dwarf_extraction_rejects_truncated_table(self):
        """ DWARF access goes through the same validated section lookups.
        """
        data = _load(ELF32)
        shoff, shentsize, _, _ = _elf_header_fields(data)
        cut = shoff + 3 * shentsize + 7
        elf = _open(data[:cut])
        with self.assertRaises(ELFParseError):
            elf.has_dwarf_info()
        with self.assertRaises(ELFParseError):
            elf.get_dwarf_info()

    def test_nobits_and_null_sections_keep_semantics(self):
        """ Sections without file content are not subject to range checks.
        """
        elf = _open(_load(ELF64))
        null = elf.get_section(0)
        self.assertTrue(null.is_null())
        self.assertEqual(null.data(), b'')
        nobits = next(s for s in elf.iter_sections()
                      if s['sh_type'] == 'SHT_NOBITS' and s.data_size > 0)
        self.assertEqual(nobits.data(), bytes(nobits.data_size))


if __name__ == '__main__':
    unittest.main()
