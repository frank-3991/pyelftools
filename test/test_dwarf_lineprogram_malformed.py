#-------------------------------------------------------------------------------
# elftools tests
#
# Tests for the error boundaries of the DWARF line number program decoder
# against untrusted/malformed input, and for the stability of address-to-source
# mappings produced from well-formed programs.
#
# The tests build synthetic .debug_line units from raw bytes, so no compiled
# ELF fixture is required. Only parsing behavior is exercised; the decoder
# itself is not modified.
#
# This code is in the public domain
#-------------------------------------------------------------------------------
import io
import unittest
from io import BytesIO

from elftools.common.exceptions import DWARFError, ELFParseError
from elftools.dwarf.constants import DW_LNE, DW_LNS
from elftools.dwarf.dwarfinfo import (
    DebugSectionDescriptor,
    DwarfConfig,
    DWARFInfo,
)
from elftools.dwarf.lineprogram import LineProgram
from elftools.dwarf.structs import DWARFStructs

# opcode_base = 10 -> nine standard opcode lengths, for opcodes 1..9
STD_LENS = bytes([0, 1, 1, 1, 1, 1, 0, 0, 1])
# opcode_base = 14 -> thirteen lengths; opcodes 10..13 have no handler
STD_LENS_14 = bytes([0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0])

STRUCTS = DWARFStructs(little_endian=True, dwarf_format=32, address_size=4)


def encode_uleb128(value):
    """Encode a non-negative integer as an ULEB128 byte string."""
    result = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            result.append(byte | 0x80)
        else:
            result.append(byte)
            return bytes(result)


def build_line_unit(
    program,
    *,
    opcode_base=10,
    standard_lengths=STD_LENS,
    directories=(b'ab',),
    files=((b'ar.c', 12, 13, 15),),
):
    """Build a complete DWARF v3 .debug_line unit (header plus program).

    The header_length field is computed from the assembled bytes so the
    reported unit length always matches the actual payload.
    """
    after_length = b'\x01'          # minimum_instruction_length
    after_length += b'\x01'         # default_is_stmt
    after_length += b'\x0F'         # line_base (signed: -1)
    after_length += b'\x0F'         # line_range
    after_length += bytes([opcode_base])
    after_length += standard_lengths[:opcode_base - 1]
    for directory in directories:
        after_length += directory + b'\x00'
    after_length += b'\x00'         # terminate include_directory list
    for name, dir_index, mtime, length in files:
        after_length += name + b'\x00'
        after_length += encode_uleb128(dir_index)
        after_length += encode_uleb128(mtime)
        after_length += encode_uleb128(length)
    after_length += b'\x00'         # empty file name terminates file_entry

    unit_length = 2 + 4 + len(after_length) + len(program)
    return (
        unit_length.to_bytes(4, 'little')
        + b'\x03\x00'                                  # version
        + len(after_length).to_bytes(4, 'little')     # header_length
        + after_length
        + program
    )


def parse_header(unit):
    """Parse a line program header from assembled unit bytes."""
    return STRUCTS.Dwarf_lineprog_header.parse(unit)


def make_line_program(program, **header_kwargs):
    """Build a LineProgram whose bounded region is exactly program bytes."""
    unit = build_line_unit(program, **header_kwargs)
    return LineProgram(
        parse_header(unit), BytesIO(program), STRUCTS, 0, len(program))


# A small well-formed program: set_address, copy, end_sequence.
VALID_PROGRAM = (
    b'\x00\x05\x02'                      # DW_LNE.set_address
    + (0x1000).to_bytes(4, 'little')    # address 0x1000
    + bytes([DW_LNS.copy])
    + b'\x00\x01\x01'                   # DW_LNE.end_sequence
)


class TestMalformedLinePrograms(unittest.TestCase):
    """Error boundaries for operands crossing the end of a unit."""

    def assert_rejected(self, program, **header_kwargs):
        """Decoding program must raise rather than run past the unit end."""
        line_program = make_line_program(program, **header_kwargs)
        with self.assertRaises(ELFParseError):
            line_program.get_entries()

    def test_truncated_uleb128_standard_operands(self):
        # A continuation byte with no terminating byte makes the ULEB128
        # operand run past the unit boundary.
        self.assert_rejected(bytes([DW_LNS.advance_pc, 0x80]))
        self.assert_rejected(bytes([DW_LNS.set_file, 0x80]))
        self.assert_rejected(bytes([DW_LNS.set_column, 0x80]))

    def test_truncated_sleb128_advance_line(self):
        self.assert_rejected(bytes([DW_LNS.advance_line, 0x80]))

    def test_truncated_fixed_advance_pc_uint16(self):
        # fixed_advance_pc consumes a uint16; only one byte is present.
        self.assert_rejected(bytes([DW_LNS.fixed_advance_pc, 0x01]))

    def test_truncated_set_isa_uleb128(self):
        # set_isa is opcode 0x0c and is a standard opcode only when
        # opcode_base exceeds it.
        self.assert_rejected(
            bytes([DW_LNS.set_isa, 0x80]),
            opcode_base=14,
            standard_lengths=STD_LENS_14)

    def test_truncated_extended_instruction_length(self):
        # The zero escape followed by an unterminated ULEB128 length crosses
        # the unit boundary before the extended opcode can be read.
        self.assert_rejected(b'\x00\x80')

    def test_missing_extended_opcode(self):
        # Length byte present, but the extended opcode byte itself is cut off.
        self.assert_rejected(b'\x00\x01')

    def test_truncated_set_address_operand(self):
        # set_address needs a 4-byte target address; only two are present.
        self.assert_rejected(b'\x00\x05\x02\x01\x02')

    def test_truncated_set_discriminator_operand(self):
        self.assert_rejected(b'\x00\x02\x04\x80')

    def test_truncated_define_file_payload(self):
        # The declared define_file body ends in the middle of the file name
        # and its trailing ULEB128 fields.
        self.assert_rejected(b'\x00\x02\x03\x61')

    def test_invalid_standard_opcode_raises_dwarf_error(self):
        # With opcode_base 14, opcode 13 is a standard opcode slot that has
        # no defined semantics and reaches the invalid-opcode error branch.
        line_program = make_line_program(
            b'\x0d', opcode_base=14, standard_lengths=STD_LENS_14)
        with self.assertRaises(DWARFError):
            line_program.get_entries()


class TestExtendedOpcodeSkipping(unittest.TestCase):
    """Unknown extended opcodes are skippable, unlike malformed input."""

    def test_unknown_extended_opcode_is_skipped(self):
        # Extended opcode 0x21 is not assigned by the DWARF standard. Its
        # length is valid, so the decoder must skip the two payload bytes and
        # continue decoding the rest of the program without an entry.
        line_program = make_line_program(
            b'\x00\x03\x21\xAA\xBB' + VALID_PROGRAM)
        entries = line_program.get_entries()

        commands = [entry.command for entry in entries]
        self.assertNotIn(0x21, commands)
        self.assertIn(DW_LNE.end_sequence, commands)
        # The well-formed part of the program still maps normally.
        copy_states = [
            entry.state for entry in entries if entry.state is not None]
        self.assertEqual(copy_states[0].address, 0x1000)

    def test_skipped_unknown_opcode_does_not_reset_state(self):
        # Skipping must behave like an old-state instruction: registers keep
        # their values for the following copy.
        program = (
            bytes([DW_LNS.negate_stmt])
            + b'\x00\x03\x21\x77\x88'          # unknown extended opcode
            + bytes([DW_LNS.copy])
            + b'\x00\x01\x01'
        )
        line_program = make_line_program(program)
        entries = line_program.get_entries()
        copy_entry = next(
            entry for entry in entries
            if entry.command == DW_LNS.copy)
        # default_is_stmt is 1; a single negate_stmt flips it to False and the
        # skipped extended opcode must not touch the register.
        self.assertFalse(copy_entry.state.is_stmt)

    def test_unknown_extended_opcode_overrunning_unit(self):
        # A valid-looking length that points past the unit end moves the
        # stream to EOF; decoding terminates cleanly without an entry or an
        # exception, and the unit simply contributes no rows.
        line_program = make_line_program(b'\x00\x05\x21\xAA\xBB')
        self.assertEqual(line_program.get_entries(), [])


class TestLineProgramStateIsolation(unittest.TestCase):
    """Line state and header file tables must not leak across sequences."""

    def test_end_sequence_resets_registers_within_unit(self):
        # The first sequence sets file 7; after end_sequence the second
        # sequence must start from the register defaults (file 1, line 1).
        program = (
            bytes([DW_LNS.set_file]) + encode_uleb128(7)
            + b'\x00\x05\x02' + (0x2000).to_bytes(4, 'little')
            + bytes([DW_LNS.copy])
            + b'\x00\x01\x01'                          # end_sequence
            + b'\x00\x05\x02' + (0x3000).to_bytes(4, 'little')
            + bytes([DW_LNS.copy])
            + b'\x00\x01\x01'
        )
        rows = [
            entry.state for entry in make_line_program(program).get_entries()
            if entry.state is not None]

        self.assertEqual(rows[0].file, 7)
        self.assertEqual(rows[0].address, 0x2000)
        self.assertTrue(rows[1].end_sequence)
        self.assertEqual(rows[2].file, 1)
        self.assertEqual(rows[2].line, 1)
        self.assertEqual(rows[2].address, 0x3000)

    def test_define_file_only_mutates_own_header(self):
        define_body = b'xf.c\x00' + b'\x00\x00\x00'
        program = (
            b'\x00' + encode_uleb128(1 + len(define_body))
            + bytes([DW_LNE.define_file]) + define_body
            + VALID_PROGRAM
        )
        line_program = make_line_program(program)
        before = len(line_program.header['file_entry'])
        line_program.get_entries()
        after = len(line_program.header['file_entry'])

        self.assertEqual(after, before + 1)
        self.assertEqual(line_program.header['file_entry'][-1].name, b'xf.c')


def make_dwarfinfo(debug_line_bytes):
    """Wrap raw .debug_line bytes in a minimal DWARFInfo context."""
    return DWARFInfo(
        config=DwarfConfig(
            little_endian=True, default_address_size=4, machine_arch='x86'),
        debug_info_sec=None,
        debug_aranges_sec=None,
        debug_abbrev_sec=None,
        debug_frame_sec=None,
        eh_frame_sec=None,
        debug_str_sec=None,
        debug_loc_sec=None,
        debug_ranges_sec=None,
        debug_line_sec=DebugSectionDescriptor(
            io.BytesIO(debug_line_bytes),
            '__debug_line', None, len(debug_line_bytes), 0),
        debug_pubtypes_sec=None,
        debug_pubnames_sec=None,
        debug_addr_sec=None,
        debug_str_offsets_sec=None,
        debug_line_str_sec=None,
        debug_loclists_sec=None,
        debug_rnglists_sec=None,
        debug_sup_sec=None,
        gnu_debugaltlink_sec=None,
        debug_types_sec=None)


def rows_of(line_program):
    """Return the state-carrying rows decoded from a line program."""
    return [
        entry.state for entry in line_program.get_entries()
        if entry.state is not None]


class TestInterleavedUnitIsolation(unittest.TestCase):
    """A malformed unit must not affect neighboring well-formed units."""

    def setUp(self):
        # Two distinct well-formed units followed by a malformed unit placed
        # at the real end of the section, so its truncated operand genuinely
        # hits the section boundary instead of borrowing the next header.
        self.good_unit_1 = build_line_unit(VALID_PROGRAM)
        self.good_unit_2 = build_line_unit(
            VALID_PROGRAM, files=((b'other.c', 1, 0, 0),))
        self.bad_unit = build_line_unit(
            bytes([DW_LNS.advance_pc, 0x80]))  # truncated ULEB128

        self.offset_1 = 0
        self.offset_2 = len(self.good_unit_1)
        self.offset_bad = self.offset_2 + len(self.good_unit_2)
        section = self.good_unit_1 + self.good_unit_2 + self.bad_unit

        self.dwarfinfo = make_dwarfinfo(section)

    def test_good_units_map_independently_before_failure(self):
        program_1 = self.dwarfinfo._parse_line_program_at_offset(
            self.offset_1, STRUCTS)
        program_2 = self.dwarfinfo._parse_line_program_at_offset(
            self.offset_2, STRUCTS)

        self.assertEqual(rows_of(program_1)[0].address, 0x1000)
        self.assertEqual(rows_of(program_2)[0].address, 0x1000)
        # File tables come from each unit's own header and never mix.
        self.assertEqual(
            [entry.name for entry in program_1.header['file_entry']],
            [b'ar.c'])
        self.assertEqual(
            [entry.name for entry in program_2.header['file_entry']],
            [b'other.c'])
        self.assertIsNot(program_1, program_2)

    def test_error_is_confined_to_the_malformed_unit(self):
        # Decode the good units first, then hit the malformed one.
        good_program = self.dwarfinfo._parse_line_program_at_offset(
            self.offset_1, STRUCTS)
        self.assertEqual(rows_of(good_program)[0].address, 0x1000)

        with self.assertRaises(ELFParseError):
            self.dwarfinfo._parse_line_program_at_offset(
                self.offset_bad, STRUCTS).get_entries()

        # The previously decoded unit is untouched by the failure: same cached
        # object and identical address-to-source mapping.
        self.assertIs(
            self.dwarfinfo._parse_line_program_at_offset(
                self.offset_1, STRUCTS),
            good_program)
        self.assertIs(
            self.dwarfinfo._parse_line_program_at_offset(
                self.offset_1, STRUCTS).get_entries(),
            good_program.get_entries())
        self.assertEqual(rows_of(good_program)[0].address, 0x1000)

    def test_malformed_unit_keeps_failing_without_poisoning_cache(self):
        # A first failure must not install a usable mapping that later calls
        # could mistake for valid data.
        for _ in range(2):
            bad_program = self.dwarfinfo._parse_line_program_at_offset(
                self.offset_bad, STRUCTS)
            with self.assertRaises(ELFParseError):
                bad_program.get_entries()

        # Both good units still resolve through the cache to stable mappings.
        program_1 = self.dwarfinfo._parse_line_program_at_offset(
            self.offset_1, STRUCTS)
        program_2 = self.dwarfinfo._parse_line_program_at_offset(
            self.offset_2, STRUCTS)
        self.assertEqual(rows_of(program_1)[0].address, 0x1000)
        self.assertEqual(rows_of(program_2)[0].address, 0x1000)
        self.assertEqual(
            self.dwarfinfo._parse_line_program_at_offset(
                self.offset_2, STRUCTS),
            program_2)

    def test_mapping_stable_across_repeated_decodes(self):
        # Repeated access to a unit must return the same decoded matrix and
        # the same source location for a given address.
        program = self.dwarfinfo._parse_line_program_at_offset(
            self.offset_2, STRUCTS)
        first_entries = program.get_entries()
        second_program = self.dwarfinfo._parse_line_program_at_offset(
            self.offset_2, STRUCTS)
        # The line table cache hands back the same program and the decoded
        # matrix is itself cached, so no re-decoding happens.
        self.assertIs(second_program, program)
        self.assertIs(second_program.get_entries(), first_entries)

        first = rows_of(program)
        second = rows_of(second_program)
        for row_a, row_b in zip(first, second):
            self.assertIs(row_a, row_b)
            self.assertEqual(row_a.address, row_b.address)
            self.assertEqual(row_a.line, row_b.line)
            self.assertEqual(row_a.file, row_b.file)


if __name__ == '__main__':
    unittest.main()
