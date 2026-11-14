#-------------------------------------------------------------------------------
# elftools: elf/compression.py
#
# Handling of compressed ELF section data
#
# Eli Bendersky (eliben@gmail.com)
# This code is in the public domain
#-------------------------------------------------------------------------------
from __future__ import annotations

import struct
import zlib
from typing import IO, TYPE_CHECKING, NamedTuple

from ..common.exceptions import ELFCompressionError
from ..common.utils import iter_stream_range, stream_read

if TYPE_CHECKING:
    from collections.abc import Generator, Iterable, Iterator

# GNU-style compressed sections ("zdebug") start with this magic, followed by
# the uncompressed size as a big-endian 64-bit number.
_GNU_MAGIC = b'ZLIB'
_GNU_HEADER_SIZE = len(_GNU_MAGIC) + 8

# Bound on the output of a single inflate step. Stored bytes are already read
# in bounded chunks, and no step may produce more than this no matter what size
# the compression header declares.
_CHUNK_SIZE = 64 * 1024


class CompressionInfo(NamedTuple):
    """ Location and declared size of a zlib stream stored in a section.

        type:
            The compression type, as spelled by Elf_Chdr.ch_type or by the
            GNU-style header. Only ELFCOMPRESS_ZLIB is supported.
        stored_offset, stored_size:
            The range of the container that holds the zlib stream itself, i.e.
            the section data that follows the compression header.
        uncompressed_size:
            The size the header declares for the decompressed data. It is only
            used for validation and allocation bounds, never trusted blindly.
    """
    type: str | int
    stored_offset: int
    stored_size: int
    uncompressed_size: int


def gnu_compression_info(
    stream: IO[bytes],
    offset: int,
    size: int,
) -> CompressionInfo:
    """ Parse the header of a GNU-style compressed section and return the
        location of its zlib stream.
    """
    if size < _GNU_HEADER_SIZE:
        raise ELFCompressionError(
            'Compressed section is too small for its header')
    header = stream_read(stream, offset, _GNU_HEADER_SIZE)
    magic, uncompressed_size = struct.unpack('>4sQ', header)
    if magic != _GNU_MAGIC:
        raise ELFCompressionError(f'Invalid compression type: {magic!r}')
    return CompressionInfo(
        type='ELFCOMPRESS_ZLIB',
        stored_offset=offset + _GNU_HEADER_SIZE,
        stored_size=size - _GNU_HEADER_SIZE,
        uncompressed_size=uncompressed_size)


def decompress_into(
    stream: IO[bytes],
    info: CompressionInfo,
    dest: IO[bytes],
) -> int:
    """ Write the decompressed data described by info into dest and return the
        number of bytes written.

        The stored data is read and inflated in bounded chunks, so the declared
        size never causes an up-front allocation. A truncated or corrupt stream,
        or output that does not match the declared size, raises
        ELFCompressionError; dest then may hold a prefix of the data and must
        not be used for further parsing.
    """
    _check_type(info)
    written = 0
    for inflated in _iter_inflate(_iter_stored(stream, info), info.uncompressed_size):
        dest.write(inflated)
        written += len(inflated)
    return written


def _check_type(info: CompressionInfo) -> None:
    if info.type == 'ELFCOMPRESS_ZLIB':
        return
    if isinstance(info.type, int):
        raise ELFCompressionError(f'Unknown compression type: {info.type:#0x}')
    raise ELFCompressionError(f'Unknown compression type: {info.type!r}')


def _iter_stored(
    stream: IO[bytes],
    info: CompressionInfo,
) -> Generator[bytes, None, None]:
    """ Yield the stored zlib stream in bounded chunks.
    """
    return iter_stream_range(stream, info.stored_offset, info.stored_size)


def _iter_inflate(
    chunks: Iterable[bytes],
    declared_size: int,
) -> Iterator[bytes]:
    """ Yield the decompressed bytes of a zlib stream in bounded chunks.

        At most declared_size bytes are accepted. One byte beyond that is
        requested deliberately: if it appears, the stream is larger than its
        header claims. The size of every inflate step is capped as well, so a
        corrupt or hostile stream cannot force an allocation based on the
        declared size.

        Bytes following the end of the zlib stream are ignored: they are not
        part of the decompressed data and cannot be reached through it.
    """
    decompressor = zlib.decompressobj()
    total = 0
    for chunk in chunks:
        pending = chunk
        while True:
            limit = min(declared_size - total + 1, _CHUNK_SIZE)
            try:
                inflated = decompressor.decompress(pending, limit)
            except zlib.error as e:
                raise ELFCompressionError(f'Invalid compressed data: {e}') from e
            total += len(inflated)
            if total > declared_size:
                raise ELFCompressionError(
                    f'Decompressed data is longer than the declared '
                    f'{declared_size} bytes')
            if inflated:
                yield inflated
            if decompressor.eof:
                break
            # The step may have produced output while leaving input untouched;
            # draining it needs another call with the remaining input or, once
            # all of it was consumed, with no input at all.
            pending = decompressor.unconsumed_tail
            if not pending and not inflated:
                break
        if decompressor.eof:
            break

    if not decompressor.eof:
        raise ELFCompressionError('Compressed data is truncated')
    if total != declared_size:
        raise ELFCompressionError(
            f'Decompressed data is {total} bytes long, should be '
            f'{declared_size} bytes long')
