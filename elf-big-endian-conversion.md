# Big-endian ELF：文件头、节表、符号、重定位与 DWARF 地址的数值转换审计

本文针对 pyelftools 中「原始字节 → 内部 Python 数值」的全链路做一次大端（MSB）专项审计。
目标是回答三个问题：

1. 32 位 / 64 位大端文件的文件头与节表能否被正确解析、正确寻址；
2. 符号值、重定位数值、DWARF 地址（含源码行号）是否在字节序切换、数值宽度、有符号性三个维度上都与逻辑值一致；
3. 若发现缺陷，如何用可重复的大小端对照样本区分「损坏输入」与「实现缺陷」，并在修复时保持现有小端结果与异常边界。

审计方法：以独立实现的参考解析器（`struct` 直接按 `EI_DATA` 解释）和 GNU readelf（`arm-none-eabi-readelf`，可处理任意机器）作为 oracle，
对仓库中已有的天然大端样本，以及由生成器产出的**同逻辑内容、两种字节序**的对照样本做逐字段比对。

---

## 1. 解析路径总览

### 1.1 两处「字节序决策点」

字节序在整条链路中只被确定一次，之后以两种形式向下传播：

| 决策点 | 位置 | 行为 |
| --- | --- | --- |
| 原始 `e_ident` 探测 | `elftools/elf/elffile.py:665` `_identify_file()` | 直接读字节，`\x01`→LE，`\x02`→BE，其它抛 `ELFError(f'Invalid EI_CLASS/EI_DATA …')` |
| 结构体工厂 | `elftools/elf/structs.py:107` `create_basic_structs()` | LE 用 `U*Int*`，BE 用 `B*Int*` |
| DWARF 结构体工厂 | `elftools/dwarf/structs.py:182` `_create_structs()` | 同上，且按 `dwarf_format`/`address_size` 再选宽度 |

`_identify_file()` 特意不经过 `ELFStructs`——此时还不知道格式，这与 ELF 规范「`e_ident` 与字长/字节序无关」的设计一致，是正确的分层。

### 1.2 结构体工厂的两张表

`elftools/elf/structs.py:111-130` 是全库最关键的「数值宽度 + 有符号性」映射：

```python
if self.little_endian:
    self.Elf_byte   = ULInt8
    self.Elf_half   = ULInt16
    self.Elf_word   = ULInt32
    self.Elf_word64 = ULInt64
    self.Elf_addr   = ULInt32 if self.elfclass == 32 else ULInt64
    self.Elf_offset = self.Elf_addr
    self.Elf_sword  = SLInt32
    self.Elf_xword  = ULInt32 if self.elfclass == 32 else ULInt64
    self.Elf_sxword = SLInt32 if self.elfclass == 32 else SLInt64
else:
    self.Elf_byte   = UBInt8
    self.Elf_half   = UBInt16
    self.Elf_word   = UBInt32
    self.Elf_word64 = UBInt64
    self.Elf_addr   = UBInt32 if self.elfclass == 32 else UBInt64
    self.Elf_offset = self.Elf_addr
    self.Elf_sword  = SBInt32
    self.Elf_xword  = UBInt32 if self.elfclass == 32 else UBInt64
    self.Elf_sxword = SBInt32 if self.elfclass == 32 else SBInt64
```

这两张表**对称**：每个 LE 名字都有唯一的 BE 对应物，宽度与符号性完全一致。`U*`/`B*` 宏只是
`FormatField(name, "<"/">", fmtchar)`（`elftools/construct/macros.py:228-303`），
底层由 `struct.Struct(endianness + formatchar)` 完成真正的字节反转（`elftools/construct/core.py:4, 387`）。

已核实的两处**风险点不存在**：

* `Elf_sword` 在 LE/BE 两侧都固定为 32 位（见上表），不随 `elfclass` 变化——符合 `Elf32_Sword` 的规范。
* `Elf_xword` 在 ELF32 上取 32 位、在 ELF64 上取 64 位；`sh_flags`、`sh_size`、`sh_addralign`、
  `sh_entsize`、`p_filesz/p_memsz/p_align` 都通过它取宽度，因此**节表宽度与 ELF class 绑定，与字节序无关**。
  实验确认：ELF32 的 `Elf_Shdr.sizeof() == 40`，ELF64 的为 64，BE 与 LE 相同（见 §5.1）。

### 1.3 从字节到内部数值的四个转换层

```
raw bytes
  │  (1) FormatField / struct.Struct           ← 字节序在这里生效
  ▼
int（宽度正确、符号性正确）
  │  (2) Enum / BitStruct / Value 适配器        ← 符号名、位域、合成字段
  ▼
Container / 命名元组
  │  (3) 偏移算术（sh_offset + n*sh_entsize …） ← 宽度在这里生效
  ▼
stream 定位
  │  (4) DWARF 语义翻译（dwarf_format / address_size / 版本）
  ▼
源码行号、地址、符号值
```

§3 与 §4 的缺陷集中在 **(2) 与 (4)**；而 **(1) 与 (3) 在本次审计的语料上全部正确**。

---

## 2. 32 位与 64 位文件头、节表的结构定义

### 2.1 文件头

`elftools/elf/structs.py:171-195` `_create_ehdr()`：

```python
self.Elf_word('e_version'), self.Elf_addr('e_entry'),
self.Elf_offset('e_phoff'), self.Elf_offset('e_shoff'),
self.Elf_word('e_flags'), self.Elf_half('e_ehsize'),
self.Elf_half('e_phentsize'), self.Elf_half('e_phnum'),
self.Elf_half('e_shentsize'), self.Elf_half('e_shnum'),
self.Elf_half('e_shstrndx'),
```

* 宽度随 class 变化的是 `e_entry / e_phoff / e_shoff`（`Elf_addr/Elf_offset`：32→4 字节，64→8 字节）；
* `e_flags` 永远是 32 位无符号（规范如此），不随 class 变化——`elffile.py:1001` 的
  `e_flags & 0x80000000` 判 DSPIC30F phantom bytes，在 BE 下同样成立；
* `e_type / e_machine / e_ehsize / e_shentsize / e_shnum / e_shstrndx` 是 `Elf_half`，两种 class 下都是 16 位。

`e_ident` 用 `Array(4, Elf_byte('EI_MAG'))` + 四个 `Enum(Elf_byte(...))`，8 位无符号，与字节序无关（正确）。

### 2.2 节表

`elftools/elf/structs.py:254-265` `_create_shdr()`：

```python
self.Elf_word('sh_name'), Enum(self.Elf_word('sh_type'), ...),
self.Elf_xword('sh_flags'), self.Elf_addr('sh_addr'),
self.Elf_offset('sh_offset'), self.Elf_xword('sh_size'),
self.Elf_word('sh_link'), self.Elf_word('sh_info'),
self.Elf_xword('sh_addralign'), self.Elf_xword('sh_entsize'),
```

字段顺序与 `Elf32_Shdr` / `Elf64_Shdr` 完全一致，`sh_type` 的枚举字典按 `e_machine` 切换
（`_create_shdr()` 中 ARM / AARCH64 / AMD64 / MIPS / RISCV 五套），**这决定了 `sh_type` 有时返回字符串、有时返回整数**，
后文 §3.4 的对照脚本必须区分这两种情况才能公平比较。

### 2.3 节表定位

`elftools/elf/elffile.py:695-701` `_section_offset()`：

```python
shentsize = self['e_shentsize']
if self['e_shoff'] > 0 and shentsize < self.structs.Elf_Shdr.sizeof():
    raise ELFError(f'Too small e_shentsize: {shentsize}')
return self['e_shoff'] + n * shentsize
```

`struct_parse` 的 seek 在 `elftools/common/utils.py:47-62`，`OverflowError/ValueError` 被统一转成 `ELFParseError`，
`_get_section_header()`（`elffile.py:724-736`）再用 `stream_pos > stream_len` 拦截越界。这套边界是所有后续寻址的安全网。
扩展编号（`e_shnum == 0` 时真实数量在 section 0 的 `sh_size`；`e_shstrndx == SHN_XINDEX` 时真实索引在
section 0 的 `sh_link`）的实现在 `num_sections()`（`elffile.py:150-166`）与 `get_shstrndx()`（`elffile.py:639-651`），
用的都是 `Elf_xword('sh_size')` 与 `Elf_word('sh_link')`，宽度正确。

---

## 3. 符号值、重定位数值的转换

### 3.1 符号

`elftools/elf/structs.py:354-385` `_create_sym()` 对 32/64 位用**不同的字段顺序**：

```python
# 32 位：st_name(word), st_value(addr), st_size(word), st_info, st_other, st_shndx(half)
# 64 位：st_name(word), st_info, st_other, st_shndx(half), st_value(addr), st_size(xword)
```

这与 `Elf32_Sym`（16 字节）/ `Elf64_Sym`（24 字节）一致。`st_value` 在 32 位上是 `Elf_addr`（4 字节），
在 64 位上是 8 字节；`st_size` 在 32 位上是 `Elf_word`（4 字节），64 位上是 `Elf_xword`（8 字节）。

`st_info` / `st_other` 是 `BitStruct('st_info', Enum(BitField('bind', 4), ...), Enum(BitField('type', 4), ...))`：

* `BitField` 走 `BitIntegerAdapter`（`elftools/construct/adapters.py:59-93`），默认 `swapped=False`、
  也就是**按位流的大端顺序**解读；
* `Bitwise` 把字节展开成「MSB 在前」的位串（`elftools/construct/lib/binary.py:4-27` `int_to_bin`）。

因此 `st_info` 的 `bind` 是**高位半字节**、`type` 是**低位半字节**，与 ELF 规范 `ELF64_ST_BIND/ELF64_ST_TYPE`
（对 1 字节的 `st_info` 而言字节序无关）一致。`st_info` 是单字节字段，**字节序不参与**，这是它能用位流实现而不出错的原因。

`st_shndx` 是 `Enum(Elf_half, ENUM_ST_SHNDX)`，`_default_=Pass`（`elftools/elf/enums.py:503-508`），
所以未知 index 原样返回整数、`SHN_UNDEF/HSN_ABS/SHN_COMMON` 返回字符串。BE 与 LE 行为一致（实测见 §5）。

### 3.2 重定位

`elftools/elf/structs.py:281-338` `_create_rel()` 分三条路径：

```python
if self.elfclass == 32:
    fields = [Elf_xword('r_info'),
              Value('r_info_sym',  lambda ctx: (ctx['r_info'] >> 8) & 0xFFFFFF),
              Value('r_info_type', lambda ctx:  ctx['r_info'] & 0xFF)]
elif self.e_machine == 'EM_MIPS':        # ELF64 MIPS 非标准布局
    fields = [Elf_word('r_sym'), Elf_byte('r_ssym'), Elf_byte('r_type3'),
              Elf_byte('r_type2'), Elf_byte('r_type'),  ...Value 合成...]
else:                                    # 其它 ELF64
    fields = [Elf_xword('r_info'),
              Value('r_info_sym',  lambda ctx: (ctx['r_info'] >> 32) & 0xFFFFFFFF),
              Value('r_info_type', lambda ctx:  ctx['r_info'] & 0xFFFFFFFF)]
```

**关键设计**：`r_info` 先作为一个整体整数按正确字节序读入，**之后才**用移位拆 sym/type。
这是正确的做法——如果改成「按字节切片再拼」，大端与小端会得到不同的位段。绝对地址 `r_offset` 用 `Elf_addr`
（32 位 4 字节、64 位 8 字节），加数 `r_addend` 用 `Elf_sxword`（**有符号**，32 位 4 字节 / 64 位 8 字节），符号性在两侧都对。

MIPS64 的 `Value('r_info', ...)` 把 4 个字段重新拼回一个伪 `r_info`（`structs.py:310-315`），
拼装方式与读取方式在逻辑上对称，且都是整数运算，因此与字节序无关。

### 3.3 重定位的应用（`elftools/elf/relocation.py:322-447`）

1. `sym_value = symtab.get_symbol(...)['st_value']`（已按 §3.1 正确解码）；
2. 依据 `recipe.bytesize` 选择读写宽度：`4 → Elf_word`、`8 → Elf_word64`、`1 → Elf_byte`、`2 → Elf_half`；
   **这些选择只依赖 `bytesize`，与字节序无关**——但因为 `Elf_*` 本身已按字节序配置，读写两端自动一致；
3. `relocated_value % (2 ** (recipe.bytesize * 8))`（`relocation.py:446`）截断后 `build_stream` 写回。
   `%` 而非掩码，对负的 relocated value 也给出正确的无符号回绕，BE/LE 相同。

没有任何硬编码 `'<'`/`'>'`（§5.4 扫描确认）。`_do_apply_uleb128_relocation()`（`relocation.py:449-475`）
走 ULEB128，本身与字节序无关。

### 3.4 天然大端语料的逐字段对照

用独立 oracle（直接 `struct.unpack_from('>…')`）与 pyelftools 逐字段比对，覆盖 file header、
节表全部字段、`.symtab`/`.dynsym` 全部符号、`SHT_REL`/`SHT_RELA` 全部条目：

| 文件 | class / 机器 | 结果 |
| --- | --- | --- |
| `mips64-relocs-be.o.elf` | ELF64 / MIPS | 全部一致（含 MIPS64 非标准 rela 布局） |
| `mips64-relocs-le.o.elf` | ELF64 / MIPS | 全部一致（同一逻辑内容的 LE 孪生） |
| `simple_armeb_gcc.o.elf` | ELF32 / ARM | 全部一致 |
| `simple_mips_gcc.o.elf` | ELF32 / MIPS | 全部一致（`.rel.debug_*`） |
| `s390x-relocs.o.elf` | ELF64 / S390 | 全部一致（`.rela.debug_*`） |
| `powerpc-dynamic.so.elf` | ELF32 / PPC | 全部一致 |
| `aarch64_be_gnu_hash.so.elf` | ELF64 / AARCH64 | 全部一致 |
| `exe_solaris32/64_cc.sparc.elf` | ELF32/64 / SPARC | 全部一致 |
| `core_linux32_qemu_mips.elf` | ELF32 / MIPS，**无节表** | 节表路径不适用；PT_NOTE 段正常产出 `NT_PRSTATUS/NT_PRPSINFO/NT_AUXV` |

`mips64-relocs-be.o.elf` 与 `mips64-relocs-le.o.elf` 是仓库里天然的**同源大小端孪生**
（同一 `.c` 编译两种字节序），它们全部字段一致，是最强的「字节序不影响结果」证据：

```
sec2 (SHT_RELA) rel0: be = 20/11/ssym=0/t3=5/t2=24/type=7/addend=0
                      le = 20/11/ssym=0/t3=5/t2=24/type=7/addend=0   ← 完全相同
```

DPI 细节：对照脚本最初把 MIPS64 的 rela 当成通用 `Elf64_Rela`，得到「pyelftools 错误」的假象；
修正 oracle 为 MIPS64 布局（`r_offset(8) r_sym(4) r_ssym(1) r_type3(1) r_type2(1) r_type(1) r_addend(8)`）后两侧一致。
手写字节验证：BE 条目 `00…14 0000000b 00 05 18 07 …` 与 LE 条目 `14 00000000 0000000b 00 05 18 07 …`
解码出同一组 `(r_offset=20, r_sym=11, ssym=0, type3=5, type2=24, type=7, addend=0)`。
这正说明**必须先确认样本遵循哪一套 ABI，再判断实现对错**。

### 3.5 重定位应用结果的字节级对照

对 `s390x-relocs.o.elf` 的 `.rela.debug_info` / `.rela.debug_aranges` / `.rela.debug_line`，
用 oracle 手工应用 `R_390_64` / `R_390_32` 后，与 `RelocationHandler.apply_section_relocations()` 的输出**逐字节相同**：

```
OK .rela.debug_info    -> .debug_info     8 relocs
OK .rela.debug_aranges -> .debug_aranges  2 relocs
OK .rela.debug_line    -> .debug_line     1 relocs
```

### 3.6 gnu hash / version / 动态段

* `elftools/elf/hash.py:163,195` 是全库**唯一**两处手工 `struct.unpack` 的地方，且都写成
  `'<I' if little_endian else '>I'`，是正确的条件化实现。对 `aarch64_be_gnu_hash.so.elf` 的
  `.gnu.hash` / `.hash` / `.dynamic`，与手工解码一致（`nbuckets=2, symoffset=7, bloom_size=1, bloom_shift=6`；
  `buckets=[7,8]`；`bloom[0]=0x100080000400000`；链字 `0xf5e615b9, 0xf5e615ab`）。
* `-V` 版本表、`.dynamic` 的 `d_tag/d_val` 与 readelf 的数值差异仅为**格式化**（前导零宽度、`(SYMINSZ)` 后缀等），
  不是数值错误（§5.5 已用规范化比较确认）。
* `.ARM.attributes`（`elftools/elf/structs.py:569-584`）的 subsection 长度在 `Elf_Attr_Subsection_Header` 里用
  `Elf_word`，在 BE 下 `simple_armeb_gcc.o.elf` 的 `'TAG_FILE 14'`、`'TAG_CPU_NAME "6"'` 与
  `arm-none-eabi-readelf -A` 完全一致。

---

## 4. DWARF 地址、行号与 `dwarf_format` 的宽度转换

### 4.1 三个彼此独立的「宽度」维度

DWARF 的数值宽度由**三个彼此独立**的参数决定，混淆它们是本类缺陷的主要来源：

| 参数 | 决定字段 | 来源 |
| --- | --- | --- |
| `little_endian` | 所有多字节字段的字节序 | 容器文件 `EI_DATA` |
| `dwarf_format`（32/64） | `Dwarf_offset`、`Dwarf_length`、initial length 字段 | **每个 unit/set 自己的 initial length** |
| `address_size`（4/8） | `Dwarf_target_addr`（`DW_FORM_addr`、`DW_OP_addr`、`DW_CFA_set_loc` …） | **每个 CU header 的 `address_size`**，或容器 elfclass |

`elftools/dwarf/structs.py:182-210` 对三者分别建表，`DwarfStructs` 以
`(little_endian, dwarf_format, address_size, dwarf_version)` 为 key 缓存（`structs.py:139,161-175`）——
缓存键包含全部四个维度，不会跨格式复用错对象。这是正确的。

### 4.2 正确处理的动态宽度路径

`elftools/dwarf/dwarfinfo.py:571-616` `_parse_CU_at_offset()`：

```python
initial_length = struct_parse(self.structs.the_Dwarf_uint32, …, offset)
dwarf_format = 64 if initial_length == 0xFFFFFFFF else 32
cu_structs = DWARFStructs(..., dwarf_format=dwarf_format, address_size=4, dwarf_version=2)  # 临时
cu_header  = struct_parse(cu_structs.Dwarf_CU_header, …)
cu_structs = DWARFStructs(..., dwarf_format=dwarf_format,
                          address_size=cu_header['address_size'],
                          dwarf_version=cu_header['version'])   # 正式
```

先读 4 字节判定格式，再按该格式重读头部，最后用头部的 `address_size` 重建 structs。**两阶段重建**是正确做法，
`0xFFFFFFFF` 哨兵本身就是 32 位无符号值，与字节序无关。

`_InitialLengthAdapter`（`elftools/dwarf/structs.py:632-645`）：
`obj.first < 0xFFFFFF00` 视为 32 位、`== 0xFFFFFFFF` 视为 64 位、其余报错——与规范 §7.4 一致。

### 4.3 地址与行号

* `Dwarf_target_addr` 由 `address_size` 选宽度（`dwarf/structs.py:191-192,205-206`），`DW_FORM_addr`、
  `DW_OP_addr`、`DW_CFA_set_loc`、`.debug_rnglists` 的 `DW_RLE_base_address` 等都用它；
* `.debug_aranges` 的地址用 `_get_addr_size_struct()`（`dwarf/aranges.py:134-142`）按 set 头里的
  `address_size` 选 `Dwarf_uint32/uint64`，在 BE 下正确（实测 `s390x-relocs.o.elf` 得到 `0x0 / 0x64`）；
* 行号 `LineState.address` 是 `state.address += address_addend` 的纯整数累加（`lineprogram.py:184,233,259,265`），
  其中 `DW_LNE.set_address` 用 `Dwarf_target_addr`（`lineprogram.py:204-207`）；
  `line_base` 用 `Dwarf_int8`（有符号），两侧一致。

天然大端 DWARF 样本与 GNU readelf 的 `decodedline` 输出**行号与地址逐行一致**：

```
s390x-relocs.o.elf:   0→13, 0x18→14, 0x22→14, 0x32→15, 0x3e→15, 0x48→15, 0x56→16   (与 readelf 相同)
simple_mips_gcc.o.elf:0→13, 0x1c→14, 0x2c→16, 0x38→17, 0x80→16, 0x90→16 …          (与 readelf 相同)
aarch64_be_gnu_hash.so.elf: 0x4d0→63, 0x4d4→64 … (与 readelf 相同)
```

### 4.4 缺陷 A：`DW_FORM_strx4` 被读成 8 字节（宽度错误）

`elftools/dwarf/structs.py:369`：

```python
'DW_FORM_strx4': self.Dwarf_uint64(''),        # 规范：4 字节索引
'DW_FORM_addrx4': self.the_Dwarf_uint32,       # 对照：4 字节
```

DWARF5 的元素编码表（第 7.5.5 节 “DW_FORM_* 编码”，Table 7.5/7.6）规定 `DW_FORM_strx1/2/3/4`
的宽度分别为 1/2/3/4 字节，与 `DW_FORM_addrx1..4` 一一对应。
代码里 `addrx4` 是 4 字节而 `strx4` 是 8 字节，**二者不一致**，`strx4` 的宽度是错的。

这是**与字节序无关的宽度缺陷**，但在大端上表现不同（见 §5.3 实测）：

```
DWARF32 LE strx4 sizeof=8  解析 4 字节索引 0x01020304 → 0xcdab01020304   （把小端后续字节并入）
DWARF32 BE strx4 sizeof=8  解析 4 字节索引 0x01020304 → 0x1020304abcd0000 （把大端后续字节并入）
```

影响：
1. DIE 解析器会**多吃 4 字节**，导致该属性之后的所有属性整体错位——`decl_line` 之类紧随其后的字段被读成
   别的属性的内容，进而**源码行号错**（DIE 里的 `DW_AT_decl_line` 被污染，`lineprogram` 里 `file_entry` 被污染）；
2. 若 DIE 之后还有足够字节，**不会抛异常**，只是静默给出错误行号/错误字符串索引——这类缺陷最难发现；
3. 若正好读到 section 末尾，抛 `ELFParseError: expected read length 8, found N`，看起来像「损坏输入」，
   实为实现缺陷。

实测（`/tmp/be_audit/probe_strx4_silent.py`，构造合法 CU：`name:strx4, decl_line:data2`）：

```
LE: DW_AT_name raw=180388626439 (spec: 7)   DW_AT_decl_line=0 (spec: 42)  DIE size=11 (spec: 7)
BE: DW_AT_name raw=30067523584  (spec: 7)   DW_AT_decl_line=0 (spec: 42)  DIE size=11 (spec: 7)
```

两侧都错，**且错误值取决于字节序**——这正是「字节序 + 宽度」耦合缺陷的典型症状。

> 复核痕迹：仓库内 `test/` 没有任何 `strx4` 用例（`grep -rn strx4 test/` 为空），
> 因此现有测试套件（153 passed）无法捕获它。

### 4.5 缺陷 B：`.eh_frame` 的 CIE_pointer 反位移在 64 位 DWARF 格式下少算 4 字节

`elftools/dwarf/callframe.py:284-293`：

```python
if self.for_eh_frame:
    cie_displacement: int = fde_header['CIE_pointer']
    cie_offset: int = (fde_offset + entry_structs.dwarf_format // 8
                  - cie_displacement)
```

CIE_pointer 字段的**起始位置**是 initial length 字段之后：32 位格式下偏移 `fde_offset + 4`，
64 位格式下偏移 `fde_offset + 12`。代码用 `dwarf_format // 8` 得到 `32//8 = 4`（正确）、
`64//8 = 8`（**错误，应为 12**）。用 `initial_length_field_size()` 才是正确写法。

实测（`/tmp/be_audit/probe_cieptr.py`，同一逻辑的 32/64 格式样本）：

```
fmt=32: fde@100, CIE@40, CIE_pointer=64 → 定位到 40  (正确)
fmt=64: fde@100, CIE@40, CIE_pointer=72 → 定位到 36  (错误，规范要求 12 字节偏移)
```

`dwarf_format // 8` 恰好在小端/32 位用例上「碰巧正确」，而在 64 位格式下系统性偏移 4 字节，
会导致 CIE 定位错误、FDE 的 `initial_location/address_range` 用错 CIE 的 augmentation，最终
`.eh_frame` 解码结果错乱。字节序不改变这个错误的符号，只改变被读错的字节内容。

### 4.6 缺陷 C：`.debug_aranges` 与 `.debug_pubnames` 的 initial length 固定按 32 位

`elftools/dwarf/structs.py:402-417`：

```python
self.Dwarf_aranges_header = Struct("Dwarf_aranges_header",
    self.Dwarf_initial_length('unit_length'), self.Dwarf_uint16('version'),
    self.Dwarf_offset('debug_info_offset'), self.Dwarf_uint8('address_size'),
    self.Dwarf_uint8('segment_size'))
```

`Dwarf_initial_length` 本身能识别 `0xFFFFFFFF` 扩展，但外层 `Dwarf_offset` 与
`aranges.py:128-130` 计算下一 set 的步长时用的 `self.structs.initial_length_field_size()`，
用的是**构造 `ARanges` 时传入的、来自 `DWARFInfo.structs` 的 `dwarf_format`**（固定为 32，
`dwarfinfo.py:141-144`），而不是该 set 自己的 initial length。因此：

* 64 位格式的 set 会被按 32 位读 `debug_info_offset` → **错位 4 字节**；
* `address_size` 读到错误值（实测为 0）→ `_get_addr_size_struct()` 断言失败。

实测（`/tmp/be_audit/probe_widths.py`，legal 64 位格式 set，`unit_length = 52`、
`debug_info_offset = 0x1234`、`address_size = 8`）：

```
LE  header: pyelftools={unit_length:52, version:2, debug_info_offset:4660,  address_size:0}
           hand    ={unit_length:52, version:2, debug_info_offset:4660,  address_size:8}
    ARanges raised AssertionError
BE  header: pyelftools={unit_length:52, version:2, debug_info_offset:0,     address_size:0}
           hand    ={unit_length:52, version:2, debug_info_offset:4660,  address_size:8}
    ARanges raised AssertionError
```

`unit_length` 两侧都对（`Dwarf_initial_length` 本身能识别扩展哨兵），但后续字段整体错位 4 字节：
`address_size` 读到偏移 18 处的 0，而不是偏移 22 处的 8，于是 `_get_addr_size_struct()` 断言失败。
`debug_info_offset` 的表现最能说明「字节序耦合」：LE 下低 4 字节恰好承载了完整值，看起来**碰巧正确**；
BE 下低 4 字节全为 0，值被读成 0——**同一个宽度缺陷在两种字节序下给出不同的错误**。

同一个问题同样出现在 `NameLUT`（`.debug_pubnames`/`.debug_pubtypes`，`namelut.py:177-198`），
其 header 用 `Dwarf_offset`/`Dwarf_length`，固定按 32 位：

```
LE  pyelftools={unit_length:38, version:2, debug_info_offset:22136, debug_info_length:0}
BE  pyelftools={unit_length:38, version:2, debug_info_offset:0,     debug_info_length:22136}
    hand    ={unit_length:38, version:2, debug_info_offset:0x5678 (=22136), debug_info_length:0x30 (=48)}
    两侧均 raised ELFParseError: expected read length 4, found 2
```

用真实 ELF + GNU readelf 做 oracle（`/tmp/be_audit/samples/fmt64-be.elf`）：

```
GNU readelf:  Length 52 / Version 2 / Offset into .debug_info 0x0 / Pointer Size 8 → 地址 0x2000 len 0x40
pyelftools :  AssertionError（aranges.py:141）
```

GNU readelf 接受并正确解码，说明这是**合法输入**而非损坏输入，缺陷在实现侧。

### 4.7 缺陷 D：行程序不按自身的 initial length 重建 `DwarfStructs`

`elftools/dwarf/dwarfinfo.py:669-682` `_parse_line_program_at_offset()` 直接
`struct_parse(structs.Dwarf_lineprog_header, …)`，其中 `structs` 是调用方传入的 CU structs。
若某个 CU 的行程序使用与 CU 不同的 DWARF 格式（规范允许，initial length 是 per-set 的），
`header_length`/`Dwarf_offset` 的宽度就会错。

实测（`/tmp/be_audit/probe_linefmt.py`，CU 声明 32 位、行程序 64 位）：

```
LE line-fmt32: files=[b'lf.c']   header_length=28    (正确)
LE line-fmt64: files=[]          header_length=28    ← 文件表丢失
BE line-fmt64: files=[]          header_length=0     ← 更糟：字段完全错位
```

注意 BE 与 LE 的错法不同（`header_length` 28 vs 0），同样是字节序放大了同一宽度缺陷。

### 4.8 检查通过的部分

* `DW_FORM_addrx3` / `DW_FORM_strx3` 的 24 位字段：`UBInt24` 与 `ULInt24`
  （`elftools/common/construct_utils.py:121-146`）在 BE/LE 下分别给出 `0x10203` / `0x30201`，
  与各自的字节顺序一致（实测 §5.2）。
* `DW_FORM_ref_addr` 的宽度按 `dwarf_version` 切换（v2 用 `target_addr`、v3+ 用 `offset`，
  `dwarf/structs.py:380`）——与规范（`DW_FORM_ref_addr` 在 DWARF v2 用 address size、v3+ 用 offset size）一致，且与字节序无关。
* `st_info` / `st_other` 的 `BitStruct`：单字节字段，位流实现与字节序无关。
* 压缩节头 `Elf_Chdr`：64 位 class 多出的 `ch_reserved` 在 BE/LE 都解析为 0、`ch_size=1234`（实测 §5.2）。
* `.debug_str_offsets` / `.debug_addr` / `.debug_loclists` 的 offset 表按 `dwarf_format` 选 4/8 字节
  （`dwarf/die.py:343` 与 `dwarf/dwarf_util.py:57`），用 `cu.structs.dwarf_format`——即**每个 CU 自己的格式**，正确。

---

## 5. 可重复的大小端对照样本

所有生成器与校验脚本都在仓库外的 `/tmp/be_audit/`（不污染仓库，也不受仓库内代码影响），
`python -I` 运行以隔离 `sys.path`。产物在 `/tmp/be_audit/samples/`。

### 5.1 样本设计与为什么它能区分「损坏输入」与「实现缺陷」

生成器 `mkelf.py` 从**一份逻辑规格**（`sections()` 里的字段值、`expect` 字典）出发，
按给定 `(elfclass, little_endian, dwarf_format)` 用 `struct.pack(e+fmt)` 写字节。
同一逻辑值因此会有两套字节串，`expected.json` 记录逻辑期望：

| 样本 | class | 字节序 | DWARF 格式 | 覆盖 |
| --- | --- | --- | --- | --- |
| `elf32-le-dwarf32.elf` | 32 | LE | 32 | 基线 |
| `elf32-be-dwarf32.elf` | 32 | BE | 32 | 基线 |
| `elf64-le-dwarf32.elf` | 64 | LE | 32 | 基线 |
| `elf64-be-dwarf32.elf` | 64 | BE | 32 | 基线 |
| `elf64-le-dwarf64.elf` | 64 | LE | 64 | initial length 12 字节 |
| `elf64-be-dwarf64.elf` | 64 | BE | 64 | initial length 12 字节 |

每个样本含 `.text`、`.symtab`（含 `st_value = 0xFFFFFFFF80000000` 的高位符号）、
`.rela.text`（`r_addend = -8`，验证有符号加数）、`.debug_abbrev/info/line/str/aranges`。

**判定原则**：

* 若 LE 与 BE 两个孪生样本**都**通过 → 该路径对字节序不敏感；
* 若两个都失败 → 是**与字节序无关的实现缺陷**（如 §4.4 的宽度问题）；
* 若一个通过、一个失败 → 是**字节序相关缺陷**；
* 若只有特定**故意改坏的字节**失败 → 是**损坏输入**，且必须给出类型化异常而非静默错值。

`verify_samples.py` 对每个样本断言：`elfclass/little_endian`、全部 `st_value/st_size`、
`r_offset/r_info_sym/r_info_type/r_addend`、CU `version/address_size/dwarf_format`、
`DW_AT_name/comp_dir/low_pc/high_pc/decl_line/decl_file`、
行表 `(address, line)` 序列与 `file_entry`、aranges `(begin, length)`。全部 6 个样本 PASS：

```
PASS elf32-le-dwarf32
PASS elf32-be-dwarf32
PASS elf64-le-dwarf32
PASS elf64-le-dwarf64
PASS elf64-be-dwarf32
PASS elf64-be-dwarf64
```

这组通过说明 §1–§3 的路径（header、节表、符号、重定位、32/64 位格式、地址与行号）**没有字节序缺陷**。

### 5.2 宽度/符号性专项样本 `mkforms.py`

DWARF5 CU：`name:strx3`、`comp_dir:strx3`、`low_pc:addr`、`high_pc:data1`、`stmt_list:sec_offset`、
`language:sdata`（负值 −42）、`str_offsets_base`、`decl_line:data2`（**哨兵**，位于最后：
若前面任一字段宽度错，它必然被读错）。外加 v5 行程序（`DW_FORM_line_strp` 的目录/文件表）：

```
PASS forms-le-dwarf32    PASS forms-le-dwarf64
PASS forms-be-dwarf32    PASS forms-be-dwarf64
```

180 度对称的 3 字节字段与有符号 `sdata` 在两侧都正确。同一生成器把 `strx4` 换成 8 字节读法即复现 §4.4。

### 5.3 缺陷复现脚本

| 脚本 | 复现 | 输出要点 |
| --- | --- | --- |
| `probe_strx4.py` | `DW_FORM_strx4` 宽度 | LE 得 `0xcdab01020304`、BE 得 `0x1020304abcd0000`，均 ≠ `0x01020304` |
| `probe_strx4_silent.py` | 静默错值 | 两侧 `decl_line` 都读成 0（应为 42），DIE 多吃 4 字节 |
| `probe_cieptr.py` | eh_frame CIE_pointer | fmt=32 定位 40（对）、fmt=64 定位 36（应 40） |
| `probe_widths.py` | aranges/pubnames 64 位格式 | `address_size=0`、`debug_info_offset` 随字节序变 4660↔0 |
| `probe_linefmt.py` | 行程序 64 位格式 | `files=[]`、`header_length` LE=28 / BE=0 |
| `probe_fmt64.py` / `probe_fmt64b.py` | 同一缺陷在真实 ELF | `AssertionError` / `KeyError 'FDE_encoding'` |

### 5.4 损坏输入 vs 实现缺陷的分离实验 `probe_corrupt.py`

以 `elf64-be-dwarf32.elf` 为基线，每次只改一处字节：

```
baseline (BE, correct EI_DATA)          parsed: class=64 LE=False cu_len=49 addr_size=8
EI_DATA flipped to LE (corrupt)         raised ELFParseError: Reading section 0 at offset … past EOF 1256
EI_CLASS flipped to 32 (corrupt)        parsed ELF, but no CUs yielded
EI_DATA=3 (invalid)                     raised ELFError: Invalid EI_DATA b'\x03'
truncated section header table          raised ELFParseError: Reading section 0 at offset 552 past EOF 500
sh_size of .debug_info = huge (corrupt) raised ELFParseError: File range at offset 348 with size … exceeds file size
```

结论：**损坏输入走的是「类型化异常 + 越界检查」路径**（`ELFError`/`ELFParseError`），
不会给出看似合理的错值。而 §4.4–§4.7 的缺陷在**合法输入**上给出错值或非类型化异常
（`AssertionError`、`IndexError`、`KeyError`），两者可以清晰分开：

* 损坏输入：异常类型是 `ELFError` / `ELFParseError`，且信息包含偏移/长度；
* 实现缺陷：合法样本上出现 `AssertionError`/`IndexError`/`KeyError`/静默错值，且 LE/BE 孪生同时或对称失败。

### 5.5 与 GNU readelf 的外部对照

`arm-none-eabi-readelf` 可作为任意机器的 oracle。对 9 个天然大端样本逐一比对
`-e -s -r -d -n -V -A` 与 4 个 DWARF dump，**数值层面全部一致**，差异均为格式化：

* 前导零宽度（`0x340` vs `0x000340`）；
* 名称截断（GNU 用 `[...]`，pyelftools 用列宽截断）；
* `Machine: <unknown>`（`get_machine_arch()` 缺表项，与字节序无关）；
* 段偏移 `0x10000` vs `10000`（`_format_hex` 少一个 `0x` 前缀）；
* `core` 文件的段级 note 未在 `-n` 中输出（`display_notes` 只遍历节，而该文件无节表）；
* 杂项字符串（`(SYMINSZ)`、`Pointer Size` vs `Address size`、`View` 列）。

**唯一被确认为数值错误的**是本轮 §4.4–§4.7 的宽度缺陷；它们都不在仓库现有大端样本的触发范围内
（现有样本全是 32 位 DWARF 格式、且不含 `strx4`），因此现有 153 个测试全通过也是预期的。

---

## 6. 修复建议与如何保持现有小端结果和异常边界

### 6.1 缺陷 A：`DW_FORM_strx4`

```python
# elftools/dwarf/structs.py:369
-            'DW_FORM_strx4': self.Dwarf_uint64(''),
+            'DW_FORM_strx4': self.the_Dwarf_uint32,
```

只改宽度，不改类型族（无符号）。小端结果不变（除非有人喂过非法 8 字节 `strx4`，那种输入本就该被拒绝）；
修复后 DIE 大小回到规范值，**后续属性的错位消失**，源码行号随之正确。

回归测试：把 §5.3 的 `strx4` 样本固化成 `test/testfiles_for_unittests` 的合法 ELF，
断言 `DW_AT_name.raw_value == 7 && DW_AT_decl_line == 42 && die.size == 7`。LE/BE 两份都要。

### 6.2 缺陷 B：`.eh_frame` CIE_pointer

```python
# elftools/dwarf/callframe.py:290
-            cie_offset: int = (fde_offset + entry_structs.dwarf_format // 8
-                          - cie_displacement)
+            cie_offset: int = (fde_offset + entry_structs.initial_length_field_size()
+                          - cie_displacement)
```

`initial_length_field_size()` 对 32 位返回 4、64 位返回 12（`dwarf/structs.py:177-180`），
**32 位结果与现状完全相同**（4 == 32//8），所以现有小端 `.eh_frame` 用例逐字节不变；
只有 64 位格式样本从「错 4 字节」变为正确。

### 6.3 缺陷 C/D：per-set 的 `dwarf_format`

`.debug_aranges` / `.debug_pubnames` / `.debug_pubtypes` / 行程序的 initial length 是 **per-set / per-program** 的，
必须像 `_parse_CU_at_offset()` 那样**先探 4 字节判定格式，再用该格式重解析整个 set**。模式：

```python
first = struct_parse(structs.the_Dwarf_uint32, stream, set_offset)
fmt = 64 if first == 0xFFFFFFFF else 32
set_structs = DWARFStructs(little_endian=structs.little_endian,
                           dwarf_format=fmt, address_size=..., dwarf_version=...)
header = struct_parse(set_structs.Dwarf_aranges_header, stream, set_offset)
next_offset = set_offset + header['unit_length'] + set_structs.initial_length_field_size()
```

要点：
1. **不要**复用 `DWARFInfo.structs`（它固定 `dwarf_format=32`，见 `dwarfinfo.py:141-144`）；
2. 步长必须用**该 set 的** `initial_length_field_size()`；
3. 行程序需从 `_parse_line_program_at_offset()` 内部重建 `DwarfStructs`，
   不能用调用方传入的 CU structs 直接读 header；
4. `DWARFStructs` 已有按四元组缓存，重建不会带来额外开销。

对现有小端用例：因为仓库内所有样本都是 32 位格式，判定分支会走 `fmt == 32`，
生成的 structs 与现状等价，**输出不变**。异常边界也保持不变：
`_get_addr_size_struct()` 的 `assert addr_header_value == 8` 建议改为 `ELFParseError`/`DWARFError`
（当前对合法 64 位格式输入抛 `AssertionError`，属于非类型化异常，与 §5.4 的损坏输入路径不一致）。

### 6.4 顺带清理（非缺陷，但影响「异常边界一致性」）

* `scripts/readelf.py:1259` 在 `lineprogram['file_entry']` 为空时抛 `IndexError`；
  对合法但无文件的 v5 行程序（§4.7 修复后仍可能出现）应给出可读的 `ELFParseError` 或跳过该 CU；
* `_format_hex` 在段属性上缺 `0x` 前缀（§5.5），属格式化不一致，不影响数值；
* `get_machine_arch()` 缺 SPARC 等表项，导致 `Machine: <unknown>`，与字节序无关。

### 6.5 修复后需要守住的三个不变量

1. **小端输出不变**：所有修复只改变「依据哪个格式字段取宽度」，对 `dwarf_format == 32` 的输入
   生成完全相同的 structs；建议在修复前后对 `test/run_readelf_tests.py` 的全部语料做 diff，
   只允许出现「修复引入的新通过」。
2. **异常边界不变**：损坏输入仍需落在 `ELFError`/`ELFParseError`（`elftools/common/exceptions.py`），
   携带偏移与长度；不要用裸 `assert` 处理外部数据。§5.4 的五个用例应在修复前后给出相同异常类型。
3. **大小端对称**：任何修复都必须在 LE/BE 孪生样本上同时验证；§5 的 `verify_samples.py` /
   `verify_forms.py` 应作为回归门槛，新增缺陷 A–D 的样本后要求 8 个 LE/BE 组合全 PASS。

---

## 7. 结论

| 路径 | 结论 |
| --- | --- |
| `e_ident` 探测（`elffile.py:665`） | 正确，与字节序无关地工作 |
| 文件头 / 节表字段宽度（`structs.py:111-130`） | LE/BE 对称；`Elf_xword` 随 class 变宽、`Elf_word` 恒 32 位；实测 ELF32 40 字节、ELF64 64 字节 |
| 节表定位 `e_shoff + n*e_shentsize`（`elffile.py:695`） | 正确；`e_shentsize` 是 `Elf_half`，与字节序无关；越界有 `ELFParseError` |
| 扩展编号（`e_shnum==0`、`e_shstrndx==SHN_XINDEX`） | BE/LE 均正确 |
| 符号 `st_value/st_size`、`st_info` 位域 | 正确；32/64 字段序正确；BE/LE 一致（含 `0xFFFFFFFF80000000` 高位值） |
| 重定位 `r_info` 拆分、`r_offset`、有符号 `r_addend` | 正确；先整体读再移位，与字节序无关；MIPS64 非标准布局正确 |
| 重定位应用与回绕（`relocation.py:322-447`） | 正确；与 oracle 逐字节一致 |
| gnu hash / dynamic / versym / ARM attributes | 数值正确；`hash.py` 两处 `struct.unpack` 条件化了字节序 |
| DWARF CU 头部两阶段重建、地址、行号 | 正确；BE 样本与 GNU readelf 逐行一致 |
| **`DW_FORM_strx4`** | **缺陷（宽度 8 应 4）**，字节序耦合，静默错行号 |
| **`.eh_frame` CIE_pointer** | **缺陷（64 位格式少 4 字节）**，32 位/小端碰巧正确 |
| **`.debug_aranges` / `.debug_pubnames`** | **缺陷（固定 32 位格式）**，合法 64 位格式输入抛 `AssertionError` |
| **行程序 per-set 格式** | **缺陷（沿用 CU structs）**，64 位格式下行号/文件表错 |

总体判断：**大端不是问题本身**——字节序在单一决策点被正确捕获并对称传播，所有天然大端样本的
文件头、节表、符号值、重定位数值与 DWARF 地址都与 oracle 一致。真正的缺陷是
**DWARF 中 per-unit / per-set 的宽度（`dwarf_format`）被在若干处固定成 32 位**，
这类缺陷在 32 位格式的小端样本上「碰巧正确」，一旦遇到 64 位格式或（通过错位）大端数据就暴露，
且错误值本身会随字节序变化——这正是把「坏输入」和「坏实现」混为一谈的根源。
