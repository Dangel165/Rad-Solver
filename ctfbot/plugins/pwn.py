"""Pwn plugin for binary exploitation analysis."""

import struct
from ..models import Finding, Target


class PwnPlugin:
    """Analyzes binaries for exploitation vulnerabilities."""
    name = "pwn"
    category = "pwn"

    def analyze(self, target: Target, flag_patterns: list[str]) -> list[Finding]:
        """Analyze target for pwn vulnerabilities."""
        findings = []

        data = target.data
        findings.extend(self._dangerous_functions(data, flag_patterns))
        findings.extend(self._rop_gadgets(data, flag_patterns))
        findings.extend(self._binary_analysis(data, flag_patterns))
        findings.extend(self._protection_checks(data, flag_patterns))
        findings.extend(self._vulnerability_hints(data, flag_patterns))
        findings.extend(self._string_analysis(data, flag_patterns))

        return findings

    def _dangerous_functions(self, data: bytes, flag_patterns: list[str]) -> list[Finding]:
        """Detect dangerous function calls."""
        findings = []
        dangerous = {
            b'strcpy': ('Buffer overflow risk', 24),
            b'gets': ('Unbounded input - buffer overflow', 26),
            b'system': ('Command execution possible', 22),
            b'exec': ('Code execution possible', 22),
            b'sprintf': ('Format string vulnerability', 24),
            b'scanf': ('Format string vulnerability', 24),
            b'strcat': ('Buffer overflow risk', 22),
            b'memcpy': ('Potential buffer overflow', 20),
            b'printf': ('Format string vulnerability', 20),
            b'malloc': ('Memory allocation - heap exploitation', 18),
            b'free': ('Memory deallocation - use-after-free', 18),
        }

        for func, (desc, score) in dangerous.items():
            count = data.count(func)
            if count > 0:
                findings.append(Finding(
                    score=score,
                    title='Dangerous Function',
                    category=self.category,
                    detail=f'Dangerous function detected ({count}x): {desc}',
                    value=func.decode()
                ))

        return findings

    def _rop_gadgets(self, data: bytes, flag_patterns: list[str]) -> list[Finding]:
        """Detect ROP gadget patterns."""
        findings = []

        # Common ROP patterns with scores
        patterns = {
            b'\x58\xc3': ('pop rax; ret', 16),
            b'\x5b\xc3': ('pop rbx; ret', 16),
            b'\x5f\xc3': ('pop rdi; ret', 18),
            b'\x5e\xc3': ('pop rsi; ret', 18),
            b'\x5d\xc3': ('pop rbp; ret', 16),
            b'\xff\xe0': ('jmp rax', 14),
            b'\xff\xe1': ('jmp rcx', 14),
            b'\xff\xe2': ('jmp rdx', 14),
            b'\xc3': ('ret', 8),
            b'\x90': ('nop', 6),
        }

        gadget_count = 0
        for pattern, (desc, score) in patterns.items():
            count = data.count(pattern)
            if count > 0:
                gadget_count += count
                if count > 5:
                    findings.append(Finding(
                        score=score + 4,
                        title='ROP Gadget',
                        category=self.category,
                        detail=f'ROP gadget found: {desc} ({count}x) - highly exploitable',
                        value=desc
                    ))
                else:
                    findings.append(Finding(
                        score=score,
                        title='ROP Gadget',
                        category=self.category,
                        detail=f'ROP gadget found: {desc} ({count}x)',
                        value=desc
                    ))

        if gadget_count > 20:
            findings.append(Finding(
                score=26,
                title='ROP Rich',
                category=self.category,
                detail='Binary is ROP-rich - exploitation highly likely',
                value=f'Total gadgets: {gadget_count}'
            ))
        elif gadget_count > 10:
            findings.append(Finding(
                score=20,
                title='ROP Rich',
                category=self.category,
                detail='Binary is ROP-rich - exploitation likely possible',
                value=f'Total gadgets: {gadget_count}'
            ))

        return findings

    def _binary_analysis(self, data: bytes, flag_patterns: list[str]) -> list[Finding]:
        """Analyze binary format and architecture."""
        findings = []

        # ELF analysis
        if data.startswith(b'\x7fELF'):
            findings.extend(self._analyze_elf(data, flag_patterns))

        # PE analysis
        if data.startswith(b'MZ'):
            findings.extend(self._analyze_pe(data, flag_patterns))

        return findings

    def _analyze_elf(self, data: bytes, flag_patterns: list[str]) -> list[Finding]:
        """Analyze ELF binary."""
        findings = []

        try:
            # ELF header analysis
            ei_class = data[4]  # 1=32-bit, 2=64-bit
            ei_data = data[5]   # 1=little-endian, 2=big-endian
            e_machine = struct.unpack('<H' if ei_data == 1 else '>H', data[18:20])[0]

            arch_map = {
                0x03: ('x86 (32-bit)', 16),
                0x3e: ('x86-64 (64-bit)', 18),
                0x28: ('ARM', 14),
                0xb7: ('ARM64', 14),
            }

            arch, score = arch_map.get(e_machine, (f'Unknown ({e_machine})', 10))
            findings.append(Finding(
                score=score,
                title='ELF Architecture',
                category=self.category,
                detail=f'ELF architecture: {arch}',
                value=arch
            ))

            # Check for common sections
            sections = {
                b'.plt': ('PLT section found - function calls', 14),
                b'.got': ('GOT section found - potential GOT overwrite', 20),
                b'.init_array': ('init_array found - constructor hooks', 18),
                b'.fini_array': ('fini_array found - destructor hooks', 18),
                b'.dynamic': ('Dynamic linking - ASLR likely', 12),
                b'.symtab': ('Symbol table present - easier to exploit', 16),
            }

            for section, (desc, score) in sections.items():
                if section in data:
                    findings.append(Finding(
                        score=score,
                        title='ELF Section',
                        category=self.category,
                        detail=desc,
                        value=section.decode()
                    ))

        except Exception:
            pass

        return findings

    def _analyze_pe(self, data: bytes, flag_patterns: list[str]) -> list[Finding]:
        """Analyze PE binary."""
        findings = []

        try:
            # PE header offset
            if len(data) > 0x3c:
                pe_offset = struct.unpack('<I', data[0x3c:0x40])[0]
                if pe_offset < len(data) - 4:
                    if data[pe_offset:pe_offset+2] == b'PE':
                        findings.append(Finding(
                            score=16,
                            title='PE Binary',
                            category=self.category,
                            detail='Windows PE binary detected',
                            value='PE Binary'
                        ))

                        # Check for imports
                        if b'kernel32' in data or b'msvcrt' in data:
                            findings.append(Finding(
                                score=14,
                                title='PE Imports',
                                category=self.category,
                                detail='Standard library imports detected - exploitation possible',
                                value='System imports found'
                            ))

        except Exception:
            pass

        return findings

    def _protection_checks(self, data: bytes, flag_patterns: list[str]) -> list[Finding]:
        """Check for security protections."""
        findings = []

        # PIE check (ELF)
        if data.startswith(b'\x7fELF'):
            try:
                e_type = struct.unpack('<H', data[16:18])[0]
                if e_type == 3:  # ET_DYN
                    findings.append(Finding(
                        score=12,
                        title='PIE Enabled',
                        category=self.category,
                        detail='Position Independent Executable - harder to exploit',
                        value='PIE Enabled'
                    ))
                else:
                    findings.append(Finding(
                        score=18,
                        title='PIE Disabled',
                        category=self.category,
                        detail='No PIE - easier to exploit with fixed addresses',
                        value='PIE Disabled'
                    ))
            except Exception:
                pass

        # Stack canary check
        if b'__stack_chk_fail' in data or b'__stack_chk_guard' in data:
            findings.append(Finding(
                score=14,
                title='Stack Canary',
                category=self.category,
                detail='Stack canary protection detected - prevents simple buffer overflows',
                value='Stack Canary'
            ))
        else:
            findings.append(Finding(
                score=16,
                title='No Stack Canary',
                category=self.category,
                detail='No stack canary - vulnerable to buffer overflow',
                value='No Stack Canary'
            ))

        # RELRO check
        if b'.got.plt' in data:
            findings.append(Finding(
                score=12,
                title='RELRO Present',
                category=self.category,
                detail='Relocation Read-Only - prevents GOT overwrite',
                value='RELRO Present'
            ))

        return findings

    def _vulnerability_hints(self, data: bytes, flag_patterns: list[str]) -> list[Finding]:
        """Detect vulnerability hints."""
        findings = []

        hints = {
            b'%x': ('Format string vulnerability hint', 22),
            b'%s': ('Format string vulnerability hint', 22),
            b'%n': ('Format string write vulnerability hint', 24),
            b'\x90\x90\x90': ('NOP sled detected - shellcode likely', 20),
            b'\xcc\xcc\xcc': ('INT3 breakpoints - debugging code', 14),
            b'sh\x00': ('Shell string - likely execve("/bin/sh")', 18),
            b'/bin/sh': ('Shell path - likely execve', 18),
        }

        for pattern, (desc, score) in hints.items():
            count = data.count(pattern)
            if count > 0:
                findings.append(Finding(
                    score=score,
                    title='Vulnerability Hint',
                    category=self.category,
                    detail=f'{desc} ({count}x)',
                    value=pattern.decode(errors='ignore')
                ))

        # Syscall patterns
        if b'\x0f\x05' in data:  # syscall (x86-64)
            findings.append(Finding(
                score=16,
                title='Syscall',
                category=self.category,
                detail='Direct syscall detected - possible privilege escalation',
                value='syscall instruction'
            ))

        if b'\xcd\x80' in data:  # int 0x80 (x86)
            findings.append(Finding(
                score=16,
                title='Int 0x80',
                category=self.category,
                detail='Legacy syscall detected - x86 32-bit',
                value='int 0x80 instruction'
            ))

        return findings

    def _string_analysis(self, data: bytes, flag_patterns: list[str]) -> list[Finding]:
        """Analyze strings in binary for exploitation hints."""
        findings = []
        
        # Extract strings
        strings = []
        current = b''
        for byte in data:
            if 32 <= byte <= 126:
                current += bytes([byte])
            else:
                if len(current) >= 4:
                    strings.append(current.decode('ascii', errors='ignore'))
                current = b''
        
        if current and len(current) >= 4:
            strings.append(current.decode('ascii', errors='ignore'))
        
        # Check for exploitation-related strings
        exploit_keywords = ['overflow', 'buffer', 'exploit', 'vulnerability', 'pwn', 'hack', 'shell', 'root']
        for s in strings[:30]:
            s_lower = s.lower()
            if any(kw in s_lower for kw in exploit_keywords):
                findings.append(Finding(
                    score=20,
                    title='Exploit String',
                    category=self.category,
                    detail=f'Exploitation-related string: {s}',
                    value=s
                ))
        
        return findings
