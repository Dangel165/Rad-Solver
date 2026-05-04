DEFAULT_ANALYSIS_PROMPT = """All Fields CTF Analysis Prompt

Scope and safety:
- Analyze only local files, authorized CTF/wargame artifacts, challenge text, and provided response dumps.
- Do not assume a filename extension is meaningful; infer type from bytes, magic values, strings, structure, and context.
- Prefer concrete answer candidates in value fields: flags, passwords, serials, magic numbers, decoded secrets, payload candidates, archive entries, and next local checks.
- Rank direct flags and verified decoded values above weak hints. Penalize noisy runtime constants and API names.

Universal:
- Look for common flag formats: flag{}, ctf{}, FLAG{}, CTF{}, and custom PREFIX{} patterns.
- Use any prompt-provided flag format, category, keywords, challenge title, hints, expected input type, and platform.
- Extract ASCII, UTF-16LE at both alignments, URL-encoded text, base encodings, printable strings, and key-value pairs.
- Check extensionless files as scripts, text dumps, binaries, archives, configs, logs, HTTP responses, or encoded blobs.

Reversing:
- Detect PE, ELF, and extensionless binaries by magic bytes, not extension.
- Extract direct strings, UTF-16 strings, prompt strings, credentials, serials, usernames, passwords, and magic numbers.
- For PE and ELF, inspect executable code sections when available.
- Try stack-built strings from rbp/rsp style stores, immediate byte/word/dword stores, XOR loops, and simple XOR keys.
- Find comparison immediates near decoded flags or prompt strings; report likely magic number / PIN / serial candidates.
- Detect packer hints such as UPX, VMProtect, Themida, packed sections, and anti-debug or timing strings.
- Report dangerous or useful APIs/import strings and explain why they matter.

Pwnable:
- Detect ELF/PE pwn hints, architecture clues, /bin/sh, system, execve, setuid, mmap, mprotect, ret2win, win, ROP, pop rdi, syscall, and format strings.
- Report dangerous functions: gets, strcpy, strcat, sprintf, scanf, printf(user), read, memcpy-like unsafe patterns if visible.
- Produce safe CTF payload candidates only: format string leak starters, ret2win target names, system('/bin/sh') target candidate, cyclic/overflow next-check suggestions.
- Do not attempt real network exploitation or unauthorized scanning.

Forensics:
- Detect file magic, embedded signatures, trailing data, nested archives, ZIP entries, PNG chunks, PDF text/secrets, JPEG/PNG metadata-like strings, high entropy, and suspicious key-value lines.
- Open ZIP content when possible, including nested ZIPs and embedded ZIPs at nonzero offsets.
- Parse PNG tEXt, zTXt, iTXt chunks and report flags or secrets from chunks.
- Scan extensionless files as raw dumps and extract hidden strings, UTF-16, archive signatures, and appended data.
- Report concrete paths/entries/offsets when useful.

Crypto:
- Try recursive decoding up to several layers: base64, base32, base85/ascii85, hex, URL encoding.
- Try Caesar/ROT, single-byte XOR, and XOR chunks inside binary-like data.
- Identify hash-shaped values and report likely hash family.
- If small RSA n/e/c parameters are present, factor toy n and decrypt when feasible.
- Prefer decoded plaintext flags/secrets over generic encoding hints.

Web:
- Analyze HTML, JS, CSS, JSON, XML, HTTP dumps, robots.txt, source maps, comments, hidden paths, backup names, and extensionless web response files.
- Extract flags from comments, JS strings, JWT payloads, base64/hex strings inside scripts, localStorage/sessionStorage/cookies, and JSON fields.
- Decode JWTs; report alg=none or admin/role claims as CTF hints.
- Detect SQLi, XSS, SSTI, prototype pollution, deserialization, GraphQL introspection, debug endpoints, admin routes, CSRF/session tokens, backup files, and sourceMappingURL.
- Produce safe CTF payload candidates only, such as SQLi probe strings, XSS alert probe, SSTI arithmetic probe, role=admin tamper candidate, and local next checks.

Output preference:
- Put the most likely flag or answer candidate at the top.
- Include why each candidate matters and what local verification to run next.
- If no flag is found, surface the best next concrete checks rather than vague advice.
"""
