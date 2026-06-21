# IPFuscator

## Author

Vincent Yiu (@vysecurity)

## Blog Post
https://vincentyiu.co.uk/ipfuscation/

## What is IPFuscator?

IPFuscation is a technique that allows an IP address to be represented in alternate but equivalent forms. IPFuscator focuses on host-encoding variants that are useful when testing parsers, filters, and SSRF defenses that key off the literal string form of an IP.

## Usage

1) `git clone https://github.com/vysec/ipfuscator`
2) `python ipfuscator.py 127.0.0.1`
3) Save the generated variants to a file with `python ipfuscator.py -o output.txt 127.0.0.1`
4) You can also use the installed CLI directly: `ipfuscator 127.0.0.1`

### CLI options

- `ipfuscator <ip>` prints a human-readable report
- `ipfuscator -o output.txt <ip>` writes a fuzzable newline-delimited variant list
- `ipfuscator -h` shows the built-in help text

### Deterministic encodings

The tool emits a stable `Known Encodings` section before the randomized variants. This currently includes:

- original dotted decimal
- single integer decimal
- single integer hexadecimal
- single integer octal
- dotted hexadecimal
- dotted octal
- zero-padded dotted decimal
- partial decimal 3-part form
- partial decimal 2-part form
- a mixed-base form

When `-o` is used, the output file contains payload candidates only, one per line. It includes the deterministic encodings above, all mixed-base dotted permutations, padded variants, and a small randomized set.

### Examples

Print the variants for the AWS metadata address:

```bash
ipfuscator 169.254.169.254
```

Write the generated variants to a file for later replay or filtering:

```bash
ipfuscator -o pl.txt 169.254.169.254
head pl.txt
```

Example fuzz-list output:

```text
169.254.169.254
2852039166
0xa9fea9fe
025177524776
0xa9.0xfe.0xa9.0xfe
0251.0376.0251.0376
169.254.43518
169.16689662
0xa9.254.0251.254
```

Take any representation and use it in commands such as `ping`, `curl`, or other tools that accept an IP or URL target. This is especially useful when exploring parser differences or testing SSRF filters that key off the literal string form of an IP address.

## Project scope

This repository keeps the Python CLI as the source of truth. It intentionally focuses on IP/host encodings rather than broader URL confusion or generic SSRF payload generation.
