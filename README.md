# IPFuscator

IPFuscator generates alternate but equivalent IP address encodings. It is meant for parser and filter testing, especially when a target keys off the literal string form of an IP address.

Upstream author and original writeup:

- Vincent Yiu (@vysecurity)
- https://vincentyiu.co.uk/ipfuscation/

## Install

Clone the repository:

```bash
git clone https://github.com/vysecurity/IPFuscator.git
cd IPFuscator
```

Run the Python CLI directly:

```bash
python ipfuscator.py 127.0.0.1
```

If you install it as a command, you can also use:

```bash
ipfuscator 127.0.0.1
```

## Usage

Print the human-readable report:

```bash
ipfuscator 169.254.169.254
```

Write a fuzzable newline-delimited variant list:

```bash
ipfuscator 169.254.169.254 -o fuzz.txt
head fuzz.txt
```

Show help:

```bash
ipfuscator -h
```

## Output modes

Without `-o`, the tool prints a report with:

- known deterministic encodings
- mixed-base permutation count
- random padded variants
- random mixed-base variants

With `-o fuzz.txt`, the tool writes payload candidates only, one per line. That file is meant to feed fuzzing, replay, or filtering workflows.

## Deterministic encodings

The `Known Encodings` section includes:

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

The fuzz list also includes:

- all mixed-base dotted permutations
- padded variants
- a small randomized set

## Example fuzz list

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

## Scope

This repository keeps the Python CLI as the source of truth. It focuses on IP and host encodings, not broader URL confusion tricks or generic SSRF payload generation.
