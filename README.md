# IPFuscator

IPFuscator generates alternate but equivalent IP address encodings for fuzzing parsers, URL validators, and SSRF filters that key off the literal string form of an IP address.

Upstream author and original writeup:

- Vincent Yiu (@vysecurity)
- https://vincentyiu.co.uk/ipfuscation/

## Install

```bash
git clone https://github.com/vysecurity/IPFuscator.git
cd IPFuscator
```

Run it directly:

```bash
python ipfuscator.py 127.0.0.1
```

Or use the installed command:

```bash
ipfuscator 127.0.0.1
```

## Default behavior

The default mode prints a human-readable report with deterministic encodings and sample randomized variants.

```bash
ipfuscator 169.254.169.254
```

Write a fuzzable newline-delimited payload list to a file:

```bash
ipfuscator 169.254.169.254 -o fuzz.txt
head fuzz.txt
```

Generate full URLs instead of bare hosts:

```bash
ipfuscator 169.254.169.254 --urls --path '/latest/meta-data/' -o fuzz.txt
head fuzz.txt
```

Show help:

```bash
ipfuscator -h
```

## Useful flags

```text
--random-count N
    Control how many random variants are generated per random section.

--urls
    Render payloads as URLs instead of bare host strings.

--scheme http|https
    Scheme to use with --urls. Default: http

--path /foo
    Path, query, or fragment suffix to append with --urls.
```

## Deterministic variants

The stable set currently includes:

- original dotted decimal
- single integer decimal
- single integer hexadecimal
- single integer hexadecimal uppercase
- single integer octal
- dotted hexadecimal
- dotted hexadecimal uppercase
- dotted octal
- zero-padded dotted decimal
- partial decimal 3-part form
- partial decimal 2-part form
- a mixed-base form

The fuzz list also includes:

- all mixed-base dotted permutations
- padded variants
- randomized padded variants
- randomized mixed-base variants

## Example fuzz list

```text
169.254.169.254
2852039166
0xa9fea9fe
0xA9FEA9FE
025177524776
0xa9.0xfe.0xa9.0xfe
0xA9.0xFE.0xA9.0xFE
0251.0376.0251.0376
169.254.43518
169.16689662
0xa9.254.0251.254
```

## Scope

This repository keeps the Python CLI as the source of truth. It focuses on IP and host encodings for fuzzing purposes, not broader URL confusion tricks or generic SSRF payload generation.
