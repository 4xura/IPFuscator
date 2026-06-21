# IPFuscator

## Author

Vincent Yiu (@vysecurity)

## Blog Post
https://vincentyiu.co.uk/ipfuscation/

## What is IPFuscator?

IPFuscation is a technique that allows for IP addresses to be represented in hexadecimal or decimal instead of the decimal encoding we are used to. IPFuscator allows us to easily convert to these alternative formats that are interpreted in the same way.

## Usage

1) `git clone https://github.com/vysec/ipfuscator`
2) `python ipfuscator.py 127.0.0.1`
3) Save the generated variants to a file with `python ipfuscator.py -o output.txt 127.0.0.1`
4) You can also use the installed CLI directly: `ipfuscator 127.0.0.1`

### CLI options

- `ipfuscator <ip>` prints the generated variants to stdout
- `ipfuscator -o output.txt <ip>` writes the same output to a file instead of stdout
- `ipfuscator -h` shows the built-in help text

### Examples

Print the variants for the AWS metadata address:

```bash
ipfuscator 169.254.169.254
```

Write the generated variants to a file for later replay or filtering:

```bash
ipfuscator -o pl.txt 169.254.169.254
cat pl.txt
```

```
IPFuscator
Author: Vincent Yiu (@vysecurity)
https://www.github.com/vysec/IPFuscator
Version: 0.1.0

IP Address:     127.0.0.1

Decimal:        2130706433
Hexadecimal:    0x7f000001
Octal:          017700000001

Full Hex:       0x7f.0x0.0x0.0x1
Full Oct:       0177.0.0.01

Random Padding:
Hex:    0x000000000007f.0x000000000000000000000000000000.0x0000.0x0000000000000000000000001
Oct:    00000000000000000000000177.000000000000000000.00000000000000000000000000000.000001

Random base:
#1:     0x7f.0x0.0.01
#2:     0x7f.0x0.0x0.1
#3:     0177.0x0.0x0.0x1
#4:     0x7f.0.0.01
#5:     127.0x0.0.0x1

Random base with random padding:
#1:     127.0x00000000.000000.000000000000000001
#2:     127.0x0000000000000.0x00000000000000000000000000000.0001
#3:     0000000000000000177.0x0000000000000000000000.0x00000000000000000000000000.1
#4:     0000000000000000000177.0.000000.1
#5:     127.0000000000000000000000.0x0000000000000000000.000000000000000000000000000001
```

Take any representation and use it in commands such as `ping`, `curl`, or other tools that accept an IP or URL target. This is especially useful when exploring parser differences or testing SSRF filters that key off the literal string form of an IP address.
