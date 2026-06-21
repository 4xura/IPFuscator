#!/usr/bin/env python3

from argparse import ArgumentParser
from itertools import product
import random
import re


__version__ = '0.2.0'
__repo_url__ = 'https://www.github.com/vysecurity/IPFuscator'


def get_args():
	parser = ArgumentParser()
	parser.add_argument('ip', help='The IP to perform IPFuscation on')
	parser.add_argument('-o', '--output', help='Write fuzzable variants to a file, one per line')
	return parser.parse_args()


def banner():
	return "\n".join([
		"IPFuscator",
		"Author: Vincent Yiu (@vysecurity)",
		__repo_url__,
		"Version: {}".format(__version__),
		"",
	])


def check_ip(ip):
	match = re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\Z', ip)
	if not match:
		return False

	parts = ip.split('.')
	if len(parts) != 4:
		return False

	for part in parts:
		if int(part) > 255 or int(part) < 0:
			return False

	return True


def parse_parts(ip):
	return [int(part) for part in ip.split('.')]


def ip_to_decimal(parts):
	return parts[0] * 16777216 + parts[1] * 65536 + parts[2] * 256 + parts[3]


def get_hex_parts(parts):
	return [hex(part) for part in parts]


def get_oct_parts(parts):
	return ["0" + oct(part)[2:] for part in parts]


def get_known_encodings(parts):
	decimal = ip_to_decimal(parts)
	hexparts = get_hex_parts(parts)
	octparts = get_oct_parts(parts)

	return [
		("Original", "{}.{}.{}.{}".format(*parts)),
		("Decimal", str(decimal)),
		("Hexadecimal", hex(decimal)),
		("Octal", "0{}".format(oct(decimal)[2:])),
		("Full Hex", ".".join(hexparts)),
		("Full Oct", ".".join(octparts)),
		("Zero-padded dotted decimal", "{}.{}.{}.{}".format(
			str(parts[0]).zfill(3),
			str(parts[1]).zfill(3),
			str(parts[2]).zfill(3),
			str(parts[3]).zfill(3),
		)),
		("Partial decimal (3 parts)", "{}.{}.{}".format(
			parts[0],
			parts[1],
			parts[2] * 256 + parts[3],
		)),
		("Partial decimal (2 parts)", "{}.{}".format(
			parts[0],
			parts[1] * 65536 + parts[2] * 256 + parts[3],
		)),
		("Mixed base", "{}.{}.{}.{}".format(
			hexparts[0],
			parts[1],
			octparts[2],
			parts[3],
		)),
	]


def unique_preserve_order(values):
	seen = set()
	result = []
	for value in values:
		if value not in seen:
			seen.add(value)
			result.append(value)
	return result


def build_random_padding(hexparts, octparts):
	randhex = []
	for part in hexparts:
		randhex.append(part.replace('0x', '0x' + '0' * random.randint(1, 30)))

	randoct = []
	for part in octparts:
		randoct.append('0' * random.randint(1, 30) + part)

	return ".".join(randhex), ".".join(randoct)


def build_random_base(parts, hexparts, octparts):
	variant = []
	for index in range(4):
		val = random.randint(0, 2)
		if val == 0:
			variant.append(str(parts[index]))
		elif val == 1:
			variant.append(hexparts[index])
		else:
			variant.append(octparts[index])
	return ".".join(variant)


def build_random_base_with_padding(parts, hexparts, octparts):
	variant = []
	for index in range(4):
		val = random.randint(0, 2)
		if val == 0:
			variant.append(str(parts[index]))
		elif val == 1:
			variant.append(hexparts[index].replace('0x', '0x' + '0' * random.randint(1, 30)))
		else:
			variant.append('0' * random.randint(1, 30) + octparts[index])
	return ".".join(variant)


def build_mixed_base_variants(parts):
	representations = []
	for part in parts:
		representations.append([
			str(part),
			hex(part),
			"0" + oct(part)[2:],
		])

	variants = []
	for choice in product(*representations):
		variants.append(".".join(choice))
	return variants


def build_padded_variants(parts):
	hexparts = get_hex_parts(parts)
	octparts = get_oct_parts(parts)
	return [
		"{}.{}.{}.{}".format(
			str(parts[0]).zfill(8),
			str(parts[1]).zfill(8),
			str(parts[2]).zfill(8),
			str(parts[3]).zfill(8),
		),
		"{}.{}.{}.{}".format(
			hexparts[0].replace('0x', '0x000000'),
			hexparts[1].replace('0x', '0x000000'),
			hexparts[2].replace('0x', '0x000000'),
			hexparts[3].replace('0x', '0x000000'),
		),
		"{}.{}.{}.{}".format(
			"000000" + octparts[0],
			"000000" + octparts[1],
			"000000" + octparts[2],
			"000000" + octparts[3],
		),
	]


def build_fuzz_variants(ip):
	parts = parse_parts(ip)
	hexparts = get_hex_parts(parts)
	octparts = get_oct_parts(parts)
	variants = []

	for _, value in get_known_encodings(parts):
		variants.append(value)

	variants.extend(build_mixed_base_variants(parts))
	variants.extend(build_padded_variants(parts))

	randhex, randoct = build_random_padding(hexparts, octparts)
	variants.append(randhex)
	variants.append(randoct)

	for _ in range(10):
		variants.append(build_random_base(parts, hexparts, octparts))
	for _ in range(10):
		variants.append(build_random_base_with_padding(parts, hexparts, octparts))

	return unique_preserve_order(variants)


def build_report_output(ip):
	parts = parse_parts(ip)
	hexparts = get_hex_parts(parts)
	octparts = get_oct_parts(parts)
	lines = []

	lines.append("IP Address:\t{}".format(ip))
	lines.append("")
	lines.append("Known Encodings:")
	for label, value in get_known_encodings(parts):
		lines.append("{}:\t{}".format(label, value))

	lines.append("")
	lines.append("Mixed base permutations:\t{}".format(len(build_mixed_base_variants(parts))))

	lines.append("")
	lines.append("Random Padding:")
	randhex, randoct = build_random_padding(hexparts, octparts)
	lines.append("Hex:\t{}".format(randhex))
	lines.append("Oct:\t{}".format(randoct))

	lines.append("")
	lines.append("Random base:")
	for count in range(5):
		lines.append("#{}:\t{}".format(count + 1, build_random_base(parts, hexparts, octparts)))

	lines.append("")
	lines.append("Random base with random padding:")
	for count in range(5):
		lines.append("#{}:\t{}".format(count + 1, build_random_base_with_padding(parts, hexparts, octparts)))

	return "\n".join(lines) + "\n"


def main():
	args = get_args()

	if not check_ip(args.ip):
		error = "[!] Invalid IP format: {}\n".format(args.ip)
		if args.output:
			with open(args.output, 'w', encoding='utf-8') as file_obj:
				file_obj.write("")
		print(error, end="")
		return

	if args.output:
		variants = build_fuzz_variants(args.ip)
		with open(args.output, 'w', encoding='utf-8', newline='\n') as file_obj:
			file_obj.write("\n".join(variants) + "\n")
	else:
		print(banner() + build_report_output(args.ip), end="")


if __name__ == '__main__':
	main()
