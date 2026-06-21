#!/usr/bin/env python3

from argparse import ArgumentParser
import random
import re


__version__ = '0.1.0'


def get_args():
	parser = ArgumentParser()
	parser.add_argument('ip', help='The IP to perform IPFuscation on')
	parser.add_argument('-o', '--output', help='Output file')
	return parser.parse_args()


def banner():
	return "\n".join([
		"IPFuscator",
		"Author: Vincent Yiu (@vysecurity)",
		"https://www.github.com/vysec/IPFuscator",
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


def get_known_encodings(parts):
	decimal = ip_to_decimal(parts)
	hexparts = [hex(part) for part in parts]
	octparts = ["0" + oct(part)[2:] for part in parts]

	return [
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
		("Partial decimal", "{}.{}.{}".format(
			parts[0],
			parts[1],
			parts[2] * 256 + parts[3],
		)),
		("Mixed base", "{}.{}.{}.{}".format(
			hexparts[0],
			parts[1],
			octparts[2],
			parts[3],
		)),
	]


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


def build_output(ip):
	parts = parse_parts(ip)
	hexparts = [hex(part) for part in parts]
	octparts = ["0" + oct(part)[2:] for part in parts]
	lines = []

	lines.append("IP Address:\t{}".format(ip))
	lines.append("")
	lines.append("Known Encodings:")
	for label, value in get_known_encodings(parts):
		lines.append("{}:\t{}".format(label, value))

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
	output = banner()

	if check_ip(args.ip):
		output += build_output(args.ip)
	else:
		output += "[!] Invalid IP format: {}\n".format(args.ip)

	if args.output:
		with open(args.output, 'w', encoding='utf-8') as file_obj:
			file_obj.write(output)
	else:
		print(output, end="")


if __name__ == '__main__':
	main()
