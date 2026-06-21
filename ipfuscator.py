#!/usr/bin/env python3

from argparse import ArgumentParser
from itertools import product
import random
import re


__version__ = '0.4.0'


UNICODE_DIGIT_STYLES = [
	{
		'name': 'Circled digits',
		'map': {
			'0': '⓪', '1': '①', '2': '②', '3': '③', '4': '④',
			'5': '⑤', '6': '⑥', '7': '⑦', '8': '⑧', '9': '⑨',
		},
	},
	{
		'name': 'Double circled digits',
		'map': {
			'0': '⓿', '1': '⓵', '2': '⓶', '3': '⓷', '4': '⓸',
			'5': '⓹', '6': '⓺', '7': '⓻', '8': '⓼', '9': '⓽',
		},
	},
]


WHOLE_NUMBER_STYLES = [
	{
		'name': 'Circled number',
		'map': {
			0: '⓪', 1: '①', 2: '②', 3: '③', 4: '④', 5: '⑤',
			6: '⑥', 7: '⑦', 8: '⑧', 9: '⑨', 10: '⑩', 11: '⑪',
			12: '⑫', 13: '⑬', 14: '⑭', 15: '⑮', 16: '⑯', 17: '⑰',
			18: '⑱', 19: '⑲', 20: '⑳',
		},
	},
	{
		'name': 'Parenthesized number',
		'map': {
			1: '⑴', 2: '⑵', 3: '⑶', 4: '⑷', 5: '⑸', 6: '⑹',
			7: '⑺', 8: '⑻', 9: '⑼', 10: '⑽', 11: '⑾', 12: '⑿',
			13: '⒀', 14: '⒁', 15: '⒂', 16: '⒃', 17: '⒄', 18: '⒅',
			19: '⒆', 20: '⒇',
		},
	},
	{
		'name': 'Number with full stop',
		'map': {
			1: '⒈', 2: '⒉', 3: '⒊', 4: '⒋', 5: '⒌', 6: '⒍',
			7: '⒎', 8: '⒏', 9: '⒐', 10: '⒑', 11: '⒒', 12: '⒓',
			13: '⒔', 14: '⒕', 15: '⒖', 16: '⒗', 17: '⒘', 18: '⒙',
			19: '⒚', 20: '⒛',
		},
	},
	{
		'name': 'Double circled number',
		'map': {
			0: '⓿', 1: '⓵', 2: '⓶', 3: '⓷', 4: '⓸', 5: '⓹',
			6: '⓺', 7: '⓻', 8: '⓼', 9: '⓽', 10: '⓾', 11: '⓫',
			12: '⓬', 13: '⓭', 14: '⓮', 15: '⓯', 16: '⓰', 17: '⓱',
			18: '⓲', 19: '⓳', 20: '⓴',
		},
	},
]


def get_args():
	parser = ArgumentParser()
	parser.add_argument('-i', '--ip', required=True, help='The IP to perform IPFuscation on')
	parser.add_argument('-o', '--output', help='Write the generated payload list to a file')
	parser.add_argument('--random-count', type=int, default=10, help='Number of random variants to generate per random section')
	parser.add_argument('--urls', action='store_true', help='Render payloads as URLs instead of bare hosts')
	parser.add_argument('--scheme', default='http', help='Scheme to use with --urls (default: http)')
	parser.add_argument('--path', default='', help='Path or suffix to append with --urls')
	return parser.parse_args()


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


def get_hex_parts_upper(parts):
	return ["0x{:X}".format(part) for part in parts]


def get_oct_parts(parts):
	return ["0" + oct(part)[2:] for part in parts]


def encode_digits(value, style):
	return ''.join(style['map'][ch] for ch in str(value))


def get_unicode_octet_variants(value):
	variants = [str(value)]

	for style in UNICODE_DIGIT_STYLES:
		variants.append(encode_digits(value, style))

	for style in WHOLE_NUMBER_STYLES:
		if value in style['map']:
			variants.append(style['map'][value])

	return unique_preserve_order(variants)


def get_domain_parser_variants(parts):
	decimal_parts = [str(part) for part in parts]
	variants = [
		".".join(decimal_parts),
		"。".join(decimal_parts),
		"%2e".join(decimal_parts),
		"%E3%80%82".join(decimal_parts),
	]

	unicode_octets = [get_unicode_octet_variants(part) for part in parts]
	for separator in (".", "。", "%2e", "%E3%80%82"):
		for choice in product(*unicode_octets):
			variants.append(separator.join(choice))

	return unique_preserve_order(variants)


def get_loopback_short_forms(parts):
	if parts[0] != 127:
		return []

	variants = []

	# Short-form variants only make sense for loopback addresses.
	variants.append("127.{}".format(parts[2] * 256 + parts[3]))
	variants.append("127.0.{}".format(parts[2] * 256 + parts[3]))

	if parts == [127, 0, 0, 1]:
		variants.extend([
			"127.1",
			"127.0.1",
			"127.000000000000000.1",
			"0",
		])

	return unique_preserve_order(variants)


def get_known_encodings(parts):
	decimal = ip_to_decimal(parts)
	hexparts = get_hex_parts(parts)
	hexparts_upper = get_hex_parts_upper(parts)
	octparts = get_oct_parts(parts)
	known = [
		("Original", "{}.{}.{}.{}".format(*parts)),
		("Decimal", str(decimal)),
		("Hexadecimal", hex(decimal)),
		("Hexadecimal uppercase", "0x{:X}".format(decimal)),
		("Octal", "0{}".format(oct(decimal)[2:])),
		("Full Hex", ".".join(hexparts)),
		("Full Hex uppercase", ".".join(hexparts_upper)),
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
		("Mixed base (HackTricks)", "{}.{}.{}.{}".format(
			hexparts_upper[0],
			parts[1],
			octparts[2],
			octparts[3],
		)),
		("Dot bypass (ideographic full stop)", get_domain_parser_variants(parts)[1]),
		("Dot bypass (percent-encoded ideographic full stop)", get_domain_parser_variants(parts)[3]),
		("Circled digits", ".".join(encode_digits(part, UNICODE_DIGIT_STYLES[0]) for part in parts)),
		("Double circled digits", ".".join(encode_digits(part, UNICODE_DIGIT_STYLES[1]) for part in parts)),
	]

	loopback_forms = get_loopback_short_forms(parts)
	if loopback_forms:
		known.append(("Loopback short forms", ", ".join(loopback_forms)))

	return known


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


def normalize_path(path):
	if not path:
		return ''
	if path.startswith('/') or path.startswith('?') or path.startswith('#'):
		return path
	return '/' + path


def render_payloads(payloads, args):
	if not args.urls:
		return payloads

	suffix = normalize_path(args.path)
	return ["{}://{}{}".format(args.scheme, payload, suffix) for payload in payloads]


def build_fuzz_variants(ip, random_count=10):
	parts = parse_parts(ip)
	hexparts = get_hex_parts(parts)
	octparts = get_oct_parts(parts)
	variants = []

	for _, value in get_known_encodings(parts):
		variants.append(value)

	variants.extend(build_mixed_base_variants(parts))
	variants.extend(build_padded_variants(parts))
	variants.extend(get_domain_parser_variants(parts))
	variants.extend(get_loopback_short_forms(parts))

	randhex, randoct = build_random_padding(hexparts, octparts)
	variants.append(randhex)
	variants.append(randoct)

	for _ in range(max(random_count, 0)):
		variants.append(build_random_base(parts, hexparts, octparts))
	for _ in range(max(random_count, 0)):
		variants.append(build_random_base_with_padding(parts, hexparts, octparts))

	return unique_preserve_order(variants)


def build_report_output(ip, random_count):
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
	lines.append("Random count per section:\t{}".format(max(random_count, 0)))

	lines.append("")
	lines.append("Random Padding:")
	randhex, randoct = build_random_padding(hexparts, octparts)
	lines.append("Hex:\t{}".format(randhex))
	lines.append("Oct:\t{}".format(randoct))

	lines.append("")
	lines.append("Random base:")
	for count in range(min(max(random_count, 0), 5)):
		lines.append("#{}:\t{}".format(count + 1, build_random_base(parts, hexparts, octparts)))

	lines.append("")
	lines.append("Random base with random padding:")
	for count in range(min(max(random_count, 0), 5)):
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
		payloads = build_fuzz_variants(args.ip, random_count=args.random_count)
		payloads = render_payloads(payloads, args)
		output = "\n".join(payloads) + "\n"
		with open(args.output, 'w', encoding='utf-8', newline='\n') as file_obj:
			file_obj.write(output)
	else:
		report = build_report_output(args.ip, args.random_count)
		print(report, end="")


if __name__ == '__main__':
	main()
