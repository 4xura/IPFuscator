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

def checkIP(ip):
	m = re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\Z',ip)
	
	if m:
		# Valid IP format
		parts = ip.split('.')
		if len(parts) == 4:
			# Valid IP
			for i in parts:
					if int(i) > 255 or int(i) < 0:
						return False
			return True
		else:
			 return False
	else:
		return False

def build_output(ip):
	parts = ip.split('.')
	lines = []

	decimal = int(parts[0]) * 16777216 + int(parts[1]) * 65536 + int(parts[2]) * 256 + int(parts[3])
	lines.append("IP Address:\t{}".format(ip))
	lines.append("")
	lines.append("Decimal:\t{}".format(decimal))
	#hexadecimal = "0x%02X%02X%02X%02X" % (int(parts[0]), int(parts[1]), int(parts[2]), int(parts[3]))
	lines.append("Hexadecimal:\t{}".format(hex(decimal)))

	#octal = oct(decimal)
	lines.append("Octal:\t\t0{}".format(oct(decimal)[2:]))
	lines.append("")

	hexparts = []
	octparts = []

	for i in parts:
		hexparts.append(hex(int(i)))
		octparts.append("0" + oct(int(i))[2:])

	lines.append("Full Hex:\t{}".format('.'.join(hexparts)))
	lines.append("Full Oct:\t{}".format('.'.join(octparts)))
	lines.append("")
	lines.append("Random Padding: ")

	randhex = ""

	for i in hexparts:
		randhex += i.replace('0x','0x' + '0' * random.randint(1,30)) + '.'

	randhex = randhex[:-1]
	lines.append("Hex:\t{}".format(randhex))

	randoct = ""
	for i in octparts:
		randoct += '0' * random.randint(1,30) + i + '.'

	randoct = randoct[:-1]

	lines.append("Oct:\t{}".format(randoct))
	lines.append("")
	lines.append("Random base:")

	randbase = []

	count = 0
	while count < 5:
		randbaseval = ""
		for i in range(0,4):
			val = random.randint(0,2)
			if val == 0:
				# dec
				randbaseval += parts[i] + '.'
			elif val == 1:
				# hex
				randbaseval += hexparts[i] + '.'
			else:
				randbaseval += octparts[i] + '.'
				# oct
		randbase.append(randbaseval[:-1])
		lines.append("#{}:\t{}".format(count+1, randbase[count]))
		count += 1

	lines.append("")
	lines.append("Random base with random padding:")

	randbase = []

	count = 0
	while count < 5:
		randbaseval = ""
		for i in range(0,4):
			val = random.randint(0,2)
			if val == 0:
				# dec
				randbaseval += parts[i] + '.'
			elif val == 1:
				# hex
				randbaseval += hexparts[i].replace('0x', '0x' + '0' * random.randint(1,30)) + '.'
			else:
				randbaseval += '0' * random.randint(1,30) + octparts[i] + '.'
				# oct
		randbase.append(randbaseval[:-1])
		lines.append("#{}:\t{}".format(count+1, randbase[count]))
		count += 1

	return "\n".join(lines) + "\n"


def main():
	args = get_args()
	output = banner()

	if checkIP(args.ip):
		output += build_output(args.ip)
	else:
		output += "[!] Invalid IP format: {}\n".format(args.ip)

	if args.output:
		with open(args.output, 'w', encoding='utf-8') as f:
			f.write(output)
	else:
		print(output, end="")


if __name__ == '__main__':
	main()
