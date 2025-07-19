exclude_list = ["\\x00"]

for x in range(1, 256):
    hex_str = "\\x" + "{:02x}".format(x)
    if hex_str not in exclude_list:
        print(hex_str, end='')
print()
