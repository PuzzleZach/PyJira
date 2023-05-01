#!/usr/bin/env python3

from argparse import ArgumentParser




def grabStrings(sfile):
    strings = []
    with open(sfile, "r+") as lines:
        for line in lines:
            strings.append(line.strip())
            if line == "\n" or line is None:
                continue
    return strings

def generateYara(strings):
    yaraParams = []
    for i, v in enumerate(strings):
        # Create the params used for yara strings and encode them as hex
        yaraParams.append(f'$string{i} = {{ {v.encode().hex()} }}\n            ')
    return yaraParams

def assembleYara(params, rule):
    rule = rule.replace(".", "_")
    strs = ""
    for i in params:
        strs += i
    yara = f"""
    rule strings_{rule} {{
        strings:
            {strs}
        condition:
            (uint16(0) == 0x5A4D) and all of ($string*)
    }}
    """
    return yara

def writeOutput(rule, filename):
    string = filename.replace(".", "") + ".yara"
    with open(string, "w+") as fname:
        fname.write(rule)

def main():

    parser = ArgumentParser(description="YARA generator in Python.")
    parser.add_argument("file", help="File to generate rules from.")

    args=parser.parse_args()

    # Pull strings from our file
    strings = grabStrings(args.file)
    # Generate yara strings from file strings
    params = generateYara(strings)

    # Assemble the yara rule
    rule = assembleYara(params, args.file)

    writeOutput(rule, args.file)

if __name__ == "__main__":
    main()
