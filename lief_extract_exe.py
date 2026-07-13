import struct
import lief

exe_file = "AOT2_EU.exe"

binary = lief.PE.parse(exe_file)

print("Image base:", hex(binary.optional_header.imagebase))

for section in binary.sections:
    print(
        f"{section.name:<10}"
        f"RVA: {hex(section.virtual_address):<16}"
        f"Raw offset: {hex(section.offset):<16}"
        f"Raw size: {hex(section.size):<16}"
        f"Virtual size: {hex(section.virtual_size):<16}"
    )

with open(exe_file, "rb") as file:
    data = file.read()

    rdata = binary.get_section(".rdata")

    rdata_start = rdata.offset
    rdata_end = rdata.offset + rdata.size

    # total image size
    image_start = binary.optional_header.imagebase
    image_end = image_start + binary.optional_header.sizeof_image

    output = open("output.txt", "w", encoding="utf-8")

    groups = []
    previous_pointer_offset = None
    run_start = None
    run_end = None
    run_count = 0

    # read pointers in r data
    for x in range(0,rdata.size // 8):
        pointer = struct.unpack_from("<Q", data, rdata_start+(8*x))[0]
        if image_start < pointer < image_end:

            rva = pointer - image_start
            string_offset = binary.rva_to_offset(rva)



            end = data.find(b"\x00", string_offset)

            if end == -1 or end - string_offset > 400:
                continue

            raw_text = data[string_offset:end]

            if not raw_text or any(byte < 32 or byte > 126 for byte in raw_text):
                continue

            text = raw_text.decode("ascii")

            if not text.startswith(("Linkdata/", "File/")):
                continue

            # print(hex(pointer), end="\t\t")
            # print("String offset:", hex(string_offset), end="\t\t")
            # print(hex(pointer), end="\t\t")
            # print(text)

            pointer_offset = rdata_start + (8 * x)

            if previous_pointer_offset is None or pointer_offset == previous_pointer_offset + 8:
                if run_start is None:
                    run_start = pointer_offset

                run_end = pointer_offset
                run_count += 1

            else:
                groups.append((run_start, run_end, run_count))

                run_start = pointer_offset
                run_end = pointer_offset
                run_count = 1

            previous_pointer_offset = pointer_offset

            # print("Pointer offset:", hex(pointer_offset), end="\t\t") # where the pointer is stored
            # print("String offset:", hex(string_offset), end="\t\t") # where the string is stored
            # print(text)

            output.write(text + "\n")

        else:
            continue

    if run_count > 0:
        groups.append((run_start, run_end, run_count))

    for index, group in enumerate(groups):
        print("Group:", index)
        print("Start:", hex(group[0]))
        print("End:", hex(group[1]))
        print("Size:", group[2])
        print()

    output.close()