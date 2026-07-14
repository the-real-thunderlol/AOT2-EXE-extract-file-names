# made by thunderlol
# 13th July, 2026

import lief
import struct
import os

GAME_PATH = r"D:\SteamLibrary\steamapps\common\AoT2"
EXE_PATH  = r"D:\SteamLibrary\steamapps\common\AoT2\AOT2_EU.exe"

def read_exe_for_filenames(exe_input):
    exe_file = exe_input
    binary = lief.PE.parse(exe_file)

    rdata = binary.get_section(".rdata")

    rdata_start = rdata.offset # where raw data starts
    rdata_end = rdata.offset + rdata.size # not used anywhere...

    image_start = binary.optional_header.imagebase
    image_end = image_start + binary.optional_header.sizeof_image

    with open(exe_file, "rb") as file:
        data = file.read() # store whole file in data
        file.seek(0) # reset cursor

        output = open("output.txt", "w", encoding="utf-8")

        groups = []
        previous_pointer_offset = None
        run_start = None
        run_end = None
        run_count = 0
        run_texts = [] # store all addresses in memory per group

        for x in range(0, rdata.size // 8):
            pointer = struct.unpack_from("<Q", data, rdata_start + (8 * x))[0]

            if image_start < pointer < image_end:
                rva = pointer - image_start # rel virt addr
                string_offset = binary.rva_to_offset(rva)

                end = data.find(b"\x00", string_offset)

                # Filters to skip
                if end == -1 or end - string_offset > 400: # string length is "-1" or more than 400 chars (too long for windows to even store)
                    continue

                raw_text = data[string_offset:end]

                if not raw_text or any(byte < 32 or byte > 126 for byte in raw_text): # reject characters not between 32 and 126
                    continue

                text = raw_text.decode("ascii")

                if not text.startswith(("Linkdata/", "File/")): # address path doesnt start like this, likely "cpp files, before compilation, not in linkdata)
                    continue
                ###

                # grouping logic
                pointer_offset = rdata_start + (8 * x)

                if previous_pointer_offset is None or pointer_offset == previous_pointer_offset + 8:
                    if run_start is None:
                        run_start = pointer_offset

                    run_end = pointer_offset
                    run_count += 1
                    run_texts.append(text)

                else:
                    groups.append((run_start, run_end, run_count, run_texts))

                    run_start = pointer_offset
                    run_end = pointer_offset
                    run_count = 1
                    run_texts = [text]

                previous_pointer_offset = pointer_offset

                output.write(text + "\n")

            else: # if outside range
                continue

        if run_count > 0:
            groups.append((run_start, run_end, run_count, run_texts))

        # for index, group in enumerate(groups):
        #     print("Group:", index)
        #     print("Start:", hex(group[0]))
        #     print("End:", hex(group[1]))
        #     print("Size:", group[2])
        #     print()

        output.close()
    return groups

def read_linkdatas(game_dir):
    LINKDATA_LIST = []

    for root, dirs, files in os.walk(game_dir):
        for name in files:
            if name.startswith("LINKDATA_"):
                LINKDATA_LIST.append(os.path.join(root, name))

    with open("linkdata_entries.txt", "w", encoding="utf-8") as f:
        for path in LINKDATA_LIST:
            f.write(path + "\n")

    linkdata_entries = []

    for linkdata in LINKDATA_LIST:
        with open(linkdata, "rb") as file:
            file.read(4)
            entries = file.read(4)
            le_convert = struct.unpack("<I", entries)[0]
            # print("Entries: ", le_convert)
            linkdata_entries.append((linkdata, le_convert))

    return linkdata_entries

# first get output.txt and groups
Groups = read_exe_for_filenames(EXE_PATH)
for group in Groups:
    print(group[2])

# then get entries in all linkdata3
Linkdatas = read_linkdatas(GAME_PATH)

# then if linkdata entries = group entries, then that group of addresses is for that linkdata

### issue -> linkdata master and linkdata D (an extra one 4kb one both have 1 entry, so if entries are same amount, that will make the code file)
### status: not resolved (ignored)


matches = []

for group in Groups:
    for path, entry_count in Linkdatas:
        if group[2] == entry_count:
            matches.append((path, group))
            break

os.makedirs("paths", exist_ok=True)

for path, group in matches:
    name = f"{os.path.splitext(os.path.basename(path))[0]}_{group[2]}" # eg LINKDATA_A
    with open(f"paths/{name}.txt", "w", encoding="utf-8") as file:
        for line in group[3]:
            file.write(line + "\n")

    print(f"{name}: {group[2]} paths written")

# now based on groups, seperate output.txt into paths/linkdata_a.txt etc,
# using groups only, since groups are in sequential order