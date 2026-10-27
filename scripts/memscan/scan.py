import re, sys
pid = sys.argv[1]
patterns = [p.encode() for p in sys.argv[2:]]
hits = {p: 0 for p in patterns}
where = {p: set() for p in patterns}
with open(f"/proc/{pid}/maps") as maps, open(f"/proc/{pid}/mem", "rb", 0) as mem:
    for line in maps:
        parts = line.split()
        if "r" not in parts[1]:
            continue
        start, end = (int(x, 16) for x in parts[0].split("-"))
        name = parts[5] if len(parts) > 5 else "[anon]"
        if name in ("[vvar]", "[vsyscall]"):
            continue
        try:
            mem.seek(start)
            data = mem.read(end - start)
        except (OSError, ValueError, OverflowError):
            continue
        for p in patterns:
            n = data.count(p)
            if n:
                hits[p] += n
                where[p].add(name)
for p in patterns:
    print(f"  {p.decode()[:40]:40} hits={hits[p]} regions={sorted(where[p])}")
