#!/usr/bin/env python3
"""
check_struct.py – show which members of a C struct are read / write-only / unused.

Quick start (no flags):
    1. Paste your struct into the STRUCT_TEXT constant below.
    2. python3 check_struct.py /path/to/src

Advanced:
    --struct-file hdr.h        # read the struct from a file
    --struct-name NAME         # read from stdin and tell me which struct

Colours:
    🟢 green   = at least one read
    🟡 yellow  = writes only
    🔴 red     = never referenced
"""
import argparse, re, sys
from pathlib import Path
from pycparser import c_parser, c_ast, plyparser

# ────────────────────────────────────────────────────────────────────────────────
# ✂️  PASTE YOUR STRUCT DEFINITION BETWEEN THE TRIPLE QUOTES  ✂️
STRUCT_TEXT = r"""
struct hws_pcie_dev {
	// struct pci_dev			*pdev;
	struct uio_info info;
	// struct hws_video		video[MAX_VID_CHANNELS];
	// spinlock_t				videoslock[MAX_VID_CHANNELS];
	// u32 *map_bar0_addr;
	// struct workqueue_struct *wq;
	unsigned long video_data[MAX_VID_CHANNELS];
 	struct tasklet_struct dpc_video_tasklet[MAX_VID_CHANNELS];
	// int irq_line;		/* flag if irq allocated successfully */	
	// int msi_enabled;	/* flag if msi was enabled for the device */	
	// int msix_enabled;	/* flag if msi-x was enabled for the device */	
	// int irq_user_count;/* user interrupt count */     
	// int m_PciDeviceLost;
	// struct msix_entry entry[32];	
	// u32 dwDeviceID;
	// u32 dwVendorID;
	// u32 m_Device_Version;
	// int  m_DeviceHW_Version;
	// u32  m_Device_SupportYV12;
	// u32 m_Device_SubVersion;
	// u32 m_Device_PortID;
	// int  m_MaxHWVideoBufferSize;
	// int m_nMaxChl;
	// int m_nCurreMaxVideoChl;
	// int m_nCurreMaxLineInChl;
	// uint8_t m_bStartRun;	// Use for start run for check i2c
	// dma_addr_t   		m_pbyVideo_phys[MAX_VID_CHANNELS] ;
    // uint8_t		*m_pbyVideoBuffer[MAX_VID_CHANNELS];
	// u32		    m_dwVideoBuffer[MAX_VID_CHANNELS];
	// u32		    m_dwVideoHighBuffer[MAX_VID_CHANNELS];
	VCAP_STATUS_INFO    m_pVCAPStatus[MAX_VID_CHANNELS][MAX_VIDEO_QUEUE];
	ACAP_VIDEO_INFO m_VideoInfo[MAX_VID_CHANNELS];

	// VIDEO_INFO      	m_format[MAX_VID_CHANNELS];
	int m_dwSWFrameRate[MAX_VID_CHANNELS];

	// ULONG m_contrast[MAX_VID_CHANNELS];
	// ULONG m_brightness[MAX_VID_CHANNELS];
	// ULONG m_saturation[MAX_VID_CHANNELS];
	// ULONG m_hue[MAX_VID_CHANNELS];
	
};
"""
# ────────────────────────────────────────────────────────────────────────────────

# ANSI colours
GREEN, YELLOW, RED, RESET = "\033[92m", "\033[93m", "\033[91m", "\033[0m"
def _fallback_regex_members(src: str, struct_name: str | None) -> list[str]:
    """
    Very forgiving extractor: walks braces, strips comments, grabs the last
    token of each declarator.   Works even if unknown types/macros exist.
    """
    lines = src.splitlines()
    # 1. locate struct header
    hdr_pat = rf"\s*struct\s+{re.escape(struct_name)}\b" if struct_name \
              else r"\s*struct\s+\w+\b"
    start = next((i for i, L in enumerate(lines) if re.match(hdr_pat, L)), -1)
    if start == -1:
        return []

    body, depth = [], 0
    for L in lines[start:]:
        depth += L.count("{") - L.count("}")
        body.append(L)
        if depth == 0 and "}" in L:
            break

    members: list[str] = []
    for raw in body:
        L = re.sub(r"/\*.*?\*/", "", raw).split("//")[0].strip()
        if not L or L in "{}":
            continue
        for stmt in L.split(";"):
            stmt = stmt.strip()
            if not stmt:
                continue
            for decl in stmt.split(","):
                decl = re.sub(r"\[[^\]]*\]", "", decl)   # drop [dims]
                decl = decl.replace("*", " ")
                tokens = [t for t in decl.split() if t]
                if tokens:
                    name = tokens[-1]
                    if re.match(r"^[A-Za-z_]\w*$", name):
                        members.append(name)
    return members
# ──────────────────────────  parsing helpers  ──────────────────────────────────
def extract_members(src: str, struct_name: str | None) -> list[str]:
    """
    Preferred: use pycparser for an exact AST walk.
    Fallback:  heuristic regex if pycparser can’t parse the input.
    """
    try:
        parser = c_parser.CParser()
        ast = parser.parse(src)

        class Grabber(c_ast.NodeVisitor):
            def __init__(self):
                self.members = []
            def visit_Struct(self, node):
                want = struct_name or node.name  # first struct if None
                if node.name == want and node.decls:
                    self.members += [d.name for d in node.decls]

        g = Grabber()
        g.visit(ast)
        if g.members:                         # success
            return g.members
    except plyparser.ParseError:
        pass                                  # fall back below

    # fallback path
    return _fallback_regex_members(src, struct_name)

# ────────────────────────────  code scan  ──────────────────────────────────────
def scan_usage(root: Path, members: list[str]) -> dict[str, dict[str, int]]:
    read_re  = {m: re.compile(rf"(?:->|\.){m}\b(?!\s*=)") for m in members}
    write_re = {m: re.compile(rf"(?:->|\.){m}\b\s*=")     for m in members}
    counts   = {m: {"read": 0, "write": 0} for m in members}

    for path in root.rglob("*"):
        if path.suffix.lower() not in {".c", ".h"} or not path.is_file():
            continue
        try:
            txt = path.read_text(errors="ignore")
        except Exception:
            continue
        for m in members:
            counts[m]["write"] += len(write_re[m].findall(txt))
            counts[m]["read"]  += len(read_re[m].findall(txt))
    return counts

def color_line(name: str, rd: int, wr: int) -> str:
    if rd:
        col = GREEN
    elif wr:
        col = YELLOW
    else:
        col = RED
    label = f"{rd:>4}R/{wr:>4}W" if (rd or wr) else "UNUSED"
    return f"{col}{name:<30} {label}{RESET}"

# ────────────────────────────  main  ───────────────────────────────────────────
def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("root", type=Path, help="Root of C source tree to scan")
    grp = ap.add_mutually_exclusive_group()
    grp.add_argument("--struct-file", type=Path,
                     help="File containing the struct definition")
    grp.add_argument("--struct-name", type=str,
                     help="Name of struct to find in stdin")
    args = ap.parse_args()

    if args.struct_file:
        struct_src = args.struct_file.read_text()
        struct_name = None
    elif args.struct_name:
        struct_src = sys.stdin.read()
        struct_name = args.struct_name
    else:
        struct_src = STRUCT_TEXT
        struct_name = None

    members = extract_members(struct_src, struct_name)
    if not members:
        sys.exit(f"{RED}No struct members found – check your input.{RESET}")

    counts = scan_usage(args.root, members)

    print(f"\nScanning {args.root} for struct member usage\n" + "-"*60)
    unused = 0
    for m in sorted(members):
        r, w = counts[m]["read"], counts[m]["write"]
        if r == 0 and w == 0:
            unused += 1
        print(color_line(m, r, w))
    print(f"\n{len(members)} members; {unused} never referenced.\n")

if __name__ == "__main__":
    main()
