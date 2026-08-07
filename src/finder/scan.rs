// Memory scanner + reverse pointer scanner for the offset finder.
//
// Standalone: depends only on `crate::procmem`. Given a target absolute address
// (found via a known value like a BPM float or a unique title string), the
// reverse pointer scanner walks the object graph backwards to the main image's
// static data, producing pointer chains in rkbx_link's offset-file format.

use std::collections::HashSet;

use crate::procmem::{ProcMem, Region};

/// Read regions in bounded chunks so a single huge mach read never blocks.
const CHUNK: usize = 8 * 1024 * 1024;

/// A discovered static pointer chain: `base -> *(base+rva) -> ... (+final)`.
/// The offset-file line is `rva` followed by `rest` (the last element of `rest`
/// is the final offset, applied without a dereference).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PointerPath {
    pub rva: usize,
    pub rest: Vec<usize>,
}

impl PointerPath {
    /// Format as an offset-file line, e.g. "04DD0708 8 3F0 0".
    pub fn to_line(&self) -> String {
        let mut s = format!("{:X}", self.rva);
        for o in &self.rest {
            s.push_str(&format!(" {o:X}"));
        }
        s
    }

    /// Number of dereferences (chain length).
    pub fn depth(&self) -> usize {
        1 + self.rest.len().saturating_sub(1)
    }

    /// Resolve to the final value address (before reading the value itself).
    pub fn resolve_addr(&self, mem: &ProcMem) -> Option<usize> {
        let mut a = mem.read_u64(mem.base + self.rva)? as usize;
        let n = self.rest.len();
        for off in &self.rest[..n.saturating_sub(1)] {
            a = mem.read_u64(a + off)? as usize;
        }
        Some(a + self.rest.last().copied().unwrap_or(0))
    }
}

/// Options bounding the reverse pointer scan.
#[derive(Clone, Copy)]
pub struct ScanOpts {
    /// Max value of any intermediate/final offset considered.
    pub max_offset: usize,
    /// Max number of dereferences (rva counts as 1).
    pub max_depth: usize,
    /// Cap on emitted paths.
    pub max_results: usize,
    /// Cap on graph nodes explored (guards against explosion).
    pub node_budget: usize,
}

impl Default for ScanOpts {
    fn default() -> Self {
        ScanOpts {
            max_offset: 0x800,
            // Deepest known chain (track_info) is 7 dereferences; allow headroom.
            max_depth: 8,
            max_results: 256,
            node_budget: 3_000_000,
        }
    }
}

pub struct Scanner<'a> {
    pub mem: &'a ProcMem,
    /// Readable regions, sorted by address.
    regions: Vec<Region>,
    /// Regions we treat as candidate holders of live pointers/values
    /// (writable heap/data, or the main image), sorted by address.
    scan_regions: Vec<Region>,
    /// Pointer map: (pointer value, location holding it), sorted by value.
    ptr_map: Vec<(u64, usize)>,
    /// Cheap bounds over all readable regions for fast pointer pre-filtering.
    addr_min: usize,
    addr_max: usize,
}

impl<'a> Scanner<'a> {
    pub fn new(mem: &'a ProcMem) -> Self {
        let mut regions = mem.enumerate_regions();
        regions.sort_by_key(|r| r.addr);
        let base = mem.base;
        let img_end = mem.base + mem.image_size;
        let scan_regions: Vec<Region> = regions
            .iter()
            .copied()
            .filter(|r| r.writable || (r.addr >= base && r.addr < img_end))
            .collect();
        let addr_min = regions.first().map(|r| r.addr).unwrap_or(0);
        let addr_max = regions.iter().map(|r| r.end()).max().unwrap_or(0);
        Scanner {
            mem,
            regions,
            scan_regions,
            ptr_map: Vec::new(),
            addr_min,
            addr_max,
        }
    }

    #[allow(dead_code)]
    pub fn total_scan_bytes(&self) -> usize {
        self.scan_regions.iter().map(|r| r.size).sum()
    }

    fn addr_readable(&self, addr: usize) -> bool {
        // binary search over sorted regions
        match self.regions.binary_search_by(|r| {
            if addr < r.addr {
                std::cmp::Ordering::Greater
            } else if addr >= r.end() {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        }) {
            Ok(_) => true,
            Err(_) => false,
        }
    }

    /// Read a scan region fully, in chunks. Returns (region_addr, bytes).
    fn read_region(&self, r: &Region) -> Option<Vec<u8>> {
        let mut out = Vec::with_capacity(r.size);
        let mut off = 0;
        while off < r.size {
            let want = CHUNK.min(r.size - off);
            match self.mem.read_bytes(r.addr + off, want) {
                Some(b) => {
                    let got = b.len();
                    out.extend_from_slice(&b);
                    if got < want {
                        break; // hit an unreadable hole
                    }
                    off += got;
                }
                None => break,
            }
        }
        if out.is_empty() {
            None
        } else {
            Some(out)
        }
    }

    // ---- Value scans -----------------------------------------------------

    /// All 4-aligned addresses holding an f32 within `tol` of `target`.
    #[allow(dead_code)]
    pub fn find_f32(&self, target: f32, tol: f32) -> Vec<usize> {
        let mut hits = Vec::new();
        for r in &self.scan_regions {
            let Some(buf) = self.read_region(r) else {
                continue;
            };
            let mut i = 0;
            while i + 4 <= buf.len() {
                let v = f32::from_le_bytes([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]);
                if v.is_finite() && (v - target).abs() <= tol {
                    hits.push(r.addr + i);
                }
                i += 4;
            }
        }
        hits
    }

    /// All 8-aligned addresses holding an i64 within `tol` of `target`.
    #[allow(dead_code)]
    pub fn find_i64_near(&self, target: i64, tol: i64) -> Vec<usize> {
        let mut hits = Vec::new();
        for r in &self.scan_regions {
            let Some(buf) = self.read_region(r) else {
                continue;
            };
            let mut i = 0;
            while i + 8 <= buf.len() {
                let v = i64::from_le_bytes(buf[i..i + 8].try_into().unwrap());
                if (v - target).abs() <= tol {
                    hits.push(r.addr + i);
                }
                i += 8;
            }
        }
        hits
    }

    /// Search for a byte pattern (ASCII) and its UTF-16LE form. Returns the
    /// start addresses of matches.
    pub fn find_string(&self, needle: &str) -> Vec<usize> {
        let ascii = needle.as_bytes().to_vec();
        let utf16: Vec<u8> = needle
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        let mut hits = Vec::new();
        for r in &self.scan_regions {
            let Some(buf) = self.read_region(r) else {
                continue;
            };
            for pat in [&ascii, &utf16] {
                if pat.is_empty() || pat.len() > buf.len() {
                    continue;
                }
                let mut i = 0;
                while i + pat.len() <= buf.len() {
                    if &buf[i..i + pat.len()] == pat.as_slice() {
                        hits.push(r.addr + i);
                        i += pat.len();
                    } else {
                        i += 1;
                    }
                }
            }
        }
        hits
    }

    // ---- Byte snapshots (for small values like masterdeck index) --------

    /// Snapshot the bytes of all scan regions.
    #[allow(dead_code)]
    pub fn snapshot(&self) -> Vec<(usize, Vec<u8>)> {
        self.scan_regions
            .iter()
            .filter_map(|r| self.read_region(r).map(|b| (r.addr, b)))
            .collect()
    }

    /// Snapshot only regions up to `max_region` bytes (skips huge media/GPU
    /// buffers). Small enumerated values like the master index live in ordinary
    /// heap allocations, so this keeps the byte-diff cheap.
    pub fn snapshot_capped(&self, max_region: usize) -> Vec<(usize, Vec<u8>)> {
        self.scan_regions
            .iter()
            .filter(|r| r.size <= max_region)
            .filter_map(|r| self.read_region(r).map(|b| (r.addr, b)))
            .collect()
    }

    /// Addresses where the byte equals `want_a` in snapshot `a` and `want_b`
    /// in snapshot `b` (a change detector for enumerated small values). Regions
    /// are matched by ADDRESS, not position — robust to regions being added or
    /// removed between snapshots (which happens when Rekordbox state changes).
    pub fn diff_byte(
        a: &[(usize, Vec<u8>)],
        b: &[(usize, Vec<u8>)],
        want_a: u8,
        want_b: u8,
    ) -> Vec<usize> {
        let bmap: std::collections::HashMap<usize, &Vec<u8>> =
            b.iter().map(|(addr, bytes)| (*addr, bytes)).collect();
        let mut hits = Vec::new();
        for (addr_a, ba) in a {
            let Some(bb) = bmap.get(addr_a) else {
                continue; // this region isn't in the other snapshot
            };
            let n = ba.len().min(bb.len());
            for i in 0..n {
                if ba[i] == want_a && bb[i] == want_b {
                    hits.push(addr_a + i);
                }
            }
        }
        hits
    }

    // ---- Pointer map + reverse scan -------------------------------------

    /// Build the pointer map: every 8-aligned word whose value points into a
    /// readable region. Call once before `reverse_scan`.
    pub fn build_pointer_map(&mut self) {
        let mut map: Vec<(u64, usize)> = Vec::new();
        for r in self.scan_regions.clone() {
            let Some(buf) = self.read_region(&r) else {
                continue;
            };
            let mut i = 0;
            while i + 8 <= buf.len() {
                let v = u64::from_le_bytes(buf[i..i + 8].try_into().unwrap());
                let vu = v as usize;
                // Cheap bounds reject first (most words aren't pointers), then
                // confirm it lands in an actual region.
                if vu >= self.addr_min && vu < self.addr_max && self.addr_readable(vu) {
                    map.push((v, r.addr + i));
                }
                i += 8;
            }
        }
        map.sort_by_key(|e| e.0);
        self.ptr_map = map;
    }

    /// Pointer-map entries whose LOCATION is in the main image's static range
    /// (i.e. candidate static base pointers). Requires `build_pointer_map`.
    #[allow(dead_code)]
    pub fn static_pointers(&self) -> Vec<(u64, usize)> {
        self.ptr_map
            .iter()
            .copied()
            .filter(|(_, loc)| self.mem.in_static_range(*loc))
            .collect()
    }

    /// Locations whose stored pointer value lies in `[lo, hi]`.
    fn ptrs_in_range(&self, lo: u64, hi: u64) -> &[(u64, usize)] {
        let start = self.ptr_map.partition_point(|e| e.0 < lo);
        let end = self.ptr_map.partition_point(|e| e.0 <= hi);
        &self.ptr_map[start..end]
    }

    /// Reverse pointer scan from `target` to static image data.
    ///
    /// Iterative deepening: search exact 1-hop chains, then 2-hop, etc., up to
    /// `max_depth`, ACCUMULATING results at every depth. Shortest chains come
    /// first, but longer ones are kept too — important because a value often
    /// has a short "alias" chain plus a longer canonical deck-array chain, and
    /// only the latter strides across decks. The caller disambiguates (e.g. by
    /// multi-deck stride consistency or cross-validation).
    pub fn reverse_scan(&self, target: usize, opts: ScanOpts) -> Vec<PointerPath> {
        let mut results = Vec::new();
        for limit in 1..=opts.max_depth {
            if results.len() >= opts.max_results {
                break;
            }
            let mut nodes = 0usize;
            // Addresses currently on the recursion stack — cycle guard only.
            let mut on_path: HashSet<usize> = HashSet::new();
            let mut acc: Vec<usize> = Vec::new();
            self.reverse_rec(
                target, &opts, limit, 0, &mut acc, &mut results, &mut nodes, &mut on_path,
            );
        }
        results.sort_by_key(|p| (p.depth(), p.rest.iter().sum::<usize>(), p.rva));
        results.dedup();
        results
    }

    /// Locations in the pointer map holding exactly `value`.
    fn locs_with_value(&self, value: u64) -> &[(u64, usize)] {
        let lo = self.ptr_map.partition_point(|e| e.0 < value);
        let hi = self.ptr_map.partition_point(|e| e.0 <= value);
        &self.ptr_map[lo..hi]
    }

    /// JOINT reverse scan across two (root, target) pairs: find the SHORTEST
    /// offset-path that, applied from each root, reaches that pair's target,
    /// using the SAME offset at every step. Because each backward step must
    /// advance BOTH decks by the identical offset, coincidental single-deck
    /// paths are pruned immediately — so this returns the real shared object-
    /// graph path (e.g. the track subchain two decks share). Root-relative:
    /// `[off_in_root, .., final]`.
    pub fn joint2_path(
        &self,
        root_a: usize,
        target_a: usize,
        root_b: usize,
        target_b: usize,
        window: usize,
        max_offset: usize,
        max_depth: usize,
    ) -> Option<Vec<usize>> {
        for limit in 1..=max_depth {
            let mut acc: Vec<usize> = Vec::new();
            let mut on_path: HashSet<usize> = HashSet::new();
            let mut out: Option<Vec<usize>> = None;
            let mut budget: u64 = 20_000_000; // bound work per pair (non-sharing pairs)
            self.joint2_rec(
                target_a, target_b, root_a, root_b, window, max_offset, limit, 0,
                &mut acc, &mut on_path, &mut out, &mut budget,
            );
            if out.is_some() {
                return out;
            }
        }
        None
    }

    #[allow(clippy::too_many_arguments)]
    fn joint2_rec(
        &self,
        ca: usize,
        cb: usize,
        root_a: usize,
        root_b: usize,
        window: usize,
        max_offset: usize,
        limit: usize,
        depth: usize,
        acc: &mut Vec<usize>,        // shared offsets so far (target-first)
        on_path: &mut HashSet<usize>,
        out: &mut Option<Vec<usize>>,
        budget: &mut u64,
    ) {
        if out.is_some() || depth >= limit || *budget == 0 {
            return;
        }
        if !on_path.insert(ca) {
            return;
        }
        let lo = ca.saturating_sub(max_offset) as u64;
        let hi = ca as u64;
        let cands: Vec<(u64, usize)> = self.ptrs_in_range(lo, hi).to_vec();
        for (value_a, loc_a) in cands {
            if out.is_some() || *budget == 0 {
                break;
            }
            *budget -= 1;
            let off = ca - value_a as usize;
            let value_b = match cb.checked_sub(off) {
                Some(v) => v as u64,
                None => continue,
            };
            // deck B must have a pointer with the same offset to stay in lock-step.
            let locs_b: Vec<usize> = self.locs_with_value(value_b).iter().map(|e| e.1).collect();
            if locs_b.is_empty() {
                continue;
            }
            let in_a = loc_a >= root_a && loc_a < root_a + window;
            if in_a && depth + 1 == limit {
                // Terminal: both decks land in their root at the SAME relative
                // offset via the same step offset.
                let rel = loc_a - root_a;
                if locs_b.iter().any(|&lb| lb == root_b + rel) {
                    let mut path = acc.clone();
                    path.push(off);
                    path.push(rel);
                    path.reverse();
                    *out = Some(path);
                    break;
                }
                continue;
            }
            // Recurse in lock-step: pick a B location as the next cb.
            acc.push(off);
            for lb in locs_b {
                self.joint2_rec(
                    loc_a, lb, root_a, root_b, window, max_offset, limit, depth + 1,
                    acc, on_path, out, budget,
                );
                if out.is_some() {
                    break;
                }
            }
            acc.pop();
        }
        on_path.remove(&ca);
    }

    #[allow(clippy::too_many_arguments)]
    fn reverse_rec(
        &self,
        target: usize,
        opts: &ScanOpts,
        limit: usize,
        depth: usize,
        acc: &mut Vec<usize>,
        results: &mut Vec<PointerPath>,
        nodes: &mut usize,
        on_path: &mut HashSet<usize>,
    ) {
        if results.len() >= opts.max_results || *nodes >= opts.node_budget {
            return;
        }
        if depth >= limit {
            return;
        }
        if !on_path.insert(target) {
            return; // cycle
        }

        let lo = target.saturating_sub(opts.max_offset) as u64;
        let hi = target as u64;
        // Clone the slice range into a small buffer so we don't hold a borrow
        // across the recursive call.
        let candidates: Vec<(u64, usize)> = self.ptrs_in_range(lo, hi).to_vec();

        for (value, loc) in candidates {
            *nodes += 1;
            if results.len() >= opts.max_results || *nodes >= opts.node_budget {
                break;
            }
            let offset = target - value as usize;

            if self.mem.in_static_range(loc) {
                // Terminal: `loc` is base+rva, dereffed to give this pointer.
                // Emit only chains of exactly the current limit's length, so
                // accumulating across limits yields each length once (no dupes).
                if depth + 1 == limit {
                    let rva = loc - self.mem.base;
                    let mut rest: Vec<usize> = acc.clone();
                    rest.push(offset);
                    rest.reverse(); // acc is target-first; line order is shallow-first
                    results.push(PointerPath { rva, rest });
                }
                continue;
            }

            // Recurse: `loc` becomes the address we now need to reach.
            acc.push(offset);
            self.reverse_rec(loc, opts, limit, depth + 1, acc, results, nodes, on_path);
            acc.pop();
        }

        on_path.remove(&target);
    }
}
