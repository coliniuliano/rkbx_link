// Self-contained macOS process-memory access for the offset finder.
//
// This module is intentionally independent of the main rkbx_link application:
// the offset finder is a separate tool, so it carries its own mach FFI and does
// not touch (or depend on) `src/memory/*`. Only `sysinfo` (already a project
// dependency) is reused, for process lookup.
//
// Requires the target (Rekordbox) to be re-signed with `get-task-allow`
// (see ./resign_rekordbox.sh) so `task_for_pid` succeeds.

use std::mem;
use sysinfo::{ProcessesToUpdate, System};

type MachPort = u32;
type KernReturn = i32;
type MachVmAddress = u64;
type MachVmSize = u64;
type Natural = u32;

const TASK_DYLD_INFO: u32 = 17;
const TASK_DYLD_INFO_COUNT: u32 =
    (mem::size_of::<TaskDyldInfo>() / mem::size_of::<Natural>()) as u32;

const VM_PROT_READ: i32 = 1;
const VM_PROT_WRITE: i32 = 2;
const VM_REGION_BASIC_INFO_64: i32 = 9;

#[repr(C)]
struct TaskDyldInfo {
    all_image_info_addr: u64,
    all_image_info_size: u64,
    all_image_info_format: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct VmRegionBasicInfo64 {
    protection: i32,
    max_protection: i32,
    inheritance: u32,
    shared: i32,
    reserved: i32,
    offset: u64,
    behavior: i32,
    user_wired_count: u16,
}

extern "C" {
    fn mach_task_self() -> MachPort;
    fn task_for_pid(target_tport: MachPort, pid: i32, t: *mut MachPort) -> KernReturn;
    fn task_info(
        target_task: MachPort,
        flavor: u32,
        task_info_out: *mut TaskDyldInfo,
        task_info_count: *mut u32,
    ) -> KernReturn;
    fn mach_vm_read_overwrite(
        target_task: MachPort,
        address: MachVmAddress,
        size: MachVmSize,
        data: MachVmAddress,
        out_size: *mut MachVmSize,
    ) -> KernReturn;
    fn mach_vm_region(
        target_task: MachPort,
        address: *mut MachVmAddress,
        size: *mut MachVmSize,
        flavor: i32,
        info: *mut i32,
        info_cnt: *mut u32,
        object_name: *mut MachPort,
    ) -> KernReturn;
}

/// A mapped, readable region of the target process.
#[derive(Clone, Copy, Debug)]
pub struct Region {
    pub addr: usize,
    pub size: usize,
    /// Currently writable (heap / __DATA) — where live object pointers live.
    pub writable: bool,
}

impl Region {
    pub fn end(&self) -> usize {
        self.addr.saturating_add(self.size)
    }
    #[allow(dead_code)]
    pub fn contains(&self, addr: usize) -> bool {
        addr >= self.addr && addr < self.end()
    }
}

pub struct ProcMem {
    task: MachPort,
    pub pid: i32,
    /// Load address of the main executable image.
    pub base: usize,
    /// Extent of the main image; static range is `[base, base + image_size)`.
    pub image_size: usize,
}

impl ProcMem {
    /// Attach to a process by (case-insensitive) name, e.g. "rekordbox".
    pub fn attach(name: &str) -> Result<ProcMem, String> {
        let mut sys = System::new();
        sys.refresh_processes(ProcessesToUpdate::All, true);

        let name_lower = name.to_lowercase();
        let process = sys
            .processes()
            .values()
            .find(|p| {
                p.name()
                    .to_str()
                    .map(|s| {
                        let pname = s.to_lowercase();
                        pname == name_lower || pname.ends_with(&format!("/{name_lower}"))
                    })
                    .unwrap_or(false)
            })
            .ok_or_else(|| format!("Process '{name}' not found — is it running?"))?;

        let pid = process.pid().as_u32() as i32;

        let mut task: MachPort = 0;
        let kr = unsafe { task_for_pid(mach_task_self(), pid, &mut task) };
        if kr != 0 {
            return Err(format!(
                "task_for_pid failed (mach error {kr}). Re-sign Rekordbox with \
                 get-task-allow: run ./resign_rekordbox.sh"
            ));
        }

        let base = Self::discover_base(task)?;
        let mut me = ProcMem {
            task,
            pid,
            base,
            image_size: 0,
        };
        me.image_size = me.compute_image_size();
        Ok(me)
    }

    fn discover_base(task: MachPort) -> Result<usize, String> {
        let mut dyld_info: TaskDyldInfo = unsafe { mem::zeroed() };
        let mut count = TASK_DYLD_INFO_COUNT;
        let kr = unsafe { task_info(task, TASK_DYLD_INFO, &mut dyld_info, &mut count) };
        if kr != 0 {
            return Err(format!("task_info(TASK_DYLD_INFO) failed: {kr}"));
        }
        let info_addr = dyld_info.all_image_info_addr;

        // dyld_all_image_infos: version(u32), infoArrayCount(u32), infoArray(u64)
        let mut header = [0u8; 16];
        if !Self::raw_read(task, info_addr, &mut header) {
            return Err("Failed to read dyld_all_image_infos".to_string());
        }
        let info_array_ptr = u64::from_ne_bytes(header[8..16].try_into().unwrap());

        // first dyld_image_info: imageLoadAddress(u64), ...
        let mut first = [0u8; 8];
        if !Self::raw_read(task, info_array_ptr, &mut first) {
            return Err("Failed to read dyld image info array".to_string());
        }
        Ok(u64::from_ne_bytes(first) as usize)
    }

    fn raw_read(task: MachPort, addr: u64, buf: &mut [u8]) -> bool {
        let mut read_size: MachVmSize = buf.len() as MachVmSize;
        let kr = unsafe {
            mach_vm_read_overwrite(
                task,
                addr,
                buf.len() as MachVmSize,
                buf.as_mut_ptr() as MachVmAddress,
                &mut read_size,
            )
        };
        kr == 0 && read_size as usize == buf.len()
    }

    /// Read a value of type T from the target.
    pub fn read<T: Copy>(&self, address: usize) -> Option<T> {
        let mut value: T = unsafe { mem::zeroed() };
        let size = mem::size_of::<T>();
        let mut read_size: MachVmSize = size as MachVmSize;
        let kr = unsafe {
            mach_vm_read_overwrite(
                self.task,
                address as MachVmAddress,
                size as MachVmSize,
                &mut value as *mut T as MachVmAddress,
                &mut read_size,
            )
        };
        if kr != 0 {
            None
        } else {
            Some(value)
        }
    }

    pub fn read_u64(&self, address: usize) -> Option<u64> {
        self.read::<u64>(address)
    }

    /// Bulk-read up to `len` bytes; returns however many were readable.
    pub fn read_bytes(&self, address: usize, len: usize) -> Option<Vec<u8>> {
        let mut buf = vec![0u8; len];
        let mut read_size: MachVmSize = len as MachVmSize;
        let kr = unsafe {
            mach_vm_read_overwrite(
                self.task,
                address as MachVmAddress,
                len as MachVmSize,
                buf.as_mut_ptr() as MachVmAddress,
                &mut read_size,
            )
        };
        if kr != 0 {
            return None;
        }
        buf.truncate(read_size as usize);
        Some(buf)
    }

    /// Read a NUL-terminated ASCII/UTF-8 string (bounded by `max`).
    pub fn read_cstring(&self, address: usize, max: usize) -> Option<String> {
        let bytes = self.read_bytes(address, max)?;
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        String::from_utf8(bytes[..end].to_vec()).ok()
    }

    /// Enumerate all readable regions via `mach_vm_region`.
    pub fn enumerate_regions(&self) -> Vec<Region> {
        let mut regions = Vec::new();
        let mut address: MachVmAddress = 1; // skip __PAGEZERO
        loop {
            let mut size: MachVmSize = 0;
            let mut info: VmRegionBasicInfo64 = unsafe { mem::zeroed() };
            let mut count =
                (mem::size_of::<VmRegionBasicInfo64>() / mem::size_of::<i32>()) as u32;
            let mut object_name: MachPort = 0;
            let kr = unsafe {
                mach_vm_region(
                    self.task,
                    &mut address,
                    &mut size,
                    VM_REGION_BASIC_INFO_64,
                    &mut info as *mut VmRegionBasicInfo64 as *mut i32,
                    &mut count,
                    &mut object_name,
                )
            };
            if kr != 0 || size == 0 {
                break;
            }
            if info.protection & VM_PROT_READ != 0 {
                regions.push(Region {
                    addr: address as usize,
                    size: size as usize,
                    writable: info.protection & VM_PROT_WRITE != 0,
                });
            }
            match address.checked_add(size) {
                Some(next) => address = next,
                None => break,
            }
        }
        regions
    }

    pub fn in_static_range(&self, addr: usize) -> bool {
        self.image_size > 0 && addr >= self.base && addr < self.base + self.image_size
    }

    /// Extent of the main image from its Mach-O LC_SEGMENT_64 load commands.
    fn compute_image_size(&self) -> usize {
        const LC_SEGMENT_64: u32 = 0x19;
        let base = self.base;
        let Some(ncmds) = self.read::<u32>(base + 16) else {
            return 0;
        };
        let mut cmd_off = base + 32; // sizeof(mach_header_64)
        let mut min_vm = u64::MAX;
        let mut max_end = 0u64;
        for _ in 0..ncmds {
            let Some(cmd) = self.read::<u32>(cmd_off) else {
                break;
            };
            let cmdsize = self.read::<u32>(cmd_off + 4).unwrap_or(0);
            if cmdsize == 0 {
                break;
            }
            if cmd == LC_SEGMENT_64 {
                let segname = self.read::<[u8; 16]>(cmd_off + 8).unwrap_or([0; 16]);
                let vmaddr = self.read::<u64>(cmd_off + 24).unwrap_or(0);
                let vmsize = self.read::<u64>(cmd_off + 32).unwrap_or(0);
                let is_pagezero = &segname[..10] == b"__PAGEZERO";
                if !is_pagezero && vmsize > 0 {
                    min_vm = min_vm.min(vmaddr);
                    max_end = max_end.max(vmaddr + vmsize);
                }
            }
            cmd_off += cmdsize as usize;
        }
        if min_vm != u64::MAX && max_end > min_vm {
            (max_end - min_vm) as usize
        } else {
            0
        }
    }
}
