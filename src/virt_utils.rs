// Axel '0vercl0k' Souchet - November 11 2025

use core::slice;
use std::collections::HashMap;
use std::ops::Range;

use crate::error::Result;
use crate::structs::{KdDebuggerData64, LdrDataTableEntry, ListEntry, Pod, UnicodeString};
use crate::virt::ignore_non_fatal;
use crate::{Context, Gva, Gxa, KdmpParserError, KernelDumpParser, virt};

/// This trait is used to implement generic behavior when reading pointers that
/// could be either 32/64-bit (think Wow64).
pub trait HasCheckedAdd: Sized + Copy + Into<u64> + From<u32> {
    fn checked_add(self, rhs: Self) -> Option<Self>;
}

macro_rules! impl_checked_add {
    ($($ty:ident),*) => {
        $(impl HasCheckedAdd for $ty {
            fn checked_add(self, rhs: $ty) -> Option<Self> {
                $ty::checked_add(self, rhs)
            }
        })*
    };
}

impl_checked_add!(u32, u64);

/// Read a `UNICODE_STRING`. Returns `None` if a memory error occurs.
fn read_unicode_string<P: HasCheckedAdd + Pod>(
    reader: &virt::Reader,
    unicode_str: &UnicodeString<P>,
) -> Result<String> {
    if (unicode_str.length % 2) != 0 {
        return Err(KdmpParserError::InvalidUnicodeString);
    }

    let mut buffer = vec![0; unicode_str.length.into()];
    reader.read_exact(Gva::new(unicode_str.buffer.into()), &mut buffer)?;

    let n = unicode_str.length / 2;

    Ok(String::from_utf16(unsafe {
        slice::from_raw_parts(buffer.as_ptr().cast(), n.into())
    })?)
}

fn try_read_unicode_string<P: HasCheckedAdd + Pod>(
    reader: &virt::Reader,
    unicode_str: &UnicodeString<P>,
) -> Result<Option<String>> {
    ignore_non_fatal(read_unicode_string(reader, unicode_str))
}

/// A module map. The key is the range of where the module lives at and the
/// value is a path to the module or it's name if no path is available.
pub type ModuleMap = HashMap<Range<Gva>, String>;

/// Walk a `LIST_ENTRY` of `LdrDataTableEntry`. It is used to dump both the user
/// & driver / module lists.
fn try_read_module_map<P: Pod + HasCheckedAdd>(
    reader: &virt::Reader,
    head: Gva,
) -> Result<Option<ModuleMap>> {
    let mut modules = ModuleMap::new();
    let Some(entry) = reader.try_read_struct::<ListEntry<P>>(head)? else {
        return Ok(None);
    };

    let mut entry_addr = Gva::new(entry.flink.into());
    // We'll walk it until we hit the starting point (it is circular).
    while entry_addr != head {
        // Read the table entry..
        let Some(data) = reader.try_read_struct::<LdrDataTableEntry<P>>(entry_addr)? else {
            return Ok(None);
        };

        // ..and read it. We first try to read `full_dll_name` but will try
        // `base_dll_name` is we couldn't read the former.
        let Some(dll_name) =
            try_read_unicode_string::<P>(reader, &data.full_dll_name).and_then(|s| {
                if s.is_none() {
                    // If we failed to read the `full_dll_name`, give `base_dll_name` a shot.
                    try_read_unicode_string::<P>(reader, &data.base_dll_name)
                } else {
                    Ok(s)
                }
            })?
        else {
            return Ok(None);
        };

        // Shove it into the map.
        let dll_end_addr = data
            .dll_base
            .checked_add(data.size_of_image.into())
            .ok_or(KdmpParserError::Overflow("module address"))?;
        let at = Gva::new(data.dll_base.into())..Gva::new(dll_end_addr.into());
        let inserted = modules.insert(at, dll_name);
        debug_assert!(inserted.is_none());

        // Go to the next entry.
        entry_addr = Gva::new(data.in_load_order_links.flink.into());
    }

    Ok(Some(modules))
}

/// Extract the drivers / modules out of the `PsLoadedModuleList`.
pub fn try_extract_kernel_modules(parser: &KernelDumpParser) -> Result<Option<ModuleMap>> {
    // Walk the LIST_ENTRY!
    try_read_module_map::<u64>(
        &virt::Reader::new(parser),
        parser.headers().ps_loaded_module_list.into(),
    )
}

/// Try to find the right `nt!_KPRCB` by walking them and finding one that has
/// the same `Rsp` than in the dump headers' context.
pub fn try_find_prcb(
    parser: &KernelDumpParser,
    kd_debugger_data_block: &KdDebuggerData64,
) -> Result<Option<Gva>> {
    let reader = virt::Reader::new(parser);
    let mut processor_block = kd_debugger_data_block.ki_processor_block;
    for _ in 0..parser.headers().number_processors {
        // Read the KPRCB pointer.
        let Some(kprcb_addr) = reader.try_read_struct::<u64>(processor_block.into())? else {
            return Ok(None);
        };

        // Calculate the address of where the CONTEXT pointer is at..
        let kprcb_context_addr = kprcb_addr
            .checked_add(kd_debugger_data_block.offset_prcb_context.into())
            .ok_or(KdmpParserError::Overflow("offset_prcb"))?;

        // ..and read it.
        let Some(kprcb_context_addr) = reader.try_read_struct::<u64>(kprcb_context_addr.into())?
        else {
            return Ok(None);
        };

        // Read the context..
        let Some(kprcb_context) = reader.try_read_struct::<Context>(kprcb_context_addr.into())?
        else {
            return Ok(None);
        };

        // ..and compare it to ours.
        let kprcb_context = Box::new(kprcb_context);
        if kprcb_context.rsp == parser.context_record().rsp {
            // The register match so we'll assume the current KPRCB is the one describing
            // the 'foreground' processor in the crash-dump.
            return Ok(Some(kprcb_addr.into()));
        }

        // Otherwise, let's move on to the next pointer.
        processor_block = processor_block
            .checked_add(size_of::<u64>() as _)
            .ok_or(KdmpParserError::Overflow("kprcb ptr"))?;
    }

    Ok(None)
}

/// Extract the user modules list by grabbing the current thread from the KPRCB.
/// Then, walk the `PEB.Ldr.InLoadOrderModuleList`.
pub fn try_extract_user_modules(
    reader: &virt::Reader,
    kd_debugger_data_block: &KdDebuggerData64,
    prcb_addr: Gva,
) -> Result<Option<ModuleMap>> {
    // Get the current _KTHREAD..
    let kthread_addr = prcb_addr
        .u64()
        .checked_add(kd_debugger_data_block.offset_prcb_current_thread.into())
        .ok_or(KdmpParserError::Overflow("offset prcb current thread"))?;
    let Some(kthread_addr) = reader.try_read_struct::<u64>(kthread_addr.into())? else {
        return Ok(None);
    };

    // ..then its TEB..
    let teb_addr = kthread_addr
        .checked_add(kd_debugger_data_block.offset_kthread_teb.into())
        .ok_or(KdmpParserError::Overflow("offset kthread teb"))?;
    let Some(teb_addr) = reader.try_read_struct::<u64>(teb_addr.into())? else {
        return Ok(None);
    };

    if teb_addr == 0 {
        return Ok(None);
    }

    // ..then its PEB..
    // ```
    // kd> dt nt!_TEB ProcessEnvironmentBlock
    // nt!_TEB
    //    +0x060 ProcessEnvironmentBlock : Ptr64 _PEB
    // ```
    let peb_offset = 0x60;
    let peb_addr = teb_addr
        .checked_add(peb_offset)
        .ok_or(KdmpParserError::Overflow("peb offset"))?;
    let Some(peb_addr) = reader.try_read_struct::<u64>(peb_addr.into())? else {
        return Ok(None);
    };

    // ..then its _PEB_LDR_DATA..
    // ```
    // kd> dt nt!_PEB Ldr
    // +0x018 Ldr              : Ptr64 _PEB_LDR_DATA
    // ```
    let ldr_offset = 0x18;
    let peb_ldr_addr = peb_addr
        .checked_add(ldr_offset)
        .ok_or(KdmpParserError::Overflow("ldr offset"))?;
    let Some(peb_ldr_addr) = reader.try_read_struct::<u64>(peb_ldr_addr.into())? else {
        return Ok(None);
    };

    // ..and finally the `InLoadOrderModuleList`.
    // ```
    // kd> dt nt!_PEB_LDR_DATA InLoadOrderModuleList
    // +0x010 InLoadOrderModuleList : _LIST_ENTRY
    // ````
    let in_load_order_module_list_offset = 0x10;
    let module_list_entry_addr = peb_ldr_addr
        .checked_add(in_load_order_module_list_offset)
        .ok_or(KdmpParserError::Overflow(
            "in load order module list offset",
        ))?;

    // From there, we walk the list!
    let Some(mut modules) = try_read_module_map::<u64>(reader, module_list_entry_addr.into())?
    else {
        return Ok(None);
    };

    // Now, it's time to dump the TEB32 if there's one.
    //
    // TEB32 is at offset 0x2000 from TEB and PEB32 is at +0x30:
    // ```
    // kd> dt nt!_TEB32 ProcessEnvironmentBlock
    // nt!_TEB32
    // +0x030 ProcessEnvironmentBlock : Uint4B
    // ```
    let teb32_offset = 0x2_000;
    let teb32_addr = teb_addr
        .checked_add(teb32_offset)
        .ok_or(KdmpParserError::Overflow("teb32 offset"))?;
    let peb32_offset = 0x30;
    let peb32_addr = teb32_addr
        .checked_add(peb32_offset)
        .ok_or(KdmpParserError::Overflow("peb32 offset"))?;
    let Some(peb32_addr) = reader.try_read_struct::<u32>(peb32_addr.into())? else {
        return Ok(Some(modules));
    };

    // ..then its _PEB_LDR_DATA.. (32-bit)
    // ```
    // kd> dt nt!_PEB32 Ldr
    // +0x00c Ldr              : Uint4B
    // ```
    let ldr_offset = 0x0c;
    let peb32_ldr_addr = peb32_addr
        .checked_add(ldr_offset)
        .ok_or(KdmpParserError::Overflow("ldr32 offset"))?;
    let Some(peb32_ldr_addr) = reader.try_read_struct::<u32>(Gva::new(peb32_ldr_addr.into()))?
    else {
        return Ok(Some(modules));
    };

    // ..and finally the `InLoadOrderModuleList`.
    // ```
    // 0:000> dt ntdll!_PEB_LDR_DATA InLoadOrderModuleList
    // +0x00c InLoadOrderModuleList : _LIST_ENTRY
    // ````
    let in_load_order_module_list_offset = 0xc;
    let module_list_entry_addr = peb32_ldr_addr
        .checked_add(in_load_order_module_list_offset)
        .ok_or(KdmpParserError::Overflow(
            "in load order module list offset",
        ))?;

    // From there, we walk the list!
    let Some(modules32) =
        try_read_module_map::<u32>(reader, Gva::new(module_list_entry_addr.into()))?
    else {
        return Ok(Some(modules));
    };

    // Merge the lists.
    modules.extend(modules32);

    // We're done!
    Ok(Some(modules))
}
