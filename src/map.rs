// Axel '0vercl0k' Souchet - July 18 2023
//! This implements logic that allows to memory map a file on both
//! Unix and Windows (cf `memory_map_file` / `unmap_memory_mapped_file`).
use std::fmt::{self, Debug};
use std::fs::File;
use std::io::{self, Cursor, Read, Seek};
use std::path::Path;

// XXX: use [cfg_select](https://github.com/rust-lang/rust/issues/115585#issue-1882997206) when it's stabilized.

pub trait Reader: Read + Seek {}

impl<T> Reader for T where T: Read + Seek {}

/// A memory mapped file reader is basically a slice of bytes over the memory
/// mapping and a cursor to be able to access the region.
pub struct MappedFileReader<'map> {
    mapped_file: &'map [u8],
    cursor: Cursor<&'map [u8]>,
}

impl Debug for MappedFileReader<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MappedFileReader").finish()
    }
}

impl MappedFileReader<'_> {
    /// Create a new [`MappedFileReader`] from a path using a memory map.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be opened or memory mapped.
    pub fn new(path: impl AsRef<Path>) -> io::Result<Self> {
        // Open the file..
        let file = File::open(path)?;

        // ..and memory map it using the underlying OS-provided APIs.
        let mapped_file = memory_map_file(&file)?;

        Ok(Self {
            mapped_file,
            cursor: Cursor::new(mapped_file),
        })
    }
}

impl Read for MappedFileReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.cursor.read(buf)
    }
}

impl Seek for MappedFileReader<'_> {
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        self.cursor.seek(pos)
    }
}

/// Drop the [`MappedFileReader`]. In the case we memory mapped the file, we
/// need to drop the mapping using OS-provided APIs.
impl Drop for MappedFileReader<'_> {
    fn drop(&mut self) {
        unmap_memory_mapped_file(self.mapped_file).expect("failed to unmap");
    }
}

#[cfg(windows)]
#[allow(non_camel_case_types, clippy::upper_case_acronyms)]
/// Module that implements memory mapping on Windows using `CreateFileMappingA`
/// / `MapViewOfFile`.
mod windows {
    use std::fs::File;
    use std::os::windows::prelude::AsRawHandle;
    use std::os::windows::raw::HANDLE;
    use std::{io, ptr, slice};

    const PAGE_READONLY: DWORD = 2;
    const FILE_MAP_READ: DWORD = 4;

    type DWORD = u32;
    type BOOL = u32;
    type SIZE_T = usize;
    type LPCSTR = *mut u8;
    type LPVOID = *const u8;

    unsafe extern "system" {
        /// Creates or opens a named or unnamed file mapping object for a
        /// specified file.
        ///
        /// <https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createfilemappinga>
        fn CreateFileMappingA(
            h: HANDLE,
            file_mapping_attrs: *const u8,
            protect: DWORD,
            max_size_high: DWORD,
            max_size_low: DWORD,
            name: LPCSTR,
        ) -> HANDLE;

        /// Maps a view of a file mapping into the address space of a calling
        /// process.
        ///
        /// <https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffile>
        fn MapViewOfFile(
            file_mapping_object: HANDLE,
            desired_access: DWORD,
            file_offset_high: DWORD,
            file_offset_low: DWORD,
            number_of_bytes_to_map: SIZE_T,
        ) -> LPVOID;

        /// Closes an open object handle.
        ///
        /// <https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle>
        fn CloseHandle(h: HANDLE) -> BOOL;

        /// Unmaps a mapped view of a file from the calling process's address
        /// space.
        ///
        /// <https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-unmapviewoffile>
        fn UnmapViewOfFile(base_address: LPVOID) -> BOOL;
    }

    /// Memory map a file into memory.
    pub fn memory_map_file<'map>(file: &File) -> Result<&'map [u8], io::Error> {
        // Grab the underlying HANDLE.
        let file_handle = file.as_raw_handle();

        // Create the mapping.
        let mapping_handle = unsafe {
            CreateFileMappingA(
                file_handle,
                ptr::null_mut(),
                PAGE_READONLY,
                0,
                0,
                ptr::null_mut(),
            )
        };

        // If the mapping is NULL, it failed so let's bail.
        if mapping_handle.is_null() {
            return Err(io::Error::last_os_error());
        }

        // Grab the size of the underlying file, this will be the size of the
        // view.
        let size = file.metadata()?.len().try_into().unwrap();

        // Map the view in the address space.
        let base = unsafe { MapViewOfFile(mapping_handle, FILE_MAP_READ, 0, 0, size) };

        // If the base address is NULL, it failed so let's bail.
        if base.is_null() {
            // Don't forget to close the HANDLE we created for the mapping.
            unsafe {
                CloseHandle(mapping_handle);
            }
            return Err(io::Error::last_os_error());
        }

        // Now we materialized a view in the address space, we can get rid of
        // the mapping handle.
        unsafe {
            CloseHandle(mapping_handle);
        }

        // Make sure the size is not bigger than what [`slice::from_raw_parts`] wants.
        assert!(size <= isize::MAX.try_into().unwrap(), "slice is too large");

        // Create the slice over the mapping.
        // SAFETY: This is safe because:
        //   - It is a byte slice, so we don't need to care about the alignment.
        //   - The base is not NULL as we've verified that it is the case above.
        //   - The underlying is owned by the type and the lifetime.
        //   - We asked the OS to map `size` bytes, so we have a guarantee that there's
        //     `size` consecutive bytes.
        //   - We never give a mutable reference to this slice, so it can't get mutated.
        //   - The total len of the slice is guaranteed to be smaller than
        //     [`isize::MAX`].
        //   - The underlying mapping, the type and the slice have the same lifetime
        //     which guarantees that we can't access the underlying once it has been
        //     unmapped (use-after-unmap).
        Ok(unsafe { slice::from_raw_parts(base, size) })
    }

    /// Unmap the memory mapped file.
    pub fn unmap_memory_mapped_file(data: &[u8]) -> Result<(), io::Error> {
        match unsafe { UnmapViewOfFile(data.as_ptr()) } {
            0 => Err(io::Error::last_os_error()),
            _ => Ok(()),
        }
    }
}

#[cfg(windows)]
use windows::{memory_map_file, unmap_memory_mapped_file};

#[cfg(unix)]
/// Module that implements memory mapping on Unix using the mmap syscall.
mod unix {
    use std::fs::File;
    use std::os::fd::AsRawFd;
    use std::{io, ptr, slice};

    const PROT_READ: i32 = 1;
    const MAP_SHARED: i32 = 1;
    const MAP_FAILED: *const u8 = usize::MAX as _;

    unsafe extern "system" {
        fn mmap(
            addr: *const u8,
            length: usize,
            prot: i32,
            flags: i32,
            fd: i32,
            offset: i32,
        ) -> *const u8;

        fn munmap(addr: *const u8, length: usize) -> i32;
    }

    pub fn memory_map_file<'map>(file: &File) -> Result<&'map [u8], io::Error> {
        // Grab the underlying file descriptor.
        let file_fd = file.as_raw_fd();

        // Grab the size of the underlying file. This will be the size of the
        // memory mapped region.
        let size = file.metadata()?.len().try_into().unwrap();

        // Mmap the file.
        let ret = unsafe { mmap(ptr::null_mut(), size, PROT_READ, MAP_SHARED, file_fd, 0) };

        // If the system call failed, bail.
        if ret == MAP_FAILED {
            return Err(io::Error::last_os_error());
        }

        // Make sure the size is not bigger than what [`slice::from_raw_parts`] wants.
        assert!(size <= isize::MAX.try_into().unwrap(), "slice is too large");

        // Create the slice over the mapping.
        // SAFETY: This is safe because:
        //   - It is a byte slice, so we don't need to care about the alignment.
        //   - The base is not NULL as we've verified that it is the case above.
        //   - The underlying is owned by the type and the lifetime.
        //   - We asked the OS to map `size` bytes, so we have a guarantee that there's
        //     `size` consecutive bytes.
        //   - We never give a mutable reference to this slice, so it can't get mutated.
        //   - The total len of the slice is guaranteed to be smaller than
        //     [`isize::MAX`].
        //   - The underlying mapping, the type and the slice have the same lifetime
        //     which guarantees that we can't access the underlying once it has been
        //     unmapped (use-after-unmap).
        Ok(unsafe { slice::from_raw_parts(ret, size) })
    }

    // Unmap a memory mapped file.
    pub fn unmap_memory_mapped_file(data: &[u8]) -> Result<(), io::Error> {
        match unsafe { munmap(data.as_ptr(), data.len()) } {
            0 => Ok(()),
            _ => Err(io::Error::last_os_error()),
        }
    }
}

#[cfg(unix)]
use unix::{memory_map_file, unmap_memory_mapped_file};

#[cfg(not(any(windows, unix)))]
/// Your system hasn't been implemented; if you do it, send a PR!
fn unimplemented() -> u32 {}
