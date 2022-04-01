// #![windows_subsystem = "windows"]

use std::ffi::CString;
use std::include_bytes;

use exe::Error as ExeError;
use exe::*;

use liboxide::Error as OxideError;
use liboxide::*;

use winapi::shared::minwindef::{LPVOID, FARPROC};
use winapi::shared::basetsd::SIZE_T;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::libloaderapi::{LoadLibraryA, GetProcAddress, GetModuleHandleA};
use winapi::um::memoryapi::{VirtualAlloc};
use winapi::um::winnt::{
    MEM_COMMIT,
    MEM_RESERVE,
    PAGE_EXECUTE_READWRITE,
    PAGE_READWRITE,
};

#[derive(Debug)]
enum Error {
    IoError(std::io::Error),
    ExeError(ExeError),
    OxideError(OxideError),
    BadString(CString),
    LibraryNotFound(String, u32),
    FunctionNotFound(String, String),
    ArchitectureMismatch(Arch, Arch),
    AllocationFailure(u32),
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::IoError(ref e) => write!(f, "i/o error: {}", e.to_string()),
            Error::ExeError(ref e) => write!(f, "exe-rs error: {}", e.to_string()),
            Error::OxideError(ref e) => write!(f, "oxide error: {}", e.to_string()),
            Error::BadString(_) => write!(f, "bad C string given"),
            Error::LibraryNotFound(lib, err) => write!(f, "library not found: {} (error {:#x})", lib, err),
            Error::FunctionNotFound(lib, func) => write!(f, "function not found: {}::{}", lib, func),
            Error::ArchitectureMismatch(expected, got) => write!(f, "architecture mismatch: expected {:?}, got {:?}", expected, got),
            Error::AllocationFailure(err) => write!(f, "allocation failure: error {:#x}", err),
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::IoError(ref e) => Some(e),
            Error::ExeError(ref e) => Some(e),
            Error::OxideError(ref e) => Some(e),
            _ => None,
        }
    }
}
impl From<std::io::Error> for Error {
    fn from(io_err: std::io::Error) -> Self {
        Self::IoError(io_err)
    }
}
impl From<ExeError> for Error {
    fn from(exe_err: ExeError) -> Self {
        Self::ExeError(exe_err)
    }
}
impl From<OxideError> for Error {
    fn from(oxide_err: OxideError) -> Self {
        Self::OxideError(oxide_err)
    }
}

#[cfg(target_arch="x86")]
const TRAMPOLINE: &[u8] = include_bytes!("trampoline-32.bin");

#[cfg(target_arch="x86_64")]
const TRAMPOLINE: &[u8] = include_bytes!("trampoline-64.bin");

fn resolve_function(lib: CString, func: CString) -> Result<FARPROC, Error> {
    let lib_str = match lib.to_str() {
        Ok(s) => s,
        Err(_) => return Err(Error::BadString(lib)),
    };
    let func_str = match func.to_str() {
        Ok(s) => s,
        Err(_) => return Err(Error::BadString(func)),
    };
    
    let module = unsafe { LoadLibraryA(lib.as_c_str().as_ptr()) };

    if module == std::ptr::null_mut() {
        return Err(Error::LibraryNotFound(lib_str.to_string(), unsafe { GetLastError() }));
    }

    let proc_address = unsafe { GetProcAddress(module, func.as_c_str().as_ptr()) };

    if proc_address == std::ptr::null_mut() {
        return Err(Error::FunctionNotFound(lib_str.to_string(), func_str.to_string()));
    }

    Ok(proc_address)
}

fn main() -> Result<(), Error> {
    let hmodule = unsafe { GetModuleHandleA(std::ptr::null()) };
    let pefile = unsafe { PtrPE::from_memory(hmodule as *const u8)? };
    let section = pefile.get_section_by_name(".odata".to_string())?;
    let section_data = section.read(&pefile)?;
    let oxide_data = OxideData::parse(section_data)?;
    let unpacked_data = oxide_data.unpack()?;
    let unpacked_pefile_disk = VecPE::from_disk_data(&unpacked_data);
    let ptr_size = std::mem::size_of::<usize>();
    let unpacked_arch = unpacked_pefile_disk.get_arch()?;

    match unpacked_arch {
        Arch::X86 => { if ptr_size == 8 { return Err(Error::ArchitectureMismatch(Arch::X86, Arch::X64)); } },
        Arch::X64 => { if ptr_size == 4 { return Err(Error::ArchitectureMismatch(Arch::X64, Arch::X86)); } },
    }

    let recreated_image = unpacked_pefile_disk.recreate_image(PEType::Memory)?;
    let unpacked_buffer = unsafe { VirtualAlloc(std::ptr::null_mut(),
                                                recreated_image.len() as SIZE_T,
                                                MEM_COMMIT | MEM_RESERVE,
                                                PAGE_READWRITE) };

    if unpacked_buffer == std::ptr::null_mut() {
        return Err(Error::AllocationFailure(unsafe { GetLastError() }));
    }

    unsafe { std::ptr::copy(recreated_image.as_ptr(), unpacked_buffer as *mut u8, recreated_image.len()) };
    let mut unpacked_pefile_memory = PtrPE::new_memory(unpacked_buffer as *const u8, recreated_image.len());
    let unpacked_pefile_memory_ro = unpacked_pefile_memory.clone();

    // resolve the imports
    if unpacked_pefile_memory.has_data_directory(ImageDirectoryEntry::Import) {
        let import_directory = ImportDirectory::parse(&unpacked_pefile_memory_ro)?;
        import_directory.resolve_iat(&mut unpacked_pefile_memory)?;
    }

    // relocate the image if it has a relocation directory
    if unpacked_pefile_memory.has_data_directory(ImageDirectoryEntry::BaseReloc) {
        let relocation_directory = RelocationDirectory::parse(&unpacked_pefile_memory_ro)?;
        relocation_directory.relocate(&mut unpacked_pefile_memory, hmodule as u64)?;
    }

    // grab some functions for the trampoline
    let virtual_protect = resolve_function(CString::new("kernel32.dll").unwrap(), CString::new("VirtualProtect").unwrap())?;
    let virtual_query = resolve_function(CString::new("kernel32.dll").unwrap(), CString::new("VirtualQuery").unwrap())?;
    let get_commandline = resolve_function(CString::new("kernel32.dll").unwrap(), CString::new("GetCommandLineA").unwrap())?;
    let add_vectored_exception_handler = resolve_function(CString::new("kernel32.dll").unwrap(), CString::new("AddVectoredExceptionHandler").unwrap())?;
    let remove_vectored_exception_handler = resolve_function(CString::new("kernel32.dll").unwrap(), CString::new("RemoveVectoredExceptionHandler").unwrap())?;
    
    // allocate and call the trampoline
    let entrypoint = unpacked_pefile_memory.get_entrypoint().unwrap();
    let trampoline_data = unsafe { VirtualAlloc(std::ptr::null_mut(),
                                                TRAMPOLINE.len(),
                                                MEM_COMMIT | MEM_RESERVE,
                                                PAGE_EXECUTE_READWRITE) };

    if trampoline_data == std::ptr::null_mut() {
        return Err(Error::AllocationFailure(unsafe { GetLastError() }));
    }

    unsafe { std::ptr::copy(TRAMPOLINE.as_ptr(), trampoline_data as *mut u8, TRAMPOLINE.len()) };
                                                
    type Trampoline = unsafe extern "system" fn(
        *mut u8,
        *const u8,
        usize,
        u32,
        FARPROC,
        FARPROC,
        FARPROC,
        FARPROC,
        FARPROC,
    );
        
    let trampoline_fn = unsafe { std::mem::transmute::<LPVOID,Trampoline>(trampoline_data) };

    unsafe { trampoline_fn(hmodule as *mut u8,
                           unpacked_buffer as *const u8,
                           recreated_image.len(),
                           entrypoint.0,
                           virtual_protect,
                           virtual_query,
                           get_commandline,
                           add_vectored_exception_handler,
                           remove_vectored_exception_handler,
    )};

    Ok(())
}
