// #![windows_subsystem = "windows"]

use std::ffi::CString;
use std::include_bytes;

use exe::*;

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
    LPCSTR,
};

#[cfg(target_arch="x86")]
const TRAMPOLINE: &[u8] = include_bytes!("trampoline-32.bin");

#[cfg(target_arch="x86_64")]
const TRAMPOLINE: &[u8] = include_bytes!("trampoline-64.bin");

fn resolve_function(lib: CString, func: CString) -> FARPROC {
    let module = unsafe { LoadLibraryA(lib.as_c_str().as_ptr()) };

    if module == std::ptr::null_mut() {
        panic!("couldn't load library");
    }

    let proc_address = unsafe { GetProcAddress(module, func.as_c_str().as_ptr()) };

    if proc_address == std::ptr::null_mut() {
        panic!("couldn't resolve function");
    }

    proc_address
}

fn main() -> Result<(), std::io::Error> {
    let hmodule = unsafe { GetModuleHandleA(std::ptr::null()) };
    let pefile = unsafe { PE::from_ptr(hmodule as *const u8).unwrap() };
    let section = pefile.get_section_by_name(".odata".to_string()).unwrap();
    let section_data = section.read(&pefile).unwrap();
    let oxide_data = OxideData::parse(section_data).unwrap();
    let unpacked_data = oxide_data.unpack();
    let unpacked_pefile_disk = PE::new_disk(unpacked_data.as_slice());
    let ptr_size = std::mem::size_of::<usize>();
    let unpacked_arch = unpacked_pefile_disk.get_arch().unwrap();

    match unpacked_arch {
        Arch::X86 => { if ptr_size == 8 { panic!("bad architecture"); } },
        Arch::X64 => { if ptr_size == 4 { panic!("bad architecture"); } },
    }

    let recreated_image = unpacked_pefile_disk.recreate_image(PEType::Memory).unwrap();
    let unpacked_buffer = unsafe { VirtualAlloc(std::ptr::null_mut(),
                                                recreated_image.len() as SIZE_T,
                                                MEM_COMMIT | MEM_RESERVE,
                                                PAGE_READWRITE) };

    if unpacked_buffer == std::ptr::null_mut() {
        panic!("couldn't get virtual buffer: {}", unsafe { GetLastError() });
    }

    unsafe { std::ptr::copy(recreated_image.as_ptr(), unpacked_buffer as *mut u8, recreated_image.len()) };
    
    let unpacked_slice = unsafe { std::slice::from_raw_parts_mut(unpacked_buffer as *mut u8, recreated_image.len()) };
    let mut unpacked_pefile_memory = PE::new_mut_memory(unpacked_slice);

    // resolve the imports
    if unpacked_pefile_memory.has_data_directory(ImageDirectoryEntry::Import) {
        let import_directory = ImportDirectory::parse(&unpacked_pefile_memory).unwrap();
        let descriptors = import_directory.descriptors.iter().cloned().collect::<Vec<ImageImportDescriptor>>();

        for descriptor in descriptors {
            let dll_name = descriptor.get_name(&unpacked_pefile_memory).unwrap().as_str();
            let dll_handle = unsafe { LoadLibraryA(dll_name.as_ptr() as LPCSTR) };

            if dll_handle == std::ptr::null_mut() {
                panic!("couldn't load DLL");
            }

            let lookup_table: Vec<Thunk> = match descriptor.get_original_first_thunk(&unpacked_pefile_memory) {
                Ok(l) => l,
                Err(_) => match descriptor.get_first_thunk(&unpacked_pefile_memory) {
                    Ok(l2) => l2,
                    Err(_) => panic!("couldn't get ILT"),
                }
            };

            let mut lookup_results = Vec::<FARPROC>::new();

            for lookup in lookup_table {
                let thunk_data = match lookup {
                    Thunk::Thunk32(t32) => t32.parse_import(),
                    Thunk::Thunk64(t64) => t64.parse_import(),
                };

                let thunk_result = match thunk_data {
                    ThunkData::Ordinal(o) => unsafe { GetProcAddress(dll_handle, o as LPCSTR) },
                    ThunkData::ImportByName(rva) => {
                        let import_by_name = ImageImportByName::parse(&unpacked_pefile_memory, rva).unwrap();

                        unsafe { GetProcAddress(dll_handle, import_by_name.name.as_str().as_ptr() as LPCSTR) }
                    },
                    _ => panic!("bad thunk"),
                };

                if thunk_result == std::ptr::null_mut() {
                    panic!("couldn't get function");
                }

                lookup_results.push(thunk_result);
            }
            
            let mut address_table = descriptor.get_mut_first_thunk(&mut unpacked_pefile_memory).unwrap();

            if address_table.len() != lookup_results.len() {
                panic!("ILT/IAT mismatch");
            }

            for i in 0..address_table.len() {
                let lookup_entry = &lookup_results[i];
                let address_entry = &mut address_table[i];
                
                match address_entry {
                    ThunkMut::Thunk32(ref mut t32) => **t32 = Thunk32(*lookup_entry as u32),
                    ThunkMut::Thunk64(ref mut t64) => **t64 = Thunk64(*lookup_entry as u64),
                }
            }
        }
    }

    // relocate the image if it has a relocation directory
    if unpacked_pefile_memory.has_data_directory(ImageDirectoryEntry::BaseReloc) {
        let relocation_directory = RelocationDirectory::parse(&unpacked_pefile_memory).unwrap();
        
        // clone the pefile so it doesn't complain, it'll still operate on the same memory space anyway
        let mut unpacked_cloned = unpacked_pefile_memory.clone();
        relocation_directory.relocate(&mut unpacked_cloned, hmodule as u64).unwrap();
    }

    // grab some functions for the trampoline
    let kernel32 = unsafe { LoadLibraryA(CString::new("kernel32.dll").unwrap().as_c_str().as_ptr()) };

    if kernel32 == std::ptr::null_mut() {
        panic!("couldn't load kernel32");
    }

    let virtual_protect = resolve_function(CString::new("kernel32.dll").unwrap(), CString::new("VirtualProtect").unwrap());
    let virtual_query = resolve_function(CString::new("kernel32.dll").unwrap(), CString::new("VirtualQuery").unwrap());
    let get_commandline = resolve_function(CString::new("kernel32.dll").unwrap(), CString::new("GetCommandLineA").unwrap());
    let add_vectored_exception_handler = resolve_function(CString::new("kernel32.dll").unwrap(), CString::new("AddVectoredExceptionHandler").unwrap());
    let remove_vectored_exception_handler = resolve_function(CString::new("kernel32.dll").unwrap(), CString::new("RemoveVectoredExceptionHandler").unwrap());
    
    // allocate and call the trampoline
    let entrypoint = unpacked_pefile_memory.get_entrypoint().unwrap();
    let trampoline_data = unsafe { VirtualAlloc(std::ptr::null_mut(),
                                                TRAMPOLINE.len(),
                                                MEM_COMMIT | MEM_RESERVE,
                                                PAGE_EXECUTE_READWRITE) };

    if trampoline_data == std::ptr::null_mut() {
        panic!("couldn't allocate trampoline");
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
