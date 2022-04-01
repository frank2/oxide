use clap::{Arg, Command};

use liboxide::Error as OxideError;
use liboxide::*;

use exe::Error as ExeError;
use exe::*;

use pkbuffer::Error as PKError;
use pkbuffer::*;

use std::include_bytes;
use std::collections::HashMap;

#[cfg(debug_assertions)]
const UNPACK_STUB_32: &[u8] = include_bytes!("../stub/target/i686-pc-windows-msvc/debug/stub.exe");

#[cfg(debug_assertions)]
const UNPACK_STUB_64: &[u8] = include_bytes!("../stub/target/x86_64-pc-windows-msvc/debug/stub.exe");

#[cfg(not(debug_assertions))]
const UNPACK_STUB_32: &[u8] = include_bytes!("../stub/target/i686-pc-windows-msvc/release/stub.exe");

#[cfg(not(debug_assertions))]
const UNPACK_STUB_64: &[u8] = include_bytes!("../stub/target/x86_64-pc-windows-msvc/release/stub.exe");

const TLS_PROXY_32: &[u8] = include_bytes!("tls-stub-32.bin");
const TLS_PROXY_64: &[u8] = include_bytes!("tls-stub-64.bin");

enum Error {
    ExeError(ExeError),
    OxideError(OxideError),
    PKError(PKError),
    MagicOffsetNotFound(u64),
    VAMismatch,
    ResourceOutOfBounds(RVA),
    OffsetMappingNotFound(RVA),
    NoFileGiven,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::ExeError(ref e) => write!(f, "exe-rs error: {}", e.to_string()),
            Error::OxideError(ref e) => write!(f, "oxide error: {}", e.to_string()),
            Error::PKError(ref e) => write!(f, "pkbuffer error: {}", e.to_string()),
            Error::MagicOffsetNotFound(offset) => write!(f, "magic offset not found: {:#x}", offset),
            Error::VAMismatch => write!(f, "the wrong VA size was encountered"),
            Error::ResourceOutOfBounds(rva) => write!(f, "resource out of bounds: {:#x}", rva.0),
            Error::OffsetMappingNotFound(rva) => write!(f, "offset mapping not found: {:#x}", rva.0),
            Error::NoFileGiven => write!(f, "you must provide a filename to pack"),
        }
    }
}
impl std::fmt::Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::ExeError(ref e) => write!(f, "ExeError: {}", e.to_string()),
            Error::OxideError(ref e) => write!(f, "OxideError: {}", e.to_string()),
            Error::PKError(ref e) => write!(f, "PKError: {}", e.to_string()),
            Error::MagicOffsetNotFound(_) => write!(f, "MagicOffsetNotFound: {}", self.to_string()),
            Error::VAMismatch => write!(f, "VAMismatch: {}", self.to_string()),
            Error::ResourceOutOfBounds(_) => write!(f, "ResourceOutOfBounds: {}", self.to_string()),
            Error::OffsetMappingNotFound(_) => write!(f, "OffsetMappingNotFound: {}", self.to_string()),
            Error::NoFileGiven => write!(f, "NoFileGiven: {}", self.to_string()),
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::ExeError(ref e) => Some(e),
            Error::OxideError(ref e) => Some(e),
            Error::PKError(ref e) => Some(e),
            _ => None,
        }
    }
}
impl From<ExeError> for Error {
    fn from(err: ExeError) -> Self {
        Self::ExeError(err)
    }
}
impl From<OxideError> for Error {
    fn from(err: OxideError) -> Self {
        Self::OxideError(err)
    }
}
impl From<PKError> for Error {
    fn from(err: PKError) -> Self {
        Self::PKError(err)
    }
}

fn wipe_directory(image: &mut VecPE, directory: ImageDirectoryEntry) -> Result<(), Error> {
    let directory_ro = image.get_data_directory(directory)?;
    let dir_address = image.translate(PETranslation::Memory(directory_ro.virtual_address))?;
    let dir_size = directory_ro.size as usize;
    
    let mut directory = image.get_mut_data_directory(directory)?;
    directory.virtual_address = RVA(0);
    directory.size = 0;
    
    image.write(dir_address, &vec![0u8; dir_size])?;

    Ok(())
}

fn rewrite_stub(stub: &VecPE, target_image_size: usize) -> Result<VecPE, Error> {
    let section_alignment = match stub.get_valid_nt_headers() {
        Ok(h) => match h {
            NTHeaders::NTHeaders32(h32) => h32.optional_header.section_alignment as usize,
            NTHeaders::NTHeaders64(h64) => h64.optional_header.section_alignment as usize,
        },
        Err(e) => return Err(From::from(e)),
    };
    
    let target_size = align(target_image_size, section_alignment);
    let section_table = stub.get_section_table()?;
    let mut stub_section_size = 0usize;
    let mut section_characteristics = SectionCharacteristics::empty();

    // calculate the current virtual size of the section table
    for section in section_table {
        stub_section_size += align(section.virtual_size as usize, section_alignment);
        section_characteristics |= section.characteristics;
    }

    let corrected_section_size;
    
    if stub_section_size < target_image_size {
        corrected_section_size = target_size
    }
    else {
        corrected_section_size = stub_section_size;
    }

    // this is not technically a memory image, it's a memory image being treated
    // as a disk image
    let stub_memory_data = stub.recreate_image(PEType::Memory)?;
    let mut stub_pe = VecPE::from_disk_data(stub_memory_data);
    let stub_pe_ro = stub_pe.as_ptr_pe();

    // change file alignment to section alignment
    match stub_pe.get_valid_mut_nt_headers() {
        Ok(ref mut h) => match h {
            NTHeadersMut::NTHeaders32(ref mut h32) => h32.optional_header.file_alignment = h32.optional_header.section_alignment,
            NTHeadersMut::NTHeaders64(ref mut h64) => h64.optional_header.file_alignment = h64.optional_header.section_alignment,
        },
        Err(e) => return Err(From::from(e)),
    };

    // rewrite the section table so that there's only one section
    let stub_sections = stub_pe.get_mut_section_table()?;

    for i in 0..stub_sections.len() {
        let mut s = &mut stub_sections[i];

        if i != 0 {
            s.set_name(None);
            s.virtual_size = 0;
            s.virtual_address = RVA(0);
            s.size_of_raw_data = 0;
            s.pointer_to_raw_data = Offset(0);
            s.pointer_to_linenumbers = Offset(0);
            s.number_of_relocations = 0;
            s.number_of_linenumbers = 0;
            s.characteristics = SectionCharacteristics::empty();
        }
        else {
            s.pointer_to_raw_data = Offset(s.virtual_address.0);
            s.size_of_raw_data = stub_section_size as u32;
            s.virtual_size = corrected_section_size as u32;
            s.characteristics = section_characteristics;
        }
    }

    match stub_pe.get_valid_mut_nt_headers() {
        Ok(ref mut h) => match h {
            NTHeadersMut::NTHeaders32(ref mut h32) => h32.file_header.number_of_sections = 1,
            NTHeadersMut::NTHeaders64(ref mut h64) => h64.file_header.number_of_sections = 1,
        },
        Err(e) => return Err(From::from(e)),
    }

    wipe_directory(&mut stub_pe, ImageDirectoryEntry::TLS)?;

    let debug_directory = DebugDirectory::parse(&stub_pe_ro)?;
    let wipe_vec = vec![0u8; debug_directory.size_of_data as usize];
    let debug_addr = stub_pe_ro.translate(PETranslation::Disk(debug_directory.pointer_to_raw_data))?;
    stub_pe.write(debug_addr, wipe_vec)?;

    wipe_directory(&mut stub_pe, ImageDirectoryEntry::Debug)?;
        
    Ok(stub_pe)
}

fn create_or_load_rdata(stub_data: &mut VecPE) -> Result<&mut ImageSectionHeader, Error> {
    // the Rust borrow checker isn't taking into account that the match branch
    // goes out of scope of borrowing this variable because of the return keywords,
    // this is apparently a known limitation of the borrow checker. bypass the borrow
    // checker by creating a new reference
    let second_ref = unsafe { &mut *(stub_data as *mut VecPE) };

    match stub_data.get_mut_section_by_name(String::from(".rdata")) {
        Ok(s) => { return Ok(s); },
        Err(e) => {
            if let ExeError::SectionNotFound = e {}
            else { return Err(From::from(e)); }
        },
    }

    second_ref.pad_to_file_alignment()?;

    let mut section = ImageSectionHeader::default();
    section.set_name(Some(".rdata"));

    let new_section = second_ref.append_section(&section)?;
    Ok(new_section)
}

fn copy_load_config(stub_data: &mut VecPE, target_pe: &VecPE) -> Result<(), Error> {
    let directory_ro = target_pe.get_data_directory(ImageDirectoryEntry::LoadConfig)?;
    let config_address = target_pe.translate(PETranslation::Memory(directory_ro.virtual_address))?;
    let config_size = target_pe.get_ref::<u32>(config_address)?;
    let config_data = target_pe.read(config_address, *config_size as usize)?;

    let section = create_or_load_rdata(stub_data)?;
    section.size_of_raw_data += config_data.len() as u32;
    section.virtual_size = section.size_of_raw_data;
    section.characteristics |= SectionCharacteristics::CNT_INITIALIZED_DATA | SectionCharacteristics::MEM_READ;

    let config_offset = Offset(stub_data.len() as u32);

    stub_data.append(&config_data);
    stub_data.fix_image_size()?;

    let stub_pe_ro = stub_data.as_ptr_pe();
    let config_rva = config_offset.as_rva(&stub_pe_ro)?;

    let directory = stub_data.get_mut_data_directory(ImageDirectoryEntry::LoadConfig)?;

    directory.virtual_address = config_rva;
    directory.size = *config_size;

    Ok(())
}

fn append_tls_callback_stub(stub_data: &mut VecPE, callback: VA) -> Result<(usize, usize), Error> {
    let callback_offset = stub_data.len();

    let mut tls_stub = match callback {
        VA::VA32(_) => TLS_PROXY_32.to_vec(),
        VA::VA64(_) => TLS_PROXY_64.to_vec(),
    };

    let mut tls_buffer = VecBuffer::from_data(&tls_stub);
    let mut relocation_offset;

    match callback {
        VA::VA32(v32) => {
            let mut search = tls_buffer.search_ref::<u32>(&0xDEADBEEF)?;

            if let Some(found_offset) = search.next() {
                relocation_offset = found_offset;
                tls_buffer.write_ref::<u32>(relocation_offset, &v32.0)?;
            }
            else {
                return Err(Error::MagicOffsetNotFound(0xDEADBEEF));
            }
        },
        VA::VA64(v64) => {
            let mut search = tls_buffer.search_ref::<u64>(&0xDEADBEEFFACEBABE)?;

            if let Some(found_offset) = search.next() {
                relocation_offset = found_offset;
                tls_buffer.write_ref::<u64>(relocation_offset, &v64.0)?;
            }
            else {
                return Err(Error::MagicOffsetNotFound(0xDEADBEEFFACEBABE));
            }
        },
    }

    relocation_offset += callback_offset;
    stub_data.append(&mut tls_stub);

    Ok((callback_offset, relocation_offset))
}

fn copy_tls(stub_data: &mut VecPE, target_pe: &VecPE) -> Result<(), Error> {
    let target_tls_directory = TLSDirectory::parse(target_pe)?;
    let target_tls_data = match target_tls_directory {
        TLSDirectory::TLS32(tls32) => tls32.read(target_pe)?,
        TLSDirectory::TLS64(tls64) => tls64.read(target_pe)?,
    };

    // get the VAs to the callbacks in the callback array as we'll be replacing a pointer in the TLS callback stub assembly
    let callbacks: Vec<VA> = match target_tls_directory {
        TLSDirectory::TLS32(tls32) => {
            let callbacks = tls32.get_callbacks(target_pe)?;
            callbacks.iter()
                .map(|x| x.as_va(target_pe))
                .collect::<Result<Vec<VA>, ExeError>>()?
        },
        TLSDirectory::TLS64(tls64) => {
            let callbacks = tls64.get_callbacks(target_pe)?;
            callbacks.iter()
                .map(|x| x.as_va(target_pe))
                .collect::<Result<Vec<VA>, ExeError>>()?
        },
    };

    let size_of_zero_fill = match target_tls_directory {
        TLSDirectory::TLS32(tls32) => tls32.size_of_zero_fill,
        TLSDirectory::TLS64(tls64) => tls64.size_of_zero_fill,
    };

    let characteristics = match target_tls_directory {
        TLSDirectory::TLS32(tls32) => tls32.characteristics,
        TLSDirectory::TLS64(tls64) => tls64.characteristics,
    };

    // we don't want the section yet, just create it if it doesn't exist yet
    let _ = create_or_load_rdata(stub_data);
    
    let data_start_offset = stub_data.len();
    stub_data.append(&target_tls_data);
    let data_end_offset = stub_data.len();

    let index_offset = data_end_offset;
    stub_data.append_ref(&0u32)?;

    let mut tls_proxies = Vec::<usize>::new();
    let mut relocations = Vec::<usize>::new();

    for callback in &callbacks {
        let (proxy, relocation) = append_tls_callback_stub(stub_data, *callback)?;

        tls_proxies.push(proxy);
        relocations.push(relocation);
    }

    let callbacks_offset = stub_data.len();

    match target_tls_directory {
        TLSDirectory::TLS32(_) => {
            stub_data.append(&vec![0u8; (callbacks.len()+1) * std::mem::size_of::<VA32>()]);

            for i in 0..callbacks.len() {
                relocations.push(callbacks_offset + (i * std::mem::size_of::<VA32>()));
            }
        },
        TLSDirectory::TLS64(_) => {
            stub_data.append(&vec![0u8; (callbacks.len()+1) * std::mem::size_of::<VA64>()]);

            for i in 0..callbacks.len() {
                relocations.push(callbacks_offset + (i * std::mem::size_of::<VA64>()));
            }
        },
    }

    let new_directory_offset = stub_data.len();

    match target_tls_directory {
        TLSDirectory::TLS32(_) => stub_data.append(&vec![0u8; std::mem::size_of::<ImageTLSDirectory32>()]),
        TLSDirectory::TLS64(_) => stub_data.append(&vec![0u8; std::mem::size_of::<ImageTLSDirectory64>()]),
    }

    let tls_data_size = stub_data.len() - data_start_offset;

    let rdata_section = create_or_load_rdata(stub_data)?;
    rdata_section.size_of_raw_data += tls_data_size as u32;
    rdata_section.virtual_size += tls_data_size as u32;
    rdata_section.characteristics |= SectionCharacteristics::MEM_READ;
    rdata_section.characteristics |= SectionCharacteristics::MEM_WRITE;
    rdata_section.characteristics |= SectionCharacteristics::MEM_EXECUTE;
    rdata_section.characteristics |= SectionCharacteristics::CNT_UNINITIALIZED_DATA;

    stub_data.fix_image_size()?;

    let stub_pe_ro = stub_data.as_ptr_pe();

    // get offsets of VAs of new header and add them to relocations
    match target_tls_directory {
        TLSDirectory::TLS32(_) => {
            let header = stub_pe_ro.get_ref::<ImageTLSDirectory32>(new_directory_offset)?;
            let start_addr = stub_pe_ro.ref_to_offset(&header.start_address_of_raw_data)?;
            relocations.push(start_addr);

            let end_addr = stub_pe_ro.ref_to_offset(&header.end_address_of_raw_data)?;
            relocations.push(end_addr);

            let index_addr = stub_pe_ro.ref_to_offset(&header.address_of_index)?;
            relocations.push(index_addr);
            
            let callback_addr = stub_pe_ro.ref_to_offset(&header.address_of_callbacks)?;
            relocations.push(callback_addr);
        },
        TLSDirectory::TLS64(_) => {
            let header = stub_pe_ro.get_ref::<ImageTLSDirectory64>(new_directory_offset)?;
            let start_addr = stub_pe_ro.ref_to_offset(&header.start_address_of_raw_data)?;
            relocations.push(start_addr);

            let end_addr = stub_pe_ro.ref_to_offset(&header.end_address_of_raw_data)?;
            relocations.push(end_addr);

            let index_addr = stub_pe_ro.ref_to_offset(&header.address_of_index)?;
            relocations.push(index_addr);
            
            let callback_addr = stub_pe_ro.ref_to_offset(&header.address_of_callbacks)?;
            relocations.push(callback_addr);
        },
    }
        
    // convert data start/end offsets into VAs
    let data_start_va = Offset(data_start_offset as u32).as_va(&stub_pe_ro)?;
    let data_end_va = Offset(data_end_offset as u32).as_va(&stub_pe_ro)?;

    // convert the address of index into a VA
    let index_va = Offset(index_offset as u32).as_va(&stub_pe_ro).unwrap();
    
    // convert address of callbacks into a VA
    let callbacks_va = Offset(callbacks_offset as u32).as_va(&stub_pe_ro).unwrap();
    
    // convert TLS proxies into VAs
    let tls_proxies_va: Vec<VA> = tls_proxies.iter()
        .map(|x| Offset(*x as u32).as_va(&stub_pe_ro))
        .collect::<Result<Vec<VA>, ExeError>>()?;
    
    // convert relocations into RVAs
    let relocations_rva: Vec<RVA> = relocations.iter()
        .map(|x| Offset(*x as u32).as_rva(&stub_pe_ro))
        .collect::<Result<Vec<RVA>, ExeError>>()?;
    
    // convert directory offset into an RVA
    let new_directory_rva = Offset(new_directory_offset as u32).as_rva(&stub_pe_ro)?;

    // get the TLS directory and update it
    let stub_tls_data_dir = stub_data.get_mut_data_directory(ImageDirectoryEntry::TLS)?;
    stub_tls_data_dir.virtual_address = new_directory_rva;
    stub_tls_data_dir.size = match target_tls_directory {
        TLSDirectory::TLS32(_) => std::mem::size_of::<ImageTLSDirectory32>() as u32,
        TLSDirectory::TLS64(_) => std::mem::size_of::<ImageTLSDirectory64>() as u32,
    };

    // get the TLS header and update it
    match target_tls_directory {
        TLSDirectory::TLS32(_) => {
            let header = stub_data.get_mut_ref::<ImageTLSDirectory32>(new_directory_offset)?;

            header.start_address_of_raw_data = match data_start_va {
                VA::VA32(v32) => v32,
                VA::VA64(_) => return Err(Error::VAMismatch),
            };
            header.end_address_of_raw_data = match data_end_va {
                VA::VA32(v32) => v32,
                VA::VA64(_) => return Err(Error::VAMismatch),
            };
            header.address_of_index = match index_va {
                VA::VA32(v32) => v32,
                VA::VA64(_) => return Err(Error::VAMismatch),
            };
            header.address_of_callbacks = match callbacks_va {
                VA::VA32(v32) => v32,
                VA::VA64(_) => return Err(Error::VAMismatch),
            };
            header.size_of_zero_fill = size_of_zero_fill;
            header.characteristics = characteristics;
        },
        TLSDirectory::TLS64(_) => {
            let header = stub_data.get_mut_ref::<ImageTLSDirectory64>(new_directory_offset)?;

            header.start_address_of_raw_data = match data_start_va {
                VA::VA64(v64) => v64,
                VA::VA32(_) => return Err(Error::VAMismatch),
            };
            header.end_address_of_raw_data = match data_end_va {
                VA::VA64(v64) => v64,
                VA::VA32(_) => return Err(Error::VAMismatch),
            };
            header.address_of_index = match index_va {
                VA::VA64(v64) => v64,
                VA::VA32(_) => return Err(Error::VAMismatch),
            };
            header.address_of_callbacks = match callbacks_va {
                VA::VA64(v64) => v64,
                VA::VA32(_) => return Err(Error::VAMismatch),
            };
            header.size_of_zero_fill = size_of_zero_fill;
            header.characteristics = characteristics;
        },
    }

    // get the callback array and fill it
    match target_tls_directory {
        TLSDirectory::TLS32(_) => {
            let callback_array = stub_data.get_mut_slice_ref::<VA32>(callbacks_offset, callbacks.len())?;

            for i in 0..callbacks.len() {
                match tls_proxies_va[i] {
                    VA::VA32(v32) => callback_array[i] = v32,
                    VA::VA64(_) => return Err(Error::VAMismatch),
                }
            }
        },
        TLSDirectory::TLS64(_) => {
            let callback_array = stub_data.get_mut_slice_ref::<VA64>(callbacks_offset, callbacks.len())?;

            for i in 0..callbacks.len() {
                match tls_proxies_va[i] {
                    VA::VA64(v64) => callback_array[i] = v64,
                    VA::VA32(_) => return Err(Error::VAMismatch),
                }
            }
       },
    }

    // add the new relocations
    let mut relocation_dir = RelocationDirectory::parse(&stub_pe_ro)?;

    // Rust really hates mutable borrows in a loop. this apparently gets fixed
    // in the polonius borrow checker (https://github.com/rust-lang/polonius),
    // so for now just do some pointer magic.
    for relocation in relocations_rva {
        relocation_dir.add_relocation(unsafe { &mut *(stub_data as *mut VecPE) }, relocation)?;
    }

    Ok(())
}

fn copy_resources(stub_data: &mut VecPE, target_pe: &VecPE) -> Result<(), Error> {
    let target_rsrc_data_dir = target_pe.get_data_directory(ImageDirectoryEntry::Resource)?;
    let target_rsrc_directory = ResourceDirectory::parse(target_pe)?;
    let rsrc_start = target_rsrc_data_dir.virtual_address;
    let rsrc_end = RVA(rsrc_start.0 + target_rsrc_data_dir.size);
    let rsrc_section = target_pe.get_section_by_rva(rsrc_start)?;
    let rsrc_data = rsrc_section.read(target_pe)?;

    // first, map the RVAs to resource offsets and get their sizes
    let mut offset_map = HashMap::<u32, ResourceOffset>::new();

    for rsrc in target_rsrc_directory.resources {
        let data_entry = rsrc.get_data_entry(target_pe)?;

        if data_entry.offset_to_data.0 < rsrc_start.0 || data_entry.offset_to_data.0 >= rsrc_end.0 {
            return Err(Error::ResourceOutOfBounds(data_entry.offset_to_data));
        }

        let rsrc_offset = ResourceOffset(data_entry.offset_to_data.0 - rsrc_start.0);

        offset_map.insert(data_entry.offset_to_data.0, rsrc_offset);
    }

    let mut stub_rsrc_section = ImageSectionHeader::default();
    stub_rsrc_section.set_name(Some(".rsrc"));
    stub_rsrc_section.size_of_raw_data = rsrc_data.len() as u32;
    stub_rsrc_section.virtual_size = stub_rsrc_section.size_of_raw_data;
    stub_rsrc_section.characteristics = rsrc_section.characteristics;

    stub_data.pad_to_file_alignment()?;
    stub_data.append(&rsrc_data.to_vec());

    let stub_rsrc_section = stub_data.append_section(&stub_rsrc_section)?;
    let stub_rsrc_rva = stub_rsrc_section.virtual_address;

    let stub_rsrc_data_dir = stub_data.get_mut_data_directory(ImageDirectoryEntry::Resource)?;
    stub_rsrc_data_dir.virtual_address = stub_rsrc_rva;
    stub_rsrc_data_dir.size = rsrc_data.len() as u32;

    stub_data.fix_image_size()?;

    let stub_pe_ro = stub_data.as_ptr_pe();
    let stub_rsrc_dir = ResourceDirectory::parse(&stub_pe_ro)?;

    for rsrc in stub_rsrc_dir.resources {
        let mut data_entry = rsrc.get_mut_data_entry(stub_data)?;

        let rsrc_offset = match offset_map.get(&data_entry.offset_to_data.0) {
            None => return Err(Error::OffsetMappingNotFound(data_entry.offset_to_data)),
            Some(ro) => ro,
        };

        let rva = stub_pe_ro.get_resource_address(*rsrc_offset)?;
        data_entry.offset_to_data = rva;
    }

    Ok(())
}

fn pack_pe(stub_pe: &mut VecPE, target_pe: &VecPE) -> Result<(), Error> {
    let (target_base, characteristics, subsystem) = match target_pe.get_valid_nt_headers() {
        Ok(h) => match h {
            NTHeaders::NTHeaders32(h32) => (h32.optional_header.image_base as usize,
                                            h32.optional_header.dll_characteristics,
                                            h32.optional_header.subsystem),
            NTHeaders::NTHeaders64(h64) => (h64.optional_header.image_base as usize,
                                            h64.optional_header.dll_characteristics,
                                            h64.optional_header.subsystem),
        },
        Err(e) => return Err(From::from(e)),
    };

    println!("[+] packing binary (this might take a bit)");
    let oxide_data = OxideData::pack(target_pe.as_slice())?;
    println!("[+] converting to bytes");
    let oxide_bytes = oxide_data.to_bytes()?;
    let mut oxide_section = ImageSectionHeader::default();
    oxide_section.set_name(Some(".odata"));

    println!("[+] creating oxide section");
    let oxide_section = stub_pe.append_section(&oxide_section)?;
    oxide_section.size_of_raw_data = oxide_bytes.len() as u32;
    oxide_section.virtual_size = oxide_section.size_of_raw_data;
    oxide_section.characteristics = SectionCharacteristics::CNT_INITIALIZED_DATA | SectionCharacteristics::MEM_READ;

    println!("[+] padding to file alignment");
    stub_pe.pad_to_file_alignment()?;
    stub_pe.append(&oxide_bytes);
    println!("[+] fixing image size");
    stub_pe.fix_image_size()?;

    if target_pe.has_data_directory(ImageDirectoryEntry::LoadConfig) {
        println!("[+] copying load config");
        copy_load_config(stub_pe, target_pe)?;
    }

    if target_pe.has_data_directory(ImageDirectoryEntry::TLS) {
        println!("[+] copying TLS directory");
        copy_tls(stub_pe, target_pe)?;
    }
    
    if target_pe.has_data_directory(ImageDirectoryEntry::Resource) {
        println!("[+] copying resources");
        copy_resources(stub_pe, target_pe)?;
    }

    let stub_pe_ro = stub_pe.as_ptr_pe();
    println!("[+] recalculating memory size");
    let new_image_size = stub_pe_ro.calculate_memory_size()?;
    println!("[+] parsing relocation directory");
    let relocation_directory = RelocationDirectory::parse(&stub_pe_ro)?;
    println!("[+] relocating binary");
    relocation_directory.relocate(stub_pe, target_base as u64)?;

    match stub_pe.get_valid_mut_nt_headers() {
        Ok(ref mut h) => match h {
            NTHeadersMut::NTHeaders32(ref mut h32) => {
                h32.optional_header.size_of_image = new_image_size as u32;
                h32.optional_header.image_base = target_base as u32;
                h32.optional_header.subsystem = subsystem;
            },
            NTHeadersMut::NTHeaders64(ref mut h64) => {
                h64.optional_header.size_of_image = new_image_size as u32;
                h64.optional_header.image_base = target_base as u64;
                h64.optional_header.subsystem = subsystem;
            },
        },
        Err(e) => return Err(From::from(e)),
    }

    // disable the relocation directory if the original binary doesn't have DYNAMIC_BASE set
    let bit_check = characteristics & DLLCharacteristics::DYNAMIC_BASE;

    if bit_check.bits() == 0 {
        println!("[+] wiping relocation directory");
        wipe_directory(stub_pe, ImageDirectoryEntry::BaseReloc)?;

        match stub_pe.get_valid_mut_nt_headers() {
            Ok(ref mut h) => match h {
                NTHeadersMut::NTHeaders32(ref mut h32) => h32.optional_header.dll_characteristics ^= DLLCharacteristics::DYNAMIC_BASE,
                NTHeadersMut::NTHeaders64(ref mut h64) => h64.optional_header.dll_characteristics ^= DLLCharacteristics::DYNAMIC_BASE,
            },
            Err(e) => return Err(From::from(e)),
        }
    }

    Ok(())
}

fn main() -> Result<(), Error> {
    let app = Command::new("OXiDE")
        .version("0.2.0")
        .about("A Rust packer.")
        .arg(Arg::new("file")
             .short('f')
             .long("file")
             .takes_value(true)
             .help("The executable to pack. Currently supports 32- and 64-bit executables."))
        .arg(Arg::new("output")
             .short('o')
             .long("output")
             .takes_value(true)
             .help("The location of the packed file. Defaults to \"packed.exe\" in the working directory."));
    let version_string = format!("{} {}", app.get_name(), app.get_version().unwrap());
    let matches = app.get_matches().clone();

    let filename = match matches.value_of("file") {
        None => return Err(Error::NoFileGiven),
        Some(s) => s,
    };

    let output = match matches.value_of("output") {
        None => "packed.exe".to_string(),
        Some(s) => s.to_string(),
    };

    println!("== {} ==\n", version_string);

    let pefile = VecPE::from_disk_file(filename)?;
    let arch = pefile.get_arch()?;

    let image_size = match pefile.get_valid_nt_headers() {
        Ok(h) => match h {
            NTHeaders::NTHeaders32(h32) => h32.optional_header.size_of_image as usize,
            NTHeaders::NTHeaders64(h64) => h64.optional_header.size_of_image as usize,
        },
        Err(e) => return Err(From::from(e)),
    };
    
    let stub_image = match arch {
        Arch::X86 => VecPE::from_disk_data(UNPACK_STUB_32),
        Arch::X64 => VecPE::from_disk_data(UNPACK_STUB_64),
    };

    let mut rewritten = rewrite_stub(&stub_image, image_size)?;
    pack_pe(&mut rewritten, &pefile)?;

    rewritten.save(&output)?;
    println!("\n[!] {} packed to {}", filename, output);

    Ok(())
}
