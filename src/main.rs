use clap::{Arg, App};

use liboxide::*;

use exe::*;

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

fn pad_to_file_alignment(data: &mut Vec<u8>) {
    let data_ro = data.clone();
    let pe_ro = PE::new_disk(data_ro.as_slice());

    let current_offset = Offset(data.len() as u32);
    let aligned_offset = pe_ro.align_to_file(current_offset).unwrap();
    let padding = (aligned_offset.0 - current_offset.0) as usize;

    if padding != 0 { data.append(&mut vec![0u8; padding]); }
}

fn fix_image_size(data: &mut Vec<u8>) {
    let data_ro = data.clone();
    let pe_ro = PE::new_disk(data_ro.as_slice());

    let mem_size = pe_ro.calculate_memory_size().unwrap();
    
    let mut pe = PE::new_mut_disk(data.as_mut_slice());

    match pe.get_valid_mut_nt_headers() {
        Ok(ref mut h) => match h {
            NTHeadersMut::NTHeaders32(ref mut h32) => h32.optional_header.size_of_image = mem_size as u32,
            NTHeadersMut::NTHeaders64(ref mut h64) => h64.optional_header.size_of_image = mem_size as u32,
        },
        Err(e) => panic!("couldn't get NT headers: {:?}", e),
    }
}

fn wipe_directory(image: &mut PE, directory: ImageDirectoryEntry) {
    let directory_ro = match image.get_data_directory(directory) {
        Ok(d) => d,
        Err(e) => panic!("couldn't get directory: {:?}", e),
    };

    let dir_address = directory_ro.virtual_address.as_offset(image).unwrap();
    let dir_size = directory_ro.size as usize;
    
    let mut directory = match image.get_mut_data_directory(directory) {
        Ok(d) => d,
        Err(e) => panic!("couldn't get directory: {:?}", e),
    };

    directory.virtual_address = RVA(0);
    directory.size = 0;

    let wipe_vec = vec![0u8; dir_size];
    
    image.buffer.write(dir_address, wipe_vec.as_slice()).ok();
}

fn rewrite_stub(stub: Vec<u8>, target_image_size: usize) -> Vec<u8> {
    let stub_disk = PE::new_disk(stub.as_slice());

    let target_size = stub_disk.align_to_section(RVA(target_image_size as u32)).unwrap().0 as usize;

    let section_table = stub_disk.get_section_table().unwrap();
    let mut stub_section_size = 0usize;
    let mut section_characteristics = SectionCharacteristics::empty();

    // calculate the current virtual size of the section table
    for section in section_table {
        stub_section_size += stub_disk.align_to_section(RVA(section.virtual_size)).unwrap().0 as usize;
        section_characteristics |= section.characteristics;
    }

    let corrected_section_size;
    
    if stub_section_size < target_image_size {
        corrected_section_size = target_size
    }
    else {
        corrected_section_size = stub_section_size;
    }

    let stub_data_ro = stub_disk.recreate_image(PEType::Memory).unwrap();
    let stub_pe_ro = PE::new_memory(stub_data_ro.as_slice());
    
    let mut stub_data = stub_data_ro.clone();
    let mut stub_pe = PE::new_mut_memory(stub_data.as_mut_slice());

    // change file alignment to section alignment
    match stub_pe.get_valid_mut_nt_headers() {
        Ok(ref mut h) => match h {
            NTHeadersMut::NTHeaders32(ref mut h32) => h32.optional_header.file_alignment = h32.optional_header.section_alignment,
            NTHeadersMut::NTHeaders64(ref mut h64) => h64.optional_header.file_alignment = h64.optional_header.section_alignment,
        },
        Err(_) => panic!("couldn't get NT headers of stub"),
    };

    // rewrite the section table so that there's only one section
    let stub_sections = stub_pe.get_mut_section_table().unwrap();

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
        Err(_) => panic!("couldn't get NT headers of stub image"),
    }

    wipe_directory(&mut stub_pe, ImageDirectoryEntry::TLS);

    let debug_directory = match DebugDirectory::parse(&stub_pe_ro) {
        Ok(d) => d,
        Err(e) => panic!("couldn't get debug directory: {:?}", e),
    };

    let wipe_vec = vec![0u8; debug_directory.size_of_data as usize];
    stub_pe.buffer.write(debug_directory.pointer_to_raw_data, wipe_vec.as_slice()).ok();

    wipe_directory(&mut stub_pe, ImageDirectoryEntry::Debug);
        
    stub_data.clone()
}

fn create_or_load_rdata(stub_data: &mut Vec<u8>) -> &mut ImageSectionHeader {
    let stub_data_ro = stub_data.clone();
    let stub_pe_ro = PE::new_disk(stub_data_ro.as_slice());

    match stub_pe_ro.get_section_by_name(String::from(".rdata")) {
        Ok(s) => {
            // this reference is not safe to use as a pointer because it points at cloned data
            // so we get the offset into the stub_data vector instead
            let section_offset = stub_pe_ro.buffer.ref_to_offset(s).unwrap();
            let stub_ptr = unsafe { stub_data.as_mut_ptr().add(section_offset.0 as usize) };
            return unsafe { &mut *(stub_ptr as *mut ImageSectionHeader) };
        }
        Err(e) => {
            if e != Error::SectionNotFound {
                panic!("couldn't search for section: {:?}", e);
            }
        },
    }
    
    pad_to_file_alignment(stub_data);

    let mut section = ImageSectionHeader::default();
    section.set_name(Some(".rdata"));

    let mut stub_pe = PE::new_mut_disk(stub_data.as_mut_slice());

    let new_section_ptr = match stub_pe.append_section(&section) {
        // this reference technically points at the stub_data buffer, so this is safe
        Ok(s) => s as *const ImageSectionHeader as *mut ImageSectionHeader,
        Err(e) => panic!("couldn't append new section: {:?}", e),
    };

    unsafe { &mut *new_section_ptr }
}

fn copy_load_config(stub_data: &mut Vec<u8>, target_pe: &PE) {
    let directory_ro = match target_pe.get_data_directory(ImageDirectoryEntry::LoadConfig) {
        Ok(d) => d,
        Err(e) => panic!("couldn't get config directory: {:?}", e),
    };

    let config_address = directory_ro.virtual_address.as_offset(&target_pe).unwrap();
    let config_size = target_pe.buffer.get_ref::<u32>(config_address).unwrap();
    let config_data = target_pe.buffer.read(config_address, *config_size as usize).unwrap();

    let section = create_or_load_rdata(stub_data);
    section.size_of_raw_data += config_data.len() as u32;
    section.virtual_size = section.size_of_raw_data;
    section.characteristics |= SectionCharacteristics::CNT_INITIALIZED_DATA | SectionCharacteristics::MEM_READ;

    let config_offset = Offset(stub_data.len() as u32);

    stub_data.append(&mut config_data.to_vec());
    fix_image_size(stub_data);

    let stub_data_ro = stub_data.clone();
    let stub_pe_ro = PE::new_disk(stub_data_ro.as_slice());
    
    let config_rva = config_offset.as_rva(&stub_pe_ro).unwrap();

    let mut stub_pe = PE::new_mut_disk(stub_data.as_mut_slice());

    let directory = match stub_pe.get_mut_data_directory(ImageDirectoryEntry::LoadConfig) {
        Ok(d) => d,
        Err(e) => panic!("couldn't get config directory: {:?}", e),
    };

    directory.virtual_address = config_rva;
    directory.size = *config_size;
}

fn append_tls_callback_stub(stub_data: &mut Vec<u8>, callback: VA) -> (Offset, Offset) {
    let callback_offset = Offset(stub_data.len() as u32);

    let mut tls_stub = match callback {
        VA::VA32(_) => TLS_PROXY_32.to_vec(),
        VA::VA64(_) => TLS_PROXY_64.to_vec(),
    };

    let mut tls_buffer = Buffer::new_mut(tls_stub.as_mut_slice());
    let mut relocation_offset;

    match callback {
        VA::VA32(v32) => {
            let hunt = tls_buffer.search_ref::<u32>(&0xDEADBEEF).unwrap();
            relocation_offset = hunt[0];
            tls_buffer.write_ref::<u32>(relocation_offset, &v32.0).ok();
        },
        VA::VA64(v64) => {
            let hunt = tls_buffer.search_ref::<u64>(&0xDEADBEEFFACEBABE).unwrap();
            relocation_offset = hunt[0];
            tls_buffer.write_ref::<u64>(relocation_offset, &v64.0).ok();
        },
    }

    relocation_offset.0 += callback_offset.0;
    stub_data.append(&mut tls_stub);

    (callback_offset, relocation_offset)
}

fn copy_tls(stub_data: &mut Vec<u8>, target_pe: &PE) {
    let target_tls_directory = match TLSDirectory::parse(&target_pe) {
        Ok(t) => t,
        Err(e) => panic!("couldn't get TLS directory: {:?}", e),
    };

    let target_tls_data = match target_tls_directory {
        TLSDirectory::TLS32(tls32) => tls32.read(&target_pe).unwrap(),
        TLSDirectory::TLS64(tls64) => tls64.read(&target_pe).unwrap(),
    };

    // get the VAs to the callbacks in the callback array as we'll be replacing a pointer in the TLS callback stub assembly
    let callbacks: Vec<VA> = match target_tls_directory {
        TLSDirectory::TLS32(tls32) => tls32.get_callbacks(&target_pe)
            .unwrap()
            .iter()
            .map(|x| target_pe.buffer
                 .ref_to_offset(x)
                 .unwrap()
                 .as_va(&target_pe)
                 .unwrap()
            ).collect(),
        TLSDirectory::TLS64(tls64) => tls64.get_callbacks(&target_pe)
            .unwrap()
            .iter()
            .map(|x| target_pe.buffer
                 .ref_to_offset(x)
                 .unwrap()
                 .as_va(&target_pe)
                 .unwrap()
            ).collect(),
    };

    let size_of_zero_fill = match target_tls_directory {
        TLSDirectory::TLS32(tls32) => tls32.size_of_zero_fill,
        TLSDirectory::TLS64(tls64) => tls64.size_of_zero_fill,
    };

    let characteristics = match target_tls_directory {
        TLSDirectory::TLS32(tls32) => tls32.characteristics,
        TLSDirectory::TLS64(tls64) => tls64.characteristics,
    };

    let _ = create_or_load_rdata(stub_data); // we don't want the section yet, just create it if it doesn't exist yet
    
    let data_start_offset = Offset(stub_data.len() as u32);
    stub_data.append(&mut target_tls_data.to_vec());
    let data_end_offset = Offset(stub_data.len() as u32);

    let index_offset = data_end_offset;
    stub_data.append(&mut vec![0u8; std::mem::size_of::<u32>()]);

    let mut tls_proxies = Vec::<Offset>::new();
    let mut relocations = Vec::<Offset>::new();

    for callback in &callbacks {
        let (proxy, relocation) = append_tls_callback_stub(stub_data, *callback);

        tls_proxies.push(proxy);
        relocations.push(relocation);
    }

    let callbacks_offset = Offset(stub_data.len() as u32);

    match target_tls_directory {
        TLSDirectory::TLS32(_) => {
            stub_data.append(&mut vec![0u8; (callbacks.len()+1) * std::mem::size_of::<VA32>()]);

            for i in 0..callbacks.len() {
                relocations.push(Offset(callbacks_offset.0 + ((i * std::mem::size_of::<VA32>()) as u32)));
            }
        },
        TLSDirectory::TLS64(_) => {
            stub_data.append(&mut vec![0u8; (callbacks.len()+1) * std::mem::size_of::<VA64>()]);

            for i in 0..callbacks.len() {
                relocations.push(Offset(callbacks_offset.0 + ((i * std::mem::size_of::<VA64>()) as u32)));
            }
        },
    }

    let new_directory_offset = Offset(stub_data.len() as u32);

    match target_tls_directory {
        TLSDirectory::TLS32(_) => stub_data.append(&mut vec![0u8; std::mem::size_of::<ImageTLSDirectory32>()]),
        TLSDirectory::TLS64(_) => stub_data.append(&mut vec![0u8; std::mem::size_of::<ImageTLSDirectory64>()]),
    }

    let tls_data_size = (stub_data.len() as u32) - data_start_offset.0;

    let rdata_section = create_or_load_rdata(stub_data);
    rdata_section.size_of_raw_data += tls_data_size;
    rdata_section.virtual_size += tls_data_size;
    rdata_section.characteristics |= SectionCharacteristics::MEM_READ;
    rdata_section.characteristics |= SectionCharacteristics::MEM_WRITE;
    rdata_section.characteristics |= SectionCharacteristics::MEM_EXECUTE;
    rdata_section.characteristics |= SectionCharacteristics::CNT_UNINITIALIZED_DATA;

    fix_image_size(stub_data);

    let stub_data_ro = stub_data.clone();
    let stub_pe_ro = PE::new_disk(stub_data_ro.as_slice());

    // get offsets of VAs of new header and add them to relocations
    match target_tls_directory {
        TLSDirectory::TLS32(_) => {
            let header = stub_pe_ro.buffer.get_ref::<ImageTLSDirectory32>(new_directory_offset).unwrap();

            relocations.push(stub_pe_ro.buffer.ref_to_offset(&header.start_address_of_raw_data).unwrap());
            relocations.push(stub_pe_ro.buffer.ref_to_offset(&header.end_address_of_raw_data).unwrap());
            relocations.push(stub_pe_ro.buffer.ref_to_offset(&header.address_of_index).unwrap());
            relocations.push(stub_pe_ro.buffer.ref_to_offset(&header.address_of_callbacks).unwrap());
        },
        TLSDirectory::TLS64(_) => {
            let header = stub_pe_ro.buffer.get_ref::<ImageTLSDirectory64>(new_directory_offset).unwrap();

            relocations.push(stub_pe_ro.buffer.ref_to_offset(&header.start_address_of_raw_data).unwrap());
            relocations.push(stub_pe_ro.buffer.ref_to_offset(&header.end_address_of_raw_data).unwrap());
            relocations.push(stub_pe_ro.buffer.ref_to_offset(&header.address_of_index).unwrap());
            relocations.push(stub_pe_ro.buffer.ref_to_offset(&header.address_of_callbacks).unwrap());
        },
    }
        
    // convert data start/end offsets into VAs
    let data_start_va = data_start_offset.as_va(&stub_pe_ro).unwrap();
    let data_end_va = data_end_offset.as_va(&stub_pe_ro).unwrap();

    // convert the address of index into a VA
    let index_va = index_offset.as_va(&stub_pe_ro).unwrap();
    
    // convert address of callbacks into a VA
    let callbacks_va = callbacks_offset.as_va(&stub_pe_ro).unwrap();
    
    // convert TLS proxies into VAs
    let tls_proxies_va: Vec<VA> = tls_proxies.iter().map(|x| x.as_va(&stub_pe_ro).unwrap()).collect();
    
    // convert relocations into RVAs
    let relocations_rva: Vec<RVA> = relocations.iter().map(|x| x.as_rva(&stub_pe_ro).unwrap()).collect();
    
    // convert directory offset into an RVA
    let new_directory_rva = new_directory_offset.as_rva(&stub_pe_ro).unwrap();

    let mut stub_pe = PE::new_mut_disk(stub_data.as_mut_slice());

    // get the TLS directory and update it
    let stub_tls_data_dir = match stub_pe.get_mut_data_directory(ImageDirectoryEntry::TLS) {
        Ok(d) => d,
        Err(e) => panic!("couldn't get TLS data directory entry: {:?}", e),
    };
    stub_tls_data_dir.virtual_address = new_directory_rva;
    stub_tls_data_dir.size = match target_tls_directory {
        TLSDirectory::TLS32(_) => std::mem::size_of::<ImageTLSDirectory32>() as u32,
        TLSDirectory::TLS64(_) => std::mem::size_of::<ImageTLSDirectory64>() as u32,
    };

    // get the TLS header and update it
    match target_tls_directory {
        TLSDirectory::TLS32(_) => {
            let header = stub_pe.buffer.get_mut_ref::<ImageTLSDirectory32>(new_directory_offset).unwrap();

            header.start_address_of_raw_data = match data_start_va {
                VA::VA32(v32) => v32,
                VA::VA64(_) => panic!("VA mismatch"),
            };
            header.end_address_of_raw_data = match data_end_va {
                VA::VA32(v32) => v32,
                VA::VA64(_) => panic!("VA mismatch"),
            };
            header.address_of_index = match index_va {
                VA::VA32(v32) => v32,
                VA::VA64(_) => panic!("VA mismatch"),
            };
            header.address_of_callbacks = match callbacks_va {
                VA::VA32(v32) => v32,
                VA::VA64(_) => panic!("VA mismatch"),
            };
            header.size_of_zero_fill = size_of_zero_fill;
            header.characteristics = characteristics;
        },
        TLSDirectory::TLS64(_) => {
            let header = stub_pe.buffer.get_mut_ref::<ImageTLSDirectory64>(new_directory_offset).unwrap();

            header.start_address_of_raw_data = match data_start_va {
                VA::VA64(v64) => v64,
                VA::VA32(_) => panic!("VA mismatch"),
            };
            header.end_address_of_raw_data = match data_end_va {
                VA::VA64(v64) => v64,
                VA::VA32(_) => panic!("VA mismatch"),
            };
            header.address_of_index = match index_va {
                VA::VA64(v64) => v64,
                VA::VA32(_) => panic!("VA mismatch"),
            };
            header.address_of_callbacks = match callbacks_va {
                VA::VA64(v64) => v64,
                VA::VA32(_) => panic!("VA mismatch"),
            };
            header.size_of_zero_fill = size_of_zero_fill;
            header.characteristics = characteristics;
        },
    }

    // get the callback array and fill it
    match target_tls_directory {
        TLSDirectory::TLS32(_) => {
            let callback_array = stub_pe.buffer.get_mut_slice_ref::<VA32>(callbacks_offset, callbacks.len()).unwrap();

            for i in 0..callbacks.len() {
                match tls_proxies_va[i] {
                    VA::VA32(v32) => callback_array[i] = v32,
                    VA::VA64(_) => panic!("VA mismatch"),
                }
            }
        },
        TLSDirectory::TLS64(_) => {
            let callback_array = stub_pe.buffer.get_mut_slice_ref::<VA64>(callbacks_offset, callbacks.len()).unwrap();

            for i in 0..callbacks.len() {
                match tls_proxies_va[i] {
                    VA::VA64(v64) => callback_array[i] = v64,
                    VA::VA32(_) => panic!("VA mismatch"),
                }
            }
       },
    }

    // add the new relocations
    let mut relocation_dir = RelocationDirectory::parse(&stub_pe_ro).unwrap();
    let stub_pe_ptr = &mut stub_pe as *const PE as *mut PE;

    for relocation in relocations_rva {
        relocation_dir.add_relocation(unsafe { &mut *stub_pe_ptr }, relocation).ok();
    }
}

fn copy_resources(stub_data: &mut Vec<u8>, target_pe: &PE) {
    let target_rsrc_data_dir = match target_pe.get_data_directory(ImageDirectoryEntry::Resource) {
        Ok(d) => d,
        Err(e) => panic!("couldn't get resource data directory: {:?}", e),
    };
    
    let target_rsrc_directory = match ResourceDirectory::parse(target_pe) {
        Ok(r) => r,
        Err(e) => panic!("couldn't get resource directory: {:?}", e),
    };

    let rsrc_start = target_rsrc_data_dir.virtual_address;
    let rsrc_end = RVA(rsrc_start.0 + target_rsrc_data_dir.size);
    let rsrc_section = match target_pe.get_section_by_rva(rsrc_start) {
        Ok(s) => s,
        Err(e) => panic!("couldn't get resource section from PE: {:?}", e),
    };
    let rsrc_data = match rsrc_section.read(&target_pe) {
        Ok(d) => d,
        Err(e) => panic!("couldn't read resource data from PE: {:?}", e),
    };

    // first, map the RVAs to resource offsets and get their sizes
    let mut offset_map = HashMap::<u32, ResourceOffset>::new();

    for rsrc in target_rsrc_directory.resources {
        let data_entry = match rsrc.get_data_entry(&target_pe) {
            Ok(d) => d,
            Err(e) => panic!("couldn't get resource entry: {:?}", e),
        };

        if data_entry.offset_to_data.0 < rsrc_start.0 || data_entry.offset_to_data.0 >= rsrc_end.0 {
            panic!("resource exists outside resource directory: {:?}", data_entry.offset_to_data);
        }

        let rsrc_offset = ResourceOffset(data_entry.offset_to_data.0 - rsrc_start.0);

        offset_map.insert(data_entry.offset_to_data.0, rsrc_offset);
    }

    let mut stub_rsrc_section = ImageSectionHeader::default();
    stub_rsrc_section.set_name(Some(".rsrc"));
    stub_rsrc_section.size_of_raw_data = rsrc_data.len() as u32;
    stub_rsrc_section.virtual_size = stub_rsrc_section.size_of_raw_data;
    stub_rsrc_section.characteristics = rsrc_section.characteristics;

    pad_to_file_alignment(stub_data);
    stub_data.append(&mut rsrc_data.to_vec());

    let mut stub_pe = PE::new_mut_disk(stub_data.as_mut_slice());
    
    let stub_rsrc_section = stub_pe.append_section(&stub_rsrc_section).unwrap().clone();
    let stub_rsrc_rva = stub_rsrc_section.virtual_address;

    let stub_rsrc_data_dir = match stub_pe.get_mut_data_directory(ImageDirectoryEntry::Resource) {
        Ok(d) => d,
        Err(e) => panic!("couldn't get resource data directory: {:?}", e),
    };

    stub_rsrc_data_dir.virtual_address = stub_rsrc_rva;
    stub_rsrc_data_dir.size = rsrc_data.len() as u32;

    fix_image_size(stub_data);

    let stub_data_ro = stub_data.clone();
    let stub_pe_ro = PE::new_disk(stub_data_ro.as_slice());
    
    let mut stub_pe = PE::new_mut_disk(stub_data.as_mut_slice());
    
    let stub_rsrc_dir = match ResourceDirectory::parse(&stub_pe_ro) {
        Ok(d) => d,
        Err(e) => panic!("couldn't get resource directory: {:?}", e),
    };

    for rsrc in stub_rsrc_dir.resources {
        let mut data_entry = match rsrc.get_mut_data_entry(&mut stub_pe) {
            Ok(d) => d,
            Err(e) => panic!("couldn't get resource entry: {:?}", e),
        };

        let rsrc_offset = match offset_map.get(&data_entry.offset_to_data.0) {
            None => panic!("no offset for {:?}", data_entry.offset_to_data),
            Some(ro) => ro,
        };

        let rva = match stub_pe_ro.get_resource_address(*rsrc_offset) {
            Ok(r) => r,
            Err(e) => panic!("couldn't translate resource offset: {:?}", e),
        };

        data_entry.offset_to_data = rva;
    }
}

fn pack_pe(stub_data: &mut Vec<u8>, target_pe: &PE) {
    let (target_base, characteristics, subsystem) = match target_pe.get_valid_nt_headers() {
        Ok(h) => match h {
            NTHeaders::NTHeaders32(h32) => (h32.optional_header.image_base as usize,
                                            h32.optional_header.dll_characteristics,
                                            h32.optional_header.subsystem),
            NTHeaders::NTHeaders64(h64) => (h64.optional_header.image_base as usize,
                                            h64.optional_header.dll_characteristics,
                                            h64.optional_header.subsystem),
        },
        Err(e) => panic!("not a valid PE file: {:?}", e),
    };

    let mut stub_pe = PE::new_mut_disk(stub_data.as_mut_slice());

    let oxide_data = OxideData::pack(target_pe.buffer.as_slice()).to_bytes();
    let mut oxide_section = ImageSectionHeader::default();
    oxide_section.set_name(Some(".odata"));

    let oxide_section = stub_pe.append_section(&oxide_section).unwrap();
    oxide_section.size_of_raw_data = oxide_data.len() as u32;
    oxide_section.virtual_size = oxide_section.size_of_raw_data;
    oxide_section.characteristics = SectionCharacteristics::CNT_INITIALIZED_DATA | SectionCharacteristics::MEM_READ;

    pad_to_file_alignment(stub_data);
    stub_data.append(&mut oxide_data.clone());
    fix_image_size(stub_data);

    if target_pe.has_data_directory(ImageDirectoryEntry::LoadConfig) {
        copy_load_config(stub_data, target_pe);
    }

    if target_pe.has_data_directory(ImageDirectoryEntry::TLS) {
        copy_tls(stub_data, target_pe);
    }
    
    if target_pe.has_data_directory(ImageDirectoryEntry::Resource) {
        copy_resources(stub_data, target_pe);
    }

    let stub_data_ro = stub_data.clone();
    let stub_pe_ro = PE::new_disk(stub_data_ro.as_slice());

    let mut stub_pe = PE::new_mut_disk(stub_data.as_mut_slice());
    
    let new_image_size = stub_pe_ro.calculate_memory_size().unwrap();

    let relocation_directory = RelocationDirectory::parse(&stub_pe_ro).unwrap();
    relocation_directory.relocate(&mut stub_pe, target_base as u64).unwrap();

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
        Err(e) => panic!("couldn't get packed NT headers: {:?}", e),
    }

    // disable the relocation directory if the original binary doesn't have DYNAMIC_BASE set
    let bit_check = characteristics & DLLCharacteristics::DYNAMIC_BASE;

    if bit_check.bits() == 0 {
        wipe_directory(&mut stub_pe, ImageDirectoryEntry::BaseReloc);

        match stub_pe.get_valid_mut_nt_headers() {
            Ok(ref mut h) => match h {
                NTHeadersMut::NTHeaders32(ref mut h32) => h32.optional_header.dll_characteristics ^= DLLCharacteristics::DYNAMIC_BASE,
                NTHeadersMut::NTHeaders64(ref mut h64) => h64.optional_header.dll_characteristics ^= DLLCharacteristics::DYNAMIC_BASE,
            },
            Err(e) => panic!("couldn't get packed NT headers: {:?}", e),
        }
    }
}

fn main() {
    let matches = App::new("OXiDE")
        .version("0.1.0")
        .about("A Rust packer.")
        .arg(Arg::with_name("file")
             .short("f")
             .long("file")
             .takes_value(true)
             .help("The executable to pack. Currently supports 32- and 64-bit executables."))
        .get_matches();

    let filename = match matches.value_of("file") {
        None => panic!("you must provide a file to pack"),
        Some(s) => s,
    };
    
    let data = match std::fs::read(filename) {
        Ok(d) => d,
        Err(e) => panic!("couldn't open file \"{}\": {:?}", filename, e),
    };

    let pefile = PE::new_disk(data.as_slice());
    let arch = pefile.get_arch().unwrap();

    let image_size = match pefile.get_valid_nt_headers() {
        Ok(h) => match h {
            NTHeaders::NTHeaders32(h32) => h32.optional_header.size_of_image as usize,
            NTHeaders::NTHeaders64(h64) => h64.optional_header.size_of_image as usize,
        },
        Err(e) => panic!("not a valid PE file: {:?}", e),
    };
    
    let mut stub_data: Vec<u8> = match arch {
        Arch::X86 => rewrite_stub(UNPACK_STUB_32.iter().cloned().collect(), image_size),
        Arch::X64 => rewrite_stub(UNPACK_STUB_64.iter().cloned().collect(), image_size),
    };

    pack_pe(&mut stub_data, &pefile);

    match std::fs::write("packed.exe", stub_data) {
        Ok(_) => println!("{} packed to packed.exe", filename),
        Err(e) => panic!("couldn't save packed executable: {:?}", e),
    }
}
