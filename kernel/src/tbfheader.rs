//! Tock Binary Format Header definitions and parsing code.

use core::{mem, slice, str};
use core::convert::TryInto;

/// Takes a value and rounds it up to be aligned % 4
macro_rules! align4 {
    ($e:expr) => {
        ($e) + ((4 - (($e) % 4)) % 4)
    };
}

/// TBF fields that must be present in all v2 headers.
#[derive(Clone, Copy, Debug)]
crate struct TbfHeaderV2Base {
    version: u16,
    header_size: u16,
    total_size: u32,
    flags: u32,
    checksum: u32,
}

pub struct TbfParseError;

impl From<core::array::TryFromSliceError> for TbfParseError {
    fn from(error: core::array::TryFromSliceError) -> Self {
        TbfParseError
    }
}

impl From<core::convert::Infallible> for TbfParseError {
    fn from(error: core::convert::Infallible) -> Self {
        TbfParseError
    }
}

impl From<core::option::NoneError> for TbfParseError {
    fn from(error: core::option::NoneError) -> Self {
        TbfParseError
    }
}


impl core::convert::TryFrom<&mut [u8]> for TbfHeaderV2Base {
    type Error = TbfParseError;

    fn try_from(b: &mut [u8]) -> Result<TbfHeaderV2Base, Self::Error> {
        Ok(TbfHeaderV2Base {
            version: u16::from_le_bytes(b.get(0..1)?.try_into()?),
            header_size: u16::from_le_bytes(b.get(2..3)?.try_into()?),
            total_size: u32::from_le_bytes(b.get(4..7)?.try_into()?),
            flags: u32::from_le_bytes(b.get(8..11)?.try_into()?),
            checksum: u32::from_le_bytes(b.get(12..15)?.try_into()?),
        })
    }

    // type Error = ();
    // fn try_from(b: &mut [u8]) -> Result<TbfHeaderV2Base, Self::Error> {
    //     if b.len() >= 16 {
    //         Ok(TbfHeaderV2Base {
    //             version: u16::from_be_bytes([b[0], b[1]]),
    //             header_size: u16::from_be_bytes([b[2], b[3]]),
    //             total_size: u32::from_be_bytes([b[4], b[5], b[6], b[7]]),
    //             flags: u32::from_be_bytes([b[8], b[9], b[10], b[11]]),
    //             checksum: u32::from_be_bytes([b[12], b[13], b[14], b[15]]),
    //         })
    //     } else {
    //         Err(())
    //     }
    // }
}

/// Types in TLV structures for each optional block of the header.
#[derive(Clone, Copy, Debug)]
#[allow(dead_code)]
crate enum TbfHeaderTypes {
    TbfHeaderMain = 1,
    TbfHeaderWriteableFlashRegions = 2,
    TbfHeaderPackageName = 3,
    Unused = 5,
}

impl core::convert::TryFrom<u16> for TbfHeaderTypes {
    type Error = TbfParseError;

    fn try_from(h: u16) -> Result<TbfHeaderTypes, Self::Error> {
        match h {
            1 => Ok(TbfHeaderTypes::TbfHeaderMain),
            2 => Ok(TbfHeaderTypes::TbfHeaderWriteableFlashRegions),
            3 => Ok(TbfHeaderTypes::TbfHeaderPackageName),
            _ => Err(TbfParseError)
        }
    }
}

/// The TLV header (T and L).
#[derive(Clone, Copy, Debug)]
crate struct TbfHeaderTlv {
    tipe: TbfHeaderTypes,
    length: u16,
}

impl core::convert::TryFrom<&mut [u8]> for TbfHeaderTlv {
    type Error = TbfParseError;

    fn try_from(b: &mut [u8]) -> Result<TbfHeaderTlv, Self::Error> {
        Ok(TbfHeaderTlv {
            tipe: u16::from_le_bytes(b.get(0..1)?.try_into()?).try_into()?,
            length: u16::from_le_bytes(b.get(2..3)?.try_into()?),
        })
    }
}

/// The v2 main section for apps.
///
/// All apps must have a main section. Without it, the header is considered as
/// only padding.
#[derive(Clone, Copy, Debug)]
crate struct TbfHeaderV2Main {
    init_fn_offset: u32,
    protected_size: u32,
    minimum_ram_size: u32,
}

impl core::convert::TryFrom<&mut [u8]> for TbfHeaderV2Main {
    type Error = TbfParseError;

    fn try_from(b: &mut [u8]) -> Result<TbfHeaderV2Main, Self::Error> {
        Ok(TbfHeaderV2Main {
            init_fn_offset: u32::from_le_bytes(b.get(0..3)?.try_into()?),
            protected_size: u32::from_le_bytes(b.get(4..7)?.try_into()?),
            minimum_ram_size: u32::from_le_bytes(b.get(8..11)?.try_into()?),
        })
    }
}

/// Writeable flash regions only need an offset and size.
///
/// There can be multiple (or zero) flash regions defined, so this is its own
/// struct.
#[derive(Clone, Copy, Debug)]
crate struct TbfHeaderV2WriteableFlashRegion {
    writeable_flash_region_offset: u32,
    writeable_flash_region_size: u32,
}

impl core::convert::TryFrom<&mut [u8]> for TbfHeaderV2WriteableFlashRegion {
    type Error = TbfParseError;

    fn try_from(b: &mut [u8]) -> Result<TbfHeaderV2WriteableFlashRegion, Self::Error> {
        Ok(TbfHeaderV2WriteableFlashRegion {
            writeable_flash_region_offset: u32::from_le_bytes(b.get(0..3)?.try_into()?),
            writeable_flash_region_size: u32::from_le_bytes(b.get(4..7)?.try_into()?),
        })
    }
}

/// Single header that can contain all parts of a v2 header.
#[derive(Clone, Copy, Debug)]
crate struct TbfHeaderV2 {
    base: &'static TbfHeaderV2Base,
    main: Option<&'static TbfHeaderV2Main>,
    package_name: Option<&'static str>,
    writeable_regions: Option<&'static [TbfHeaderV2WriteableFlashRegion]>,
}

/// Type that represents the fields of the Tock Binary Format header.
///
/// This specifies the locations of the different code and memory sections
/// in the tock binary, as well as other information about the application.
/// The kernel can also use this header to keep persistent state about
/// the application.
#[derive(Debug)]
crate enum TbfHeader {
    TbfHeaderV2(TbfHeaderV2),
    Padding(&'static TbfHeaderV2Base),
}

impl TbfHeader {
    /// Return whether this is an app or just padding between apps.
    crate fn is_app(&self) -> bool {
        match *self {
            TbfHeader::TbfHeaderV2(_) => true,
            TbfHeader::Padding(_) => false,
        }
    }

    /// Return whether the application is enabled or not.
    /// Disabled applications are not started by the kernel.
    crate fn enabled(&self) -> bool {
        match *self {
            TbfHeader::TbfHeaderV2(hd) => {
                // Bit 1 of flags is the enable/disable bit.
                hd.base.flags & 0x00000001 == 1
            }
            TbfHeader::Padding(_) => false,
        }
    }

    /// Get the total size in flash of this app or padding.
    crate fn get_total_size(&self) -> u32 {
        match *self {
            TbfHeader::TbfHeaderV2(hd) => hd.base.total_size,
            TbfHeader::Padding(hd) => hd.total_size,
        }
    }

    /// Add up all of the relevant fields in header version 1, or just used the
    /// app provided value in version 2 to get the total amount of RAM that is
    /// needed for this app.
    crate fn get_minimum_app_ram_size(&self) -> u32 {
        match *self {
            TbfHeader::TbfHeaderV2(hd) => hd.main.map_or(0, |m| m.minimum_ram_size),
            _ => 0,
        }
    }

    /// Get the number of bytes from the start of the app's region in flash that
    /// is for kernel use only. The app cannot write this region.
    crate fn get_protected_size(&self) -> u32 {
        match *self {
            TbfHeader::TbfHeaderV2(hd) => {
                hd.main.map_or(0, |m| m.protected_size) + (hd.base.header_size as u32)
            }
            _ => 0,
        }
    }

    /// Get the offset from the beginning of the app's flash region where the
    /// app should start executing.
    crate fn get_init_function_offset(&self) -> u32 {
        match *self {
            TbfHeader::TbfHeaderV2(hd) => {
                hd.main.map_or(0, |m| m.init_fn_offset) + (hd.base.header_size as u32)
            }
            _ => 0,
        }
    }

    /// Get the name of the app.
    crate fn get_package_name(&self) -> &'static str {
        match *self {
            TbfHeader::TbfHeaderV2(hd) => hd.package_name.unwrap_or(""),
            _ => "",
        }
    }

    /// Get the number of flash regions this app has specified in its header.
    crate fn number_writeable_flash_regions(&self) -> usize {
        match *self {
            TbfHeader::TbfHeaderV2(hd) => hd.writeable_regions.map_or(0, |wr| wr.len()),
            _ => 0,
        }
    }

    /// Get the offset and size of a given flash region.
    crate fn get_writeable_flash_region(&self, index: usize) -> (u32, u32) {
        match *self {
            TbfHeader::TbfHeaderV2(hd) => hd.writeable_regions.map_or((0, 0), |wr| {
                if wr.len() > index {
                    (
                        wr[index].writeable_flash_region_offset,
                        wr[index].writeable_flash_region_size,
                    )
                } else {
                    (0, 0)
                }
            }),
            _ => (0, 0),
        }
    }
}

/// Parse the TBF header length and the entire length of the TBF binary.
///
/// ## Return
///
/// Some((Version, TBF header length, entire TBF length))
crate fn parse_tbf_header_lengths(app: &'static mut [u8; 8]) -> Result<(u16, u16, u32), TbfParseError> {
    // Version is the first 16 bits of the app TBF contents. We need this to
    // correctly parse the other lengths.
    //
    // ## Safety
    // We trust that the version number has been checked prior to running this
    // parsing code. That is, whatever loaded this application has verified that
    // the version is valid and therefore we can trust it.
    let version = u16::from_le_bytes(app.get(0..1).ok_or(TbfParseError)?.try_into()?);

    match version {
        2 => {
            // In version 2, the next 16 bits after the version represent
            // the size of the TBF header in bytes.
            let tbf_header_size = u16::from_le_bytes(app.get(2..3).ok_or(TbfParseError)?.try_into()?);

            // The next 4 bytes are the size of the entire app's TBF space
            // including the header. This also must be checked before parsing
            // this header and we trust the value in flash.
            let tbf_size = u32::from_le_bytes(app.get(4..7).ok_or(TbfParseError)?.try_into()?);

            // Check that the header length isn't greater than the entire
            // app. If that at least looks good then return the sizes.
            if u32::from(tbf_header_size) > tbf_size {
                Err(TbfParseError)
            } else {
                Ok((version, tbf_header_size, tbf_size))
            }
        }

        _ => Err(TbfParseError)
    }
}

crate fn parse_tbf_header(header: &'static mut [u8], version: u16) -> Result<TbfHeader, TbfParseError> {
    match version {
        2 => {
            let tbf_header_base: TbfHeaderV2Base = header.try_into()?;

            // Calculate checksum. The checksum is the XOR of each 4 byte word
            // in the header.
            let mut checksum: u32 = 0;

            // let header_size: usize = tbf_header_base.header_size.try_into()?;

            // Get an iterator across 4 byte fields in the header.
            let header_iter = header.chunks_exact(4);

            // Iterate all chunks and XOR the chunks to compute the checksum.
            for (i, chunk) in header_iter.enumerate() {
                let word = u32::from_le_bytes(chunk.try_into()?);
                if i == 3 {
                    // Skip the checksum field.
                } else {
                    checksum ^= word;
                }
            }

            // DO WE NEED TO PARSE THE REMAINDER (AKA DO APPS HAVE HEADERS
            // NOT MULTIPLE OF 4)
            // let extra = header_iter.remainder();


            if checksum != tbf_header_base.checksum {
                return Err(TbfParseError);
            }






            // let mut num_chunks = tbf_header_base.header_size as usize / 4;
            // let leftover_bytes = tbf_header_base.header_size as usize % 4;
            // if leftover_bytes != 0 {
            //     num_chunks += 1;
            // }


            // for (i, chunk) in app.chunks(4).take(num_chunks).enumerate() {
            //     let word =
            //     if i == 3 {
            //         // Skip the checksum field.
            //     } else if i == num_chunks - 1 && leftover_bytes != 0 {
            //         // In this case, we don't want to use the entire word.
            //         checksum ^= *chunk & (0xFFFFFFFF >> (4 - leftover_bytes));
            //     } else {
            //         checksum ^= *chunk;
            //     }
            // }





            // let mut chunks = tbf_header_base.header_size as usize / 4;
            // let leftover_bytes = tbf_header_base.header_size as usize % 4;
            // if leftover_bytes != 0 {
            //     chunks += 1;
            // }
            // let mut checksum: u32 = 0;
            // let header = unsafe { slice::from_raw_parts(address as *const u32, chunks) };
            // for (i, chunk) in header.iter().enumerate() {
            //     if i == 3 {
            //         // Skip the checksum field.
            //     } else if i == chunks - 1 && leftover_bytes != 0 {
            //         // In this case, we don't want to use the entire word.
            //         checksum ^= *chunk & (0xFFFFFFFF >> (4 - leftover_bytes));
            //     } else {
            //         checksum ^= *chunk;
            //     }
            // }

            // if checksum != tbf_header_base.checksum {
            //     return None;
            // }


            // Get the rest of the header
            let remaining = header.get(16..)?;

            // If there is nothing left in the header then this is just a
            // padding "app" between two other apps.
            if remaining.len() == 0 {
                // Just padding.
                Ok(TbfHeader::Padding(&tbf_header_base))
            } else {







                Err(TbfParseError)
            }
        }
        _ => Err(TbfParseError)
    }
}

#[allow(clippy::cast_ptr_alignment)]
crate unsafe fn parse_and_validate_tbf_header(address: *const u8) -> Option<TbfHeader> {
    parse_and_validate_tbf_header_internal(address)
}

/// Converts a pointer to memory to a TbfHeader struct
///
/// This function takes a pointer to arbitrary memory and optionally returns a
/// TBF header struct. This function will validate the header checksum, but does
/// not perform sanity or security checking on the structure.
#[allow(clippy::cast_ptr_alignment)]
crate fn parse_and_validate_tbf_header_internal(address: *const u8) -> Option<TbfHeader> {
    let version = unsafe { *(address as *const u16) };

    match version {
        2 => {
            let tbf_header_base = unsafe { &*(address as *const TbfHeaderV2Base) };

            // Some sanity checking. Make sure the header isn't longer than the
            // total app. Make sure the total app fits inside a reasonable size
            // of flash.
            if tbf_header_base.header_size as u32 >= tbf_header_base.total_size
                || tbf_header_base.total_size > 0x010000000
            {
                return None;
            }

            // Calculate checksum. The checksum is the XOR of each 4 byte word
            // in the header.
            let mut chunks = tbf_header_base.header_size as usize / 4;
            let leftover_bytes = tbf_header_base.header_size as usize % 4;
            if leftover_bytes != 0 {
                chunks += 1;
            }
            let mut checksum: u32 = 0;
            let header = unsafe { slice::from_raw_parts(address as *const u32, chunks) };
            for (i, chunk) in header.iter().enumerate() {
                if i == 3 {
                    // Skip the checksum field.
                } else if i == chunks - 1 && leftover_bytes != 0 {
                    // In this case, we don't want to use the entire word.
                    checksum ^= *chunk & (0xFFFFFFFF >> (4 - leftover_bytes));
                } else {
                    checksum ^= *chunk;
                }
            }

            if checksum != tbf_header_base.checksum {
                return None;
            }

            // Skip the base of the header.
            let mut offset = mem::size_of::<TbfHeaderV2Base>() as isize;
            let mut remaining_length = tbf_header_base.header_size as usize - offset as usize;

            // Check if this is a real app or just padding. Padding apps are
            // identified by not having any options.
            if remaining_length == 0 {
                // Just padding.
                if checksum == tbf_header_base.checksum {
                    Some(TbfHeader::Padding(tbf_header_base))
                } else {
                    None
                }
            } else {
                // This is an actual app.

                // Places to save fields that we parse out of the header
                // options.
                let mut main_pointer: Option<&TbfHeaderV2Main> = None;
                let mut wfr_pointer: Option<&'static [TbfHeaderV2WriteableFlashRegion]> = None;
                let mut app_name_str = "";

                // Loop through the header looking for known options.
                while remaining_length > mem::size_of::<TbfHeaderTlv>() {
                    let tbf_tlv_header = unsafe { &*(address.offset(offset) as *const TbfHeaderTlv) };

                    remaining_length -= mem::size_of::<TbfHeaderTlv>();
                    offset += mem::size_of::<TbfHeaderTlv>() as isize;

                    // Only parse known TLV blocks. There is no type 0.
                    if (tbf_tlv_header.tipe as u16) < TbfHeaderTypes::Unused as u16
                        && (tbf_tlv_header.tipe as u16) > 0
                    {
                        // This lets us skip unknown header types.

                        match tbf_tlv_header.tipe {
                            TbfHeaderTypes::TbfHeaderMain =>
                            /* Main */
                            {
                                if remaining_length >= mem::size_of::<TbfHeaderV2Main>()
                                    && tbf_tlv_header.length as usize
                                        == mem::size_of::<TbfHeaderV2Main>()
                                {
                                    let tbf_main =
                                        unsafe { &*(address.offset(offset) as *const TbfHeaderV2Main) };
                                    main_pointer = Some(tbf_main);
                                }
                            }
                            TbfHeaderTypes::TbfHeaderWriteableFlashRegions =>
                            /* Writeable Flash Regions */
                            {
                                // Length must be a multiple of the size of a region definition.
                                if tbf_tlv_header.length as usize
                                    % mem::size_of::<TbfHeaderV2WriteableFlashRegion>()
                                    == 0
                                {
                                    let number_regions = tbf_tlv_header.length as usize
                                        / mem::size_of::<TbfHeaderV2WriteableFlashRegion>();
                                    let region_start = unsafe { &*(address.offset(offset)
                                        as *const TbfHeaderV2WriteableFlashRegion) };
                                    let regions =
                                        unsafe { slice::from_raw_parts(region_start, number_regions) };
                                    wfr_pointer = Some(regions);
                                }
                            }
                            TbfHeaderTypes::TbfHeaderPackageName =>
                            /* Package Name */
                            {
                                if remaining_length >= tbf_tlv_header.length as usize {
                                    let package_name_byte_array = unsafe { slice::from_raw_parts(
                                        address.offset(offset),
                                        tbf_tlv_header.length as usize,
                                    ) };
                                    let _ =
                                        str::from_utf8(package_name_byte_array).map(|name_str| {
                                            app_name_str = name_str;
                                        });
                                }
                            }
                            TbfHeaderTypes::Unused => {}
                        }
                    }

                    // All TLV blocks are padded to 4 bytes, so we need to skip
                    // more if the length is not a multiple of 4.
                    remaining_length -= align4!(tbf_tlv_header.length) as usize;
                    offset += align4!(tbf_tlv_header.length) as isize;
                }

                let tbf_header = TbfHeaderV2 {
                    base: tbf_header_base,
                    main: main_pointer,
                    package_name: Some(app_name_str),
                    writeable_regions: wfr_pointer,
                };

                Some(TbfHeader::TbfHeaderV2(tbf_header))
            }
        }

        // If we don't recognize the version number, we assume this is not a
        // valid app.
        _ => None,
    }
}
