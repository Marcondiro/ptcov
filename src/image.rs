use core::fmt;

/// A memory chunk containing (a part of) the target's executable memory.
///
/// This is disassembled during trace decoding to reconstruct the execution flow.
#[derive(Clone, PartialEq)]
pub struct PtImage<'a> {
    data: &'a [u8],
    virtual_address: u64,
    cr3: Option<u64>,
    vmcs_ptr: Option<u64>,
}

impl fmt::Debug for PtImage<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PtImage")
            .field("virtual_address", &self.virtual_address)
            .field("virtual_address_end", &self.virtual_address_end())
            .field("cr3", &self.cr3)
            .field("vmcs_ptr", &self.vmcs_ptr)
            .finish()
    }
}

impl<'a> PtImage<'a> {
    /// Creates a new image containing `data` mapped at `virtual_address`.
    #[must_use]
    pub const fn new(data: &'a [u8], virtual_address: u64) -> Self {
        Self {
            data,
            virtual_address,
            cr3: None,
            vmcs_ptr: None,
        }
    }

    /// Returns the raw bytes of the image.
    #[must_use]
    pub const fn data(&self) -> &[u8] {
        self.data
    }

    /// Returns the start virtual address of the image.
    #[must_use]
    pub const fn virtual_address_start(&self) -> u64 {
        self.virtual_address
    }

    /// Returns the exclusive end virtual address of the image.
    #[must_use]
    pub const fn virtual_address_end(&self) -> u64 {
        self.virtual_address + self.data.len() as u64
    }

    /// Returns the image CR3 value, if set.
    #[must_use]
    pub const fn cr3(&self) -> Option<u64> {
        self.cr3
    }

    /// Returns the image VMCS pointer value, if set.
    #[must_use]
    pub const fn vmcs_ptr(&self) -> Option<u64> {
        self.vmcs_ptr
    }
}
