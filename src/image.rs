// todo better debug print
/// A memory image segment used during instruction decoding.
#[derive(Debug, Clone, PartialEq)]
pub struct PtImage<'a> {
    data: &'a [u8],
    virtual_address: u64,
    cr3: Option<u64>,
    vmcs_ptr: Option<u64>,
}

impl<'a> PtImage<'a> {
    /// Creates a new image from `data` mapped at `virtual_address`.
    pub const fn new(data: &'a [u8], virtual_address: u64) -> Self {
        Self {
            data,
            virtual_address,
            cr3: None,
            vmcs_ptr: None,
        }
    }

    /// Returns the raw bytes of the image.
    pub const fn data(&self) -> &[u8] {
        self.data
    }

    /// Returns the start virtual address of the image.
    pub const fn virtual_address_start(&self) -> u64 {
        self.virtual_address
    }

    /// Returns the exclusive end virtual address of the image.
    pub const fn virtual_address_end(&self) -> u64 {
        self.virtual_address + self.data.len() as u64
    }

    /// Returns the CR3 filter value, if set.
    pub const fn cr3(&self) -> Option<u64> {
        self.cr3
    }

    /// Returns the VMCS pointer filter value, if set.
    pub const fn vmcs_ptr(&self) -> Option<u64> {
        self.vmcs_ptr
    }
}
