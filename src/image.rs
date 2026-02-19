// todo better debug print
#[derive(Debug, Clone, PartialEq)]
pub struct PtImage<'a> {
    data: &'a [u8],
    virtual_address: u64,
    cr3: Option<u64>,
    vmcs_ptr: Option<u64>,
}

impl<'a> PtImage<'a> {
    pub const fn new(data: &'a [u8], virtual_address: u64) -> Self {
        Self {
            data,
            virtual_address,
            cr3: None,
            vmcs_ptr: None,
        }
    }

    pub const fn data(&self) -> &[u8] {
        self.data
    }

    pub const fn virtual_address_start(&self) -> u64 {
        self.virtual_address
    }

    pub const fn virtual_address_end(&self) -> u64 {
        self.virtual_address + self.data.len() as u64
    }

    pub const fn cr3(&self) -> Option<u64> {
        self.cr3
    }

    pub const fn vmcs_ptr(&self) -> Option<u64> {
        self.vmcs_ptr
    }
}
