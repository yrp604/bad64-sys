// Copyright 2021-2025 Vector 35 Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Sections are [crate::segment::Segment]s that are loaded into memory at run time

use std::fmt;
use std::hash::{Hash, Hasher};
use std::ops::Range;

use binaryninjacore_sys::*;

use crate::binary_view::BinaryView;
use crate::rc::*;
use crate::string::*;

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, Default)]
pub enum Semantics {
    #[default]
    DefaultSection,
    ReadOnlyCode,
    ReadOnlyData,
    ReadWriteData,
    External,
}

impl From<BNSectionSemantics> for Semantics {
    fn from(bn: BNSectionSemantics) -> Self {
        use self::BNSectionSemantics::*;

        match bn {
            DefaultSectionSemantics => Semantics::DefaultSection,
            ReadOnlyCodeSectionSemantics => Semantics::ReadOnlyCode,
            ReadOnlyDataSectionSemantics => Semantics::ReadOnlyData,
            ReadWriteDataSectionSemantics => Semantics::ReadWriteData,
            ExternalSectionSemantics => Semantics::External,
        }
    }
}

impl From<Semantics> for BNSectionSemantics {
    fn from(semantics: Semantics) -> Self {
        use self::BNSectionSemantics::*;

        match semantics {
            Semantics::DefaultSection => DefaultSectionSemantics,
            Semantics::ReadOnlyCode => ReadOnlyCodeSectionSemantics,
            Semantics::ReadOnlyData => ReadOnlyDataSectionSemantics,
            Semantics::ReadWriteData => ReadWriteDataSectionSemantics,
            Semantics::External => ExternalSectionSemantics,
        }
    }
}

pub struct Section {
    handle: *mut BNSection,
}

impl Section {
    unsafe fn from_raw(handle: *mut BNSection) -> Self {
        debug_assert!(!handle.is_null());
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: *mut BNSection) -> Ref<Self> {
        debug_assert!(!handle.is_null());
        Ref::new(Self { handle })
    }

    /// You need to create a section builder, customize that section, then add it to a binary view:
    ///
    /// ```no_run
    /// # use binaryninja::section::Section;
    /// # use binaryninja::binary_view::BinaryViewExt;
    /// let bv = binaryninja::load("example").unwrap();
    /// bv.add_section(Section::builder("example".to_string(), 0..1024).align(4).entry_size(4))
    /// ```
    pub fn builder(name: String, range: Range<u64>) -> SectionBuilder {
        SectionBuilder::new(name, range)
    }

    pub fn name(&self) -> BnString {
        unsafe { BnString::from_raw(BNSectionGetName(self.handle)) }
    }

    pub fn section_type(&self) -> String {
        unsafe { BnString::into_string(BNSectionGetType(self.handle)) }
    }

    pub fn start(&self) -> u64 {
        unsafe { BNSectionGetStart(self.handle) }
    }

    pub fn end(&self) -> u64 {
        unsafe { BNSectionGetEnd(self.handle) }
    }

    pub fn len(&self) -> usize {
        unsafe { BNSectionGetLength(self.handle) as usize }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn address_range(&self) -> Range<u64> {
        self.start()..self.end()
    }

    pub fn semantics(&self) -> Semantics {
        unsafe { BNSectionGetSemantics(self.handle).into() }
    }

    pub fn linked_section(&self) -> BnString {
        unsafe { BnString::from_raw(BNSectionGetLinkedSection(self.handle)) }
    }

    pub fn info_section(&self) -> BnString {
        unsafe { BnString::from_raw(BNSectionGetInfoSection(self.handle)) }
    }

    pub fn info_data(&self) -> u64 {
        unsafe { BNSectionGetInfoData(self.handle) }
    }

    pub fn align(&self) -> u64 {
        unsafe { BNSectionGetAlign(self.handle) }
    }

    pub fn entry_size(&self) -> usize {
        unsafe { BNSectionGetEntrySize(self.handle) as usize }
    }

    pub fn auto_defined(&self) -> bool {
        unsafe { BNSectionIsAutoDefined(self.handle) }
    }
}

impl fmt::Debug for Section {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Section")
            .field("name", &self.name())
            .field("address_range", &self.address_range())
            .field("section_type", &self.section_type())
            .field("semantics", &self.semantics())
            .field("linked_section", &self.linked_section())
            .field("align", &self.align())
            .field("entry_size", &self.entry_size())
            .field("auto_defined", &self.auto_defined())
            .finish()
    }
}

impl PartialEq for Section {
    fn eq(&self, other: &Self) -> bool {
        // TODO: Do we want to make this complete match like this?
        self.name() == other.name()
            && self.address_range() == other.address_range()
            && self.semantics() == other.semantics()
            && self.linked_section() == other.linked_section()
            && self.info_section() == other.info_section()
            && self.info_data() == other.info_data()
            && self.align() == other.align()
            && self.entry_size() == other.entry_size()
            && self.auto_defined() == other.auto_defined()
    }
}

impl Eq for Section {}

impl Hash for Section {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.name().hash(state);
        self.address_range().hash(state);
    }
}

impl ToOwned for Section {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl RefCountable for Section {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: BNNewSectionReference(handle.handle),
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeSection(handle.handle);
    }
}

impl CoreArrayProvider for Section {
    type Raw = *mut BNSection;
    type Context = ();
    type Wrapped<'a> = Guard<'a, Section>;
}

unsafe impl CoreArrayProviderInner for Section {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeSectionList(raw, count);
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, context: &'a Self::Context) -> Self::Wrapped<'a> {
        Guard::new(Section::from_raw(*raw), context)
    }
}

#[must_use]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SectionBuilder {
    is_auto: bool,
    name: String,
    range: Range<u64>,
    semantics: Semantics,
    ty: String,
    align: u64,
    entry_size: u64,
    linked_section: String,
    info_section: String,
    info_data: u64,
}

impl SectionBuilder {
    pub fn new(name: String, range: Range<u64>) -> Self {
        Self {
            is_auto: false,
            name,
            range,
            semantics: Semantics::DefaultSection,
            ty: "".to_string(),
            align: 1,
            entry_size: 1,
            linked_section: "".to_string(),
            info_section: "".to_string(),
            info_data: 0,
        }
    }

    pub fn semantics(mut self, semantics: Semantics) -> Self {
        self.semantics = semantics;
        self
    }

    pub fn section_type(mut self, ty: String) -> Self {
        self.ty = ty;
        self
    }

    pub fn align(mut self, align: u64) -> Self {
        self.align = align;
        self
    }

    pub fn entry_size(mut self, entry_size: u64) -> Self {
        self.entry_size = entry_size;
        self
    }

    pub fn linked_section(mut self, linked_section: String) -> Self {
        self.linked_section = linked_section;
        self
    }

    pub fn info_section(mut self, info_section: String) -> Self {
        self.info_section = info_section;
        self
    }

    pub fn info_data(mut self, info_data: u64) -> Self {
        self.info_data = info_data;
        self
    }

    pub fn is_auto(mut self, is_auto: bool) -> Self {
        self.is_auto = is_auto;
        self
    }

    pub(crate) fn create(self, view: &BinaryView) {
        let name = self.name.to_cstr();
        let ty = self.ty.to_cstr();
        let linked_section = self.linked_section.to_cstr();
        let info_section = self.info_section.to_cstr();

        let start = self.range.start;
        let len = self.range.end.wrapping_sub(start);

        unsafe {
            if self.is_auto {
                BNAddAutoSection(
                    view.handle,
                    name.as_ptr(),
                    start,
                    len,
                    self.semantics.into(),
                    ty.as_ptr(),
                    self.align,
                    self.entry_size,
                    linked_section.as_ptr(),
                    info_section.as_ptr(),
                    self.info_data,
                );
            } else {
                BNAddUserSection(
                    view.handle,
                    name.as_ptr(),
                    start,
                    len,
                    self.semantics.into(),
                    ty.as_ptr(),
                    self.align,
                    self.entry_size,
                    linked_section.as_ptr(),
                    info_section.as_ptr(),
                    self.info_data,
                );
            }
        }
    }
}

impl<T: AsRef<Section>> From<T> for SectionBuilder {
    fn from(value: T) -> Self {
        let value = value.as_ref();
        let name = value.name().to_string_lossy().to_string();
        let ty = value.section_type().to_string();
        let linked_section = value.linked_section().to_string_lossy().to_string();
        let info_section = value.info_section().to_string_lossy().to_string();

        Self {
            is_auto: value.auto_defined(),
            name,
            range: value.address_range(),
            semantics: value.semantics(),
            ty,
            align: value.align(),
            entry_size: value.entry_size() as u64,
            linked_section,
            info_section,
            info_data: value.info_data(),
        }
    }
}
