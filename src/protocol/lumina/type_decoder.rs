//! Decoder for IDA serialized `type_t` / `p_list` blobs used by Lumina.

use super::wire::unpack_dd;

const TYPE_BASE_MASK: u8 = 0x0F;
const TYPE_FLAGS_MASK: u8 = 0x30;
const TYPE_MODIF_MASK: u8 = 0xC0;

const BT_UNK: u8 = 0x00;
const BT_VOID: u8 = 0x01;
const BT_INT8: u8 = 0x02;
const BT_INT16: u8 = 0x03;
const BT_INT32: u8 = 0x04;
const BT_INT64: u8 = 0x05;
const BT_INT128: u8 = 0x06;
const BT_INT: u8 = 0x07;
const BT_BOOL: u8 = 0x08;
const BT_FLOAT: u8 = 0x09;
const BT_PTR: u8 = 0x0A;
const BT_ARRAY: u8 = 0x0B;
const BT_FUNC: u8 = 0x0C;
const BT_COMPLEX: u8 = 0x0D;
const BT_BITFIELD: u8 = 0x0E;

const BTMT_SIZE0: u8 = 0x00;
const BTMT_SIZE12: u8 = 0x10;
const BTMT_SIZE48: u8 = 0x20;
const BTMT_SIZE128: u8 = 0x30;

const BTMT_UNKSIGN: u8 = 0x00;
const BTMT_SIGNED: u8 = 0x10;
const BTMT_USIGNED: u8 = 0x20;
const BTMT_CHAR: u8 = 0x30;

const BTMT_DEFBOOL: u8 = 0x00;
const BTMT_BOOL1: u8 = 0x10;
const BTMT_BOOL2: u8 = 0x20;
const BTMT_BOOL4: u8 = 0x30;

const BTMT_FLOAT: u8 = 0x00;
const BTMT_DOUBLE: u8 = 0x10;
const BTMT_LNGDBL: u8 = 0x20;
const BTMT_SPECFLT: u8 = 0x30;

const BTMT_DEFPTR: u8 = 0x00;
const BTMT_NEAR: u8 = 0x10;
const BTMT_FAR: u8 = 0x20;
const BTMT_CLOSURE: u8 = 0x30;

const BTMT_NONBASED: u8 = 0x10;

const BTMT_STRUCT: u8 = 0x00;
const BTMT_UNION: u8 = 0x10;
const BTMT_ENUM: u8 = 0x20;
const BTMT_TYPEDEF: u8 = 0x30;

const BTMT_BFLDI8: u8 = 0x00;
const BTMT_BFLDI16: u8 = 0x10;
const BTMT_BFLDI32: u8 = 0x20;
const BTMT_BFLDI64: u8 = 0x30;

const BTM_CONST: u8 = 0x40;
const BTM_VOLATILE: u8 = 0x80;

const RESERVED_BYTE: u8 = 0xFF;
const TAH_BYTE: u8 = 0xFE;
const FAH_BYTE: u8 = 0xFF;

const MAX_DECL_ALIGN: u32 = 0x000F;
const TAH_HASATTRS: u32 = 0x0010;

const TAUDT_UNALIGNED: u32 = 0x0040;
const TAUDT_MSSTRUCT: u32 = 0x0020;
const TAUDT_CPPOBJ: u32 = 0x0080;
const TAUDT_VFTABLE: u32 = 0x0100;
const TAUDT_FLDREPR: u32 = 0x0200;
const TAUDT_FIXED: u32 = 0x0400;
const TAUDT_TUPLE: u32 = 0x0800;
const TAUDT_IFACE: u32 = 0x1000;

const TAFLD_METHOD: u32 = 0x0200;

const TAPTR_PTR32: u32 = 0x0020;
const TAPTR_PTR64: u32 = 0x0040;
const TAPTR_RESTRICT: u32 = 0x0060;
const TAPTR_SHIFTED: u32 = 0x0080;

const TAENUM_64BIT: u32 = 0x0020;
const TAENUM_UNSIGNED: u32 = 0x0040;
const TAENUM_SIGNED: u32 = 0x0080;
const TAENUM_OCT: u32 = 0x0100;
const TAENUM_BIN: u32 = 0x0200;
const TAENUM_NUMSIGN: u32 = 0x0400;
const TAENUM_LZERO: u32 = 0x0800;

const BTE_ALWAYS: u8 = 0x80;
const BTE_BITMASK: u8 = 0x10;

const CM_CC_MASK: u8 = 0xF0;
const CM_CC_VOIDARG: u8 = 0x20;
const CM_CC_CDECL: u8 = 0x30;
const CM_CC_ELLIPSIS: u8 = 0x40;
const CM_CC_STDCALL: u8 = 0x50;
const CM_CC_PASCAL: u8 = 0x60;
const CM_CC_FASTCALL: u8 = 0x70;
const CM_CC_THISCALL: u8 = 0x80;
const CM_CC_SWIFT: u8 = 0x90;
const CM_CC_SPOILED: u8 = 0xA0;
const CM_CC_GOLANG: u8 = 0xB0;
const CM_CC_RESERVE3: u8 = 0xC0;
const CM_CC_SPECIALE: u8 = 0xD0;
const CM_CC_SPECIALP: u8 = 0xE0;
const CM_CC_SPECIAL: u8 = 0xF0;
const CM_CC_LAST_USERCALL: u32 = 0xFF;

const BFA_FUNC_MARKER: u8 = 0x0F;
const BFA_FUNC_EXT_FORMAT: u8 = 0x80;
const EXT_FUNC_HAS_SPOILED_REGS: u8 = 0x01;

const FAI_HIDDEN: u32 = 0x0001;
const FAI_RETPTR: u32 = 0x0002;
const FAI_STRUCT: u32 = 0x0004;
const FAI_ARRAY: u32 = 0x0008;
const FAI_UNUSED: u32 = 0x0010;

const ALOC_STACK: u32 = 1;
const ALOC_DIST: u32 = 2;
const ALOC_REG1: u32 = 3;
const ALOC_REG2: u32 = 4;
const ALOC_RREL: u32 = 5;
const ALOC_STATIC: u32 = 6;

const WIDE_EA_BIT: u32 = 0x20;
const SERIALIZED_BADLOC: u32 = 0x40;
const SCATTERED_BIT: u32 = 0x80;
const OLDBIT: u32 = 0x40;

const DQ_BNOT: u32 = 0x100;
const DQ_FF4: u32 = 0x200;
const DQ_FF8: u32 = 0x400;

const BV_MAGIC1: u8 = 0xAC;
const BV_MAGIC2: u8 = 0xAE;

#[derive(Debug, Clone)]
struct FunctionArg {
    name: String,
    ty: TypeNode,
    argloc: Option<String>,
    flags: u32,
}

#[derive(Debug, Clone)]
enum TypeKind {
    Primitive(String),
    Typeref(String),
    Struct {
        name: Option<String>,
        members: Vec<(String, TypeNode)>,
        is_union: bool,
    },
    Enum {
        name: Option<String>,
        members: Vec<String>,
    },
    Pointer(Box<TypeNode>),
    Array {
        elem: Box<TypeNode>,
        count: Option<u32>,
        base: Option<u32>,
    },
    Function {
        ret: Box<TypeNode>,
        cc: Option<String>,
        retloc: Option<String>,
        args: Vec<FunctionArg>,
        varargs: bool,
        unknown_args: bool,
    },
    Bitfield {
        base: String,
        width: u32,
        unsigned: bool,
    },
}

#[derive(Debug, Clone)]
struct TypeNode {
    is_const: bool,
    is_volatile: bool,
    attrs: Vec<String>,
    kind: TypeKind,
}

impl TypeNode {
    fn is_void(&self) -> bool {
        matches!(self.kind, TypeKind::Primitive(ref p) if p == "void")
    }

    fn render(&self, name: Option<&str>) -> String {
        match &self.kind {
            TypeKind::Primitive(base) | TypeKind::Typeref(base) => {
                let mut s = String::new();
                append_cv_prefix(&mut s, self.is_const, self.is_volatile);
                s.push_str(base);
                if let Some(name) = name.filter(|n| !n.is_empty()) {
                    s.push(' ');
                    s.push_str(name);
                }
                append_render_attrs(&mut s, &self.attrs);
                s
            }
            TypeKind::Struct {
                name: tag_name,
                members,
                is_union,
            } => {
                let mut s = String::new();
                append_cv_prefix(&mut s, self.is_const, self.is_volatile);
                s.push_str(if *is_union { "union" } else { "struct" });
                if let Some(tag_name) = tag_name {
                    s.push(' ');
                    s.push_str(tag_name);
                }
                if !members.is_empty() {
                    s.push_str(" {\n");
                    for (member_name, member_ty) in members {
                        s.push_str("    ");
                        s.push_str(&member_ty.render(Some(member_name)));
                        s.push_str(";\n");
                    }
                    s.push('}');
                }
                if let Some(name) = name.filter(|n| !n.is_empty()) {
                    s.push(' ');
                    s.push_str(name);
                }
                append_render_attrs(&mut s, &self.attrs);
                s
            }
            TypeKind::Enum {
                name: tag_name,
                members,
            } => {
                let mut s = String::new();
                append_cv_prefix(&mut s, self.is_const, self.is_volatile);
                s.push_str("enum");
                if let Some(tag_name) = tag_name {
                    s.push(' ');
                    s.push_str(tag_name);
                }
                if !members.is_empty() {
                    s.push_str(" { ");
                    s.push_str(&members.join(", "));
                    s.push_str(" }");
                }
                if let Some(name) = name.filter(|n| !n.is_empty()) {
                    s.push(' ');
                    s.push_str(name);
                }
                append_render_attrs(&mut s, &self.attrs);
                s
            }
            TypeKind::Pointer(inner) => {
                let mut declarator = match name {
                    Some(n) if !n.is_empty() => format!("*{}", n),
                    _ => "*".to_string(),
                };
                if !self.attrs.is_empty() {
                    declarator.push(' ');
                    declarator.push_str(&self.attrs.join(" "));
                }
                if self.is_const {
                    declarator.push_str(" const");
                }
                if self.is_volatile {
                    declarator.push_str(" volatile");
                }
                if matches!(
                    inner.kind,
                    TypeKind::Function { .. } | TypeKind::Array { .. }
                ) {
                    declarator = format!("({})", declarator);
                }
                inner.render(Some(&declarator))
            }
            TypeKind::Array { elem, count, base } => {
                let suffix = match (count, base) {
                    (Some(count), Some(base)) if *base != 0 => {
                        format!("[base={}, count={}]", base, count)
                    }
                    (Some(count), _) => format!("[{}]", count),
                    (None, Some(base)) if *base != 0 => format!("[base={}]", base),
                    _ => "[]".to_string(),
                };
                let mut declarator = match name {
                    Some(n) if !n.is_empty() => format!("{}{}", n, suffix),
                    _ => suffix,
                };
                if !self.attrs.is_empty() {
                    declarator.push(' ');
                    declarator.push_str(&self.attrs.join(" "));
                }
                elem.render(Some(&declarator))
            }
            TypeKind::Function {
                ret,
                cc,
                retloc,
                args,
                varargs,
                unknown_args,
            } => {
                let mut parts = Vec::new();
                if *unknown_args {
                    parts.push("...".to_string());
                } else {
                    for arg in args {
                        let mut rendered = if arg.name.is_empty() {
                            arg.ty.render(None)
                        } else {
                            arg.ty.render(Some(&arg.name))
                        };
                        let flags = format_arg_flags(arg.flags);
                        if !flags.is_empty() {
                            rendered = format!("{} {}", flags.join(" "), rendered);
                        }
                        if let Some(loc) = &arg.argloc {
                            rendered.push_str(" @<");
                            rendered.push_str(loc);
                            rendered.push('>');
                        }
                        parts.push(rendered);
                    }
                    if *varargs {
                        parts.push("...".to_string());
                    }
                    if parts.is_empty() {
                        parts.push("void".to_string());
                    }
                }

                let mut declarator = name.unwrap_or_default().to_string();
                if let Some(cc) = cc {
                    if declarator.is_empty() {
                        declarator = cc.clone();
                    } else {
                        declarator = format!("{} {}", cc, declarator);
                    }
                }
                if let Some(loc) = retloc {
                    if !declarator.is_empty() {
                        declarator.push(' ');
                    }
                    declarator.push_str("@<");
                    declarator.push_str(loc);
                    declarator.push('>');
                }
                declarator.push('(');
                declarator.push_str(&parts.join(", "));
                declarator.push(')');
                if !self.attrs.is_empty() {
                    declarator.push(' ');
                    declarator.push_str(&self.attrs.join(" "));
                }
                ret.render(Some(&declarator))
            }
            TypeKind::Bitfield {
                base,
                width,
                unsigned,
            } => {
                let mut s = String::new();
                append_cv_prefix(&mut s, self.is_const, self.is_volatile);
                if *unsigned {
                    s.push_str("unsigned ");
                }
                s.push_str(base);
                if let Some(name) = name.filter(|n| !n.is_empty()) {
                    s.push(' ');
                    s.push_str(name);
                }
                s.push(':');
                s.push_str(&width.to_string());
                append_render_attrs(&mut s, &self.attrs);
                s
            }
        }
    }
}

#[derive(Debug, Clone)]
struct TypeAttr {
    key: Vec<u8>,
    value: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
struct ParsedAttrHeader {
    decl_align: u8,
    bits: u32,
    attrs: Vec<TypeAttr>,
}

#[derive(Debug, Clone)]
struct CallConv {
    raw: u32,
    keyword: Option<String>,
}

struct Decoder<'a> {
    ty: &'a [u8],
    fields: &'a [u8],
}

impl<'a> Decoder<'a> {
    fn new(ty: &'a [u8], fields: &'a [u8]) -> Self {
        Self { ty, fields }
    }

    fn parse_type(&mut self) -> Result<TypeNode, String> {
        let t = self
            .read_byte()
            .ok_or_else(|| "truncated type string".to_string())?;
        let is_const = (t & BTM_CONST) != 0;
        let is_volatile = (t & BTM_VOLATILE) != 0;
        let base = t & TYPE_BASE_MASK;
        let flags = t & TYPE_FLAGS_MASK;

        let (kind, attrs) = match base {
            BT_UNK | BT_VOID | BT_INT8 | BT_INT16 | BT_INT32 | BT_INT64 | BT_INT128 | BT_INT
            | BT_BOOL | BT_FLOAT => {
                let attr_header = self.parse_optional_tah()?;
                let attrs = collect_attr_tokens(&attr_header, 0);
                (TypeKind::Primitive(simple_type_name(base, flags)), attrs)
            }
            BT_PTR => self.parse_pointer(flags)?,
            BT_ARRAY => self.parse_array(flags)?,
            BT_FUNC => self.parse_function(flags)?,
            BT_COMPLEX => self.parse_complex(flags)?,
            BT_BITFIELD => self.parse_bitfield(flags)?,
            _ => return Err(format!("unsupported base type byte 0x{t:02x}")),
        };

        Ok(TypeNode {
            is_const,
            is_volatile,
            attrs,
            kind,
        })
    }

    fn parse_pointer(&mut self, flags: u8) -> Result<(TypeKind, Vec<String>), String> {
        let mut attrs = Vec::new();

        if flags == BTMT_CLOSURE {
            let marker = self
                .read_byte()
                .ok_or_else(|| "truncated closure pointer".to_string())?;
            if marker == 0 {
                return Err("malformed closure pointer".to_string());
            }
            if marker == RESERVED_BYTE {
                let closure_target = self.parse_type()?;
                if !matches!(closure_target.kind, TypeKind::Function { .. }) {
                    return Err("closure pointer does not point to function".to_string());
                }
                attrs.push("__closure".to_string());
            } else {
                attrs.push(format!("__based_ptr({marker})"));
            }
        } else {
            match flags {
                BTMT_NEAR => attrs.push("__near".to_string()),
                BTMT_FAR => attrs.push("__far".to_string()),
                BTMT_DEFPTR => {}
                _ => attrs.push(format!("__ptr_mode(0x{flags:02X})")),
            }
        }

        let ptr_header = self.parse_optional_tah()?;
        let ptr_bits = ptr_header.bits;

        match ptr_bits & TAPTR_RESTRICT {
            TAPTR_PTR32 => attrs.push("__ptr32".to_string()),
            TAPTR_PTR64 => attrs.push("__ptr64".to_string()),
            TAPTR_RESTRICT => attrs.push("__restrict".to_string()),
            _ => {}
        }

        let inner = self.parse_type()?;

        if (ptr_bits & TAPTR_SHIFTED) != 0 {
            let parent = self.parse_type()?;
            let delta = self.read_de()? as i32;
            attrs.push(format_shifted_attr(&parent, delta));
        }

        attrs.extend(collect_attr_tokens(
            &ptr_header,
            TAPTR_RESTRICT | TAPTR_SHIFTED,
        ));

        Ok((TypeKind::Pointer(Box::new(inner)), attrs))
    }

    fn parse_array(&mut self, flags: u8) -> Result<(TypeKind, Vec<String>), String> {
        let (count, base) = if (flags & BTMT_NONBASED) != 0 {
            let n = self.read_dt()? as u32;
            ((n != 0).then_some(n), None)
        } else {
            let (num, base) = self.read_da()?;
            ((num != 0).then_some(num), Some(base))
        };

        let attr_header = self.parse_optional_tah()?;
        let elem = self.parse_type()?;

        Ok((
            TypeKind::Array {
                elem: Box::new(elem),
                count,
                base,
            },
            collect_attr_tokens(&attr_header, 0),
        ))
    }

    fn parse_function(&mut self, _flags: u8) -> Result<(TypeKind, Vec<String>), String> {
        self.skip_func_attrs()?;
        let cc = self.read_callcnv()?;
        let attr_header = self.parse_optional_tah()?;

        let ret_start = self.ty;
        let mut ret_no_fields = Decoder::new(self.ty, &[]);
        let ret = ret_no_fields.parse_type()?;
        self.ty = ret_no_fields.ty;

        let mut retloc = None;
        if is_user_cc(cc.raw) && !ret.is_void() {
            let loc = self.parse_argloc(false)?;
            if loc == "BADLOC" {
                return Err("invalid usercall return location".to_string());
            }
            retloc = Some(loc);
        }

        let mut args = Vec::new();
        let mut varargs = false;
        let mut unknown_args = false;

        if cc.raw != u32::from(CM_CC_VOIDARG) {
            let n = self.read_dt()?;
            if n == 0 {
                if is_vararg_cc(cc.raw) {
                    varargs = true;
                } else {
                    unknown_args = true;
                }
            } else if n == 1 {
                let preview = self.ty.first().copied().unwrap_or(0);
                if (preview & TYPE_BASE_MASK) == BT_VOID
                    && (preview & TYPE_FLAGS_MASK) == BTMT_SIZE0
                {
                    let mut void_decoder = Decoder::new(self.ty, self.fields);
                    let _ = void_decoder.parse_type()?;
                    self.ty = void_decoder.ty;
                    self.fields = void_decoder.fields;
                } else {
                    self.parse_func_args(n as usize, cc.raw, &mut args)?;
                }
            } else {
                self.parse_func_args(n as usize, cc.raw, &mut args)?;
            }
        }

        let mut ret_final = ret;
        if !self.fields.is_empty()
            && !ret_start.is_empty()
            && (ret_start[0] & TYPE_BASE_MASK) > BT_FLOAT
        {
            let mut ret_with_fields = Decoder::new(ret_start, self.fields);
            if let Ok(parsed) = ret_with_fields.parse_type() {
                ret_final = parsed;
                self.fields = ret_with_fields.fields;
            }
        }

        Ok((
            TypeKind::Function {
                ret: Box::new(ret_final),
                cc: cc.keyword,
                retloc,
                args,
                varargs,
                unknown_args,
            },
            collect_attr_tokens(&attr_header, 0),
        ))
    }

    fn parse_func_args(
        &mut self,
        n: usize,
        cc_raw: u32,
        args: &mut Vec<FunctionArg>,
    ) -> Result<(), String> {
        for _ in 0..n {
            let arg_name = self.read_name().unwrap_or_default();
            let mut arg_flags = 0;
            if self.peek_byte() == Some(FAH_BYTE) {
                self.ty = &self.ty[1..];
                arg_flags = self.read_de()?;
            }

            let arg_ty = self.parse_type()?;
            let argloc = if is_user_cc(cc_raw) {
                let loc = self.parse_argloc(false)?;
                if loc == "BADLOC" {
                    return Err("invalid usercall argument location".to_string());
                }
                Some(loc)
            } else {
                None
            };

            args.push(FunctionArg {
                name: arg_name,
                ty: arg_ty,
                argloc,
                flags: arg_flags,
            });
        }
        Ok(())
    }

    fn parse_complex(&mut self, flags: u8) -> Result<(TypeKind, Vec<String>), String> {
        if flags == BTMT_TYPEDEF {
            let kind = TypeKind::Typeref(
                self.read_type_name()
                    .unwrap_or_else(|| "<anon_typeref>".to_string()),
            );
            let attr_header = self.parse_optional_tah()?;
            return Ok((kind, collect_attr_tokens(&attr_header, 0)));
        }

        let n = self.read_complex_n()?;
        if n == 0 {
            let name = self.read_type_name();
            let sdacl = self.parse_optional_sdacl()?;
            return Ok(match flags {
                BTMT_STRUCT => (
                    TypeKind::Struct {
                        name,
                        members: Vec::new(),
                        is_union: false,
                    },
                    collect_udt_attr_tokens(&sdacl),
                ),
                BTMT_UNION => (
                    TypeKind::Struct {
                        name,
                        members: Vec::new(),
                        is_union: true,
                    },
                    collect_udt_attr_tokens(&sdacl),
                ),
                BTMT_ENUM => (
                    TypeKind::Enum {
                        name,
                        members: Vec::new(),
                    },
                    collect_enum_attr_tokens(&sdacl),
                ),
                _ => return Err("unknown complex subtype".to_string()),
            });
        }

        match flags {
            BTMT_STRUCT | BTMT_UNION => self.parse_udt(n, flags == BTMT_UNION),
            BTMT_ENUM => self.parse_enum(n),
            _ => Err("unknown complex subtype".to_string()),
        }
    }

    fn parse_udt(&mut self, n: u32, is_union: bool) -> Result<(TypeKind, Vec<String>), String> {
        let nmembers = (n >> 3) as usize;
        let udt_header = self.parse_optional_sdacl()?;
        let mut members = Vec::with_capacity(nmembers);
        let fixed = (udt_header.bits & TAUDT_FIXED) != 0;

        for _ in 0..nmembers {
            let member_name = self.read_name().unwrap_or_default();
            let member_ty = self.parse_type()?;

            let mut member_bits = 0u32;
            if self.peek_byte().is_some_and(is_sdacl_byte) {
                let member_header = self.parse_optional_sdacl()?;
                member_bits = member_header.bits;
            }

            if fixed && (member_bits & TAFLD_METHOD) == 0 {
                let _ = self.read_dq()?;
            }

            members.push((member_name, member_ty));
        }

        if fixed {
            let _ = self.read_dq()?;
        }

        Ok((
            TypeKind::Struct {
                name: None,
                members,
                is_union,
            },
            collect_udt_attr_tokens(&udt_header),
        ))
    }

    fn parse_enum(&mut self, n: u32) -> Result<(TypeKind, Vec<String>), String> {
        let enum_header = self.parse_optional_tah()?;
        let enum_64bit = (enum_header.bits & TAENUM_64BIT) != 0;

        let bte = self
            .read_byte()
            .ok_or_else(|| "truncated enum".to_string())?;
        if (bte & BTE_ALWAYS) == 0 {
            return Err("malformed enum flags".to_string());
        }

        let mut members = Vec::with_capacity(n as usize);
        let mut remaining_group = 0i32;
        for _ in 0..n {
            let name = self.read_name().unwrap_or_default();

            if remaining_group > 0 {
                remaining_group -= 1;
            } else if (bte & BTE_BITMASK) != 0 {
                remaining_group = self.read_dt()?;
                if remaining_group <= 0 {
                    return Err("invalid enum bitmask group".to_string());
                }
                remaining_group -= 1;
            }

            let _ = self.read_de()?;
            if enum_64bit {
                let _ = self.read_de()?;
            }
            members.push(name);
        }

        Ok((
            TypeKind::Enum {
                name: None,
                members,
            },
            collect_enum_attr_tokens(&enum_header),
        ))
    }

    fn parse_bitfield(&mut self, flags: u8) -> Result<(TypeKind, Vec<String>), String> {
        let dt = self.read_dt()? as u32;
        let width = dt >> 1;
        let unsigned = (dt & 1) != 0;
        let base = match flags {
            BTMT_BFLDI8 => "__int8",
            BTMT_BFLDI16 => "__int16",
            BTMT_BFLDI32 => "__int32",
            BTMT_BFLDI64 => "__int64",
            _ => return Err("invalid bitfield base".to_string()),
        };
        let attr_header = self.parse_optional_tah()?;
        Ok((
            TypeKind::Bitfield {
                base: base.to_string(),
                width,
                unsigned,
            },
            collect_attr_tokens(&attr_header, 0),
        ))
    }

    fn skip_func_attrs(&mut self) -> Result<(), String> {
        while self
            .peek_byte()
            .is_some_and(|b| (b & CM_CC_MASK) == CM_CC_SPOILED)
        {
            let lead = self
                .read_byte()
                .ok_or_else(|| "truncated function attrs".to_string())?;
            let mut scnt = (lead & 0x0F) as usize;
            if scnt == BFA_FUNC_MARKER as usize {
                let bfa = self
                    .read_byte()
                    .ok_or_else(|| "truncated function attr marker".to_string())?;
                if (bfa & BFA_FUNC_EXT_FORMAT) != 0 {
                    let _ = self.read_de()?;
                    if (bfa & EXT_FUNC_HAS_SPOILED_REGS) != 0 {
                        scnt = self.read_dt()? as usize;
                    } else {
                        scnt = 0;
                    }
                } else {
                    scnt = 0;
                }
            }
            for _ in 0..scnt {
                self.skip_spoil_info()?;
            }
        }
        Ok(())
    }

    fn skip_spoil_info(&mut self) -> Result<(), String> {
        let t = self
            .read_byte()
            .ok_or_else(|| "truncated spoil info".to_string())?;
        if (t & 0x80) == 0 {
            return Ok(());
        }
        if t == 0xFF {
            let _ = self.read_dt()?;
        }
        let _ = self
            .read_byte()
            .ok_or_else(|| "truncated spoil size".to_string())?;
        Ok(())
    }

    fn read_callcnv(&mut self) -> Result<CallConv, String> {
        let cm = self
            .read_byte()
            .ok_or_else(|| "truncated calling convention".to_string())?;
        let raw = if (cm & CM_CC_MASK) == CM_CC_RESERVE3 {
            self.read_de()?
        } else {
            u32::from(cm & CM_CC_MASK)
        };

        Ok(CallConv {
            raw,
            keyword: callconv_keyword(raw),
        })
    }

    fn parse_optional_tah(&mut self) -> Result<ParsedAttrHeader, String> {
        if self.peek_byte() == Some(TAH_BYTE) {
            self.parse_attr_header(false)
        } else {
            Ok(ParsedAttrHeader::default())
        }
    }

    fn parse_optional_sdacl(&mut self) -> Result<ParsedAttrHeader, String> {
        if self.peek_byte().is_some_and(is_sdacl_byte) {
            self.parse_attr_header(true)
        } else {
            Ok(ParsedAttrHeader::default())
        }
    }

    fn parse_attr_header(&mut self, sdacl: bool) -> Result<ParsedAttrHeader, String> {
        let t = self
            .read_byte()
            .ok_or_else(|| "truncated attr header".to_string())?;

        let mut tah_bits = if !sdacl {
            if t != TAH_BYTE {
                return Err("expected tah header".to_string());
            }
            8
        } else if t == TAH_BYTE {
            8
        } else {
            (((u32::from(t & TYPE_FLAGS_MASK)) >> 3) | u32::from(t & 1)) + 1
        };

        if tah_bits == 8 {
            tah_bits = 0;
            let mut shift = 0u32;
            loop {
                let b = self
                    .read_byte()
                    .ok_or_else(|| "truncated tah bits".to_string())?;
                if b == 0 {
                    return Err("malformed tah bits".to_string());
                }
                tah_bits |= u32::from(b & 0x7F) << shift;
                if (b & 0x80) == 0 {
                    break;
                }
                shift += 7;
                if shift > 28 {
                    return Err("tah bits too large".to_string());
                }
            }
        }

        let decl_align = (tah_bits & MAX_DECL_ALIGN) as u8;
        let bits = tah_bits & !MAX_DECL_ALIGN;
        let attrs = if (bits & TAH_HASATTRS) != 0 {
            self.deserialize_type_attrs()?
        } else {
            Vec::new()
        };

        Ok(ParsedAttrHeader {
            decl_align,
            bits,
            attrs,
        })
    }

    fn deserialize_type_attrs(&mut self) -> Result<Vec<TypeAttr>, String> {
        let n = self.read_dt()?;
        if n <= 0 {
            return Err("empty type attribute array".to_string());
        }

        let mut attrs = Vec::with_capacity(n as usize);
        let mut prev_key: Option<Vec<u8>> = None;
        for _ in 0..n {
            let key = self.read_len_prefixed_type_bytes()?;
            if key.is_empty() || key.contains(&0) {
                return Err("invalid type attribute key".to_string());
            }
            if let Some(prev) = &prev_key {
                if prev >= &key {
                    return Err("type attribute keys are not sorted".to_string());
                }
            }
            let value = self.deserialize_attr_bytevec()?;
            prev_key = Some(key.clone());
            attrs.push(TypeAttr { key, value });
        }
        Ok(attrs)
    }

    fn deserialize_attr_bytevec(&mut self) -> Result<Vec<u8>, String> {
        let n = self.read_dt()?;
        if n < 0 {
            return Err("invalid type attribute value length".to_string());
        }
        let mut out = Vec::with_capacity(n as usize);
        for _ in 0..n {
            let mut c = self
                .read_byte()
                .ok_or_else(|| "truncated type attribute value".to_string())?;
            if c == 0 {
                return Err("invalid zero byte in type attribute value".to_string());
            }
            match c {
                BV_MAGIC1 => c = 0,
                BV_MAGIC2 => {
                    c = self
                        .read_byte()
                        .ok_or_else(|| "truncated escaped type attribute value".to_string())?;
                    if c != BV_MAGIC1 && c != BV_MAGIC2 {
                        return Err("invalid escaped type attribute value".to_string());
                    }
                }
                _ => {}
            }
            out.push(c);
        }
        Ok(out)
    }

    fn read_len_prefixed_type_bytes(&mut self) -> Result<Vec<u8>, String> {
        let len = self.read_dt()? as usize;
        if self.ty.len() < len {
            return Err("truncated length-prefixed data".to_string());
        }
        let out = self.ty[..len].to_vec();
        self.ty = &self.ty[len..];
        Ok(out)
    }

    fn parse_argloc(&mut self, forbid_stkoff: bool) -> Result<String, String> {
        let high = self
            .read_byte()
            .ok_or_else(|| "truncated argloc".to_string())?;

        if high == 0xFF {
            let mut n = self.read_dt()? as u32;
            let mut wide_ea = false;
            if (n & WIDE_EA_BIT) != 0 {
                n &= !WIDE_EA_BIT;
                wide_ea = true;
            }

            if n == SERIALIZED_BADLOC {
                return Ok("BADLOC".to_string());
            }

            let scattered_bit = if (n & OLDBIT) != 0 && n < (OLDBIT << 1) {
                OLDBIT
            } else if (n & SCATTERED_BIT) != 0 {
                SCATTERED_BIT
            } else {
                0
            };

            if scattered_bit != 0 {
                n &= !scattered_bit;
                let count = n as usize;
                let mut parts = Vec::with_capacity(count);
                for _ in 0..count {
                    let part_loc = self.parse_argloc(false)?;
                    let off = self.read_dt()?;
                    let part_size = if scattered_bit == OLDBIT {
                        self.read_dt()? as u32
                    } else {
                        self.read_de()?
                    };
                    let mut part = format!("{}:{}", off, part_loc);
                    if part_size > 0 {
                        part.push('.');
                        part.push_str(&part_size.to_string());
                    }
                    parts.push(part);
                }
                return Ok(parts.join(", "));
            }

            match n + 1 {
                ALOC_STACK => {
                    if forbid_stkoff {
                        return Err("stack argloc forbidden".to_string());
                    }
                    let ea = self.read_ea(wide_ea)?;
                    Ok(format_stack_offset(ea))
                }
                ALOC_DIST => Ok("BADLOC".to_string()),
                ALOC_REG1 => {
                    let reg = self.read_dt()?;
                    let off = self.read_dt()?;
                    Ok(format_reg1(reg, off))
                }
                ALOC_REG2 => {
                    let reglo = self.read_dt()?;
                    let reghi = self.read_dt()?;
                    Ok(format_reg2(reglo, reghi))
                }
                ALOC_RREL => {
                    let reg = self.read_dt()?;
                    let off = self.read_ea(wide_ea)?;
                    Ok(format_rrel(reg, off))
                }
                ALOC_STATIC => {
                    let ea = self.read_ea(wide_ea)?;
                    Ok(format_ea(ea))
                }
                _ => Err("invalid argloc kind".to_string()),
            }
        } else {
            let r1 = i32::from(high & 0x7F) - 1;
            if high > 0x80 {
                let low = self
                    .read_byte()
                    .ok_or_else(|| "truncated old-style reg pair argloc".to_string())?;
                if low == 0 {
                    return Err("invalid old-style reg pair argloc".to_string());
                }
                let r2 = i32::from(low) - 1;
                Ok(format_reg2(r1, r2))
            } else if r1 == -1 {
                if forbid_stkoff {
                    return Err("stack argloc forbidden".to_string());
                }
                Ok("^0".to_string())
            } else {
                Ok(format_reg1(r1, 0))
            }
        }
    }

    fn read_ea(&mut self, wide_ea: bool) -> Result<u64, String> {
        let low = u64::from(self.read_de()?);
        let high = if wide_ea {
            u64::from(self.read_de()?)
        } else {
            0
        };
        Ok(low | (high << 32))
    }

    fn read_complex_n(&mut self) -> Result<u32, String> {
        let mut n = self.read_dt()? as u32;
        if n == 0x7FFE {
            n = self.read_de()?;
        }
        Ok(n)
    }

    fn read_da(&mut self) -> Result<(u32, u32), String> {
        let mut v = 0u32;
        for _ in 0..4 {
            let b = self.read_byte().ok_or_else(|| "truncated da".to_string())?;
            if (b as i8) >= 0 {
                return Err("invalid da encoding".to_string());
            }
            v = (v << 7) | u32::from(b & 0x7F);
        }

        let b = self
            .read_byte()
            .ok_or_else(|| "truncated da tail".to_string())?;
        if b == 0 {
            return Err("invalid da tail".to_string());
        }

        v = (v << 4) | u32::from(b & 0x0F);
        let base = v;

        let mut num_el = u32::from((b & 0x70) >> 4);
        for _ in 0..4 {
            let b = self
                .read_byte()
                .ok_or_else(|| "truncated da count".to_string())?;
            if (b as i8) >= 0 {
                return Err("invalid da count encoding".to_string());
            }
            num_el = (num_el << 7) | u32::from(b & 0x7F);
        }
        Ok((num_el, base))
    }

    fn read_dq(&mut self) -> Result<u64, String> {
        let header = self.read_dt()? as u32;
        if header == DQ_FF8 {
            return Ok(u64::MAX);
        }
        if header == DQ_FF4 {
            return Ok(u32::MAX as u64);
        }
        let mut val = 0u64;
        for i in 0..8 {
            if (header & (1 << i)) != 0 {
                let b = self.read_byte().ok_or_else(|| "truncated dq".to_string())?;
                if b == 0 {
                    return Err("invalid zero byte in dq".to_string());
                }
                val |= u64::from(b) << (i * 8);
            }
        }
        if (header & DQ_BNOT) != 0 {
            val = !val;
        }
        Ok(val)
    }

    fn read_dt(&mut self) -> Result<i32, String> {
        let b = self.read_byte().ok_or_else(|| "truncated dt".to_string())?;
        let mut val = b as i8 as i32;
        if val == 0 {
            return Err("invalid zero dt byte".to_string());
        }
        if val < 0 {
            let next = self.peek_byte().unwrap_or(0);
            if next == 0 {
                return Err("invalid dt extension".to_string());
            }
            let next = self
                .read_byte()
                .ok_or_else(|| "truncated dt extension".to_string())?;
            val &= 0x7F;
            val |= i32::from(next) << 7;
        }
        Ok(val - 1)
    }

    fn read_de(&mut self) -> Result<u32, String> {
        let mut v = 0u32;
        loop {
            let c = self.read_byte().ok_or_else(|| "truncated de".to_string())?;
            if c == 0 {
                return Err("invalid zero de byte".to_string());
            }
            let signed = c as i8;
            v <<= 6;
            if signed < 0 {
                v = (v << 1) | u32::from(c & 0x7F);
            } else {
                v |= u32::from(c & 0x3F);
                break;
            }
        }
        Ok(v)
    }

    fn read_name(&mut self) -> Option<String> {
        if self.fields.is_empty() || self.fields[0] == 0 {
            return None;
        }
        let len = self.read_dt_from_fields().ok()? as usize;
        if self.fields.len() < len {
            return None;
        }
        let name = String::from_utf8_lossy(&self.fields[..len]).into_owned();
        self.fields = &self.fields[len..];
        Some(name)
    }

    fn read_type_name(&mut self) -> Option<String> {
        let len = self.read_dt().ok()? as usize;
        if self.ty.len() < len {
            return None;
        }
        let name = String::from_utf8_lossy(&self.ty[..len]).into_owned();
        self.ty = &self.ty[len..];
        Some(name)
    }

    fn read_dt_from_fields(&mut self) -> Result<i32, String> {
        let b = self
            .read_field_byte()
            .ok_or_else(|| "truncated field dt".to_string())?;
        let mut val = b as i8 as i32;
        if val == 0 {
            return Err("invalid zero field dt byte".to_string());
        }
        if val < 0 {
            let next = self.fields.first().copied().unwrap_or(0);
            if next == 0 {
                return Err("invalid field dt extension".to_string());
            }
            let next = self
                .read_field_byte()
                .ok_or_else(|| "truncated field dt extension".to_string())?;
            val &= 0x7F;
            val |= i32::from(next) << 7;
        }
        Ok(val - 1)
    }

    fn read_byte(&mut self) -> Option<u8> {
        let b = self.ty.first().copied()?;
        self.ty = &self.ty[1..];
        Some(b)
    }

    fn read_field_byte(&mut self) -> Option<u8> {
        let b = self.fields.first().copied()?;
        self.fields = &self.fields[1..];
        Some(b)
    }

    fn peek_byte(&self) -> Option<u8> {
        self.ty.first().copied()
    }
}

fn append_cv_prefix(out: &mut String, is_const: bool, is_volatile: bool) {
    if is_const {
        out.push_str("const ");
    }
    if is_volatile {
        out.push_str("volatile ");
    }
}

fn append_render_attrs(out: &mut String, attrs: &[String]) {
    if attrs.is_empty() {
        return;
    }
    if !out.is_empty() {
        out.push(' ');
    }
    out.push_str(&attrs.join(" "));
}

fn collect_attr_tokens(header: &ParsedAttrHeader, known_bits: u32) -> Vec<String> {
    let mut out = Vec::new();

    if header.decl_align != 0 {
        let al = 1u32 << (u32::from(header.decl_align.saturating_sub(1)));
        out.push(format!("__align({al})"));
    }

    for attr in &header.attrs {
        out.push(format_type_attr_token(attr));
    }

    let unknown = header.bits & !(known_bits | TAH_HASATTRS);
    if unknown != 0 {
        out.push(format!("__tah_bits(0x{unknown:X})"));
    }

    out
}

fn collect_udt_attr_tokens(header: &ParsedAttrHeader) -> Vec<String> {
    let mut out = Vec::new();
    if (header.bits & TAUDT_UNALIGNED) != 0 {
        out.push("__unaligned".to_string());
    }
    if (header.bits & TAUDT_MSSTRUCT) != 0 {
        out.push("__msstruct".to_string());
    }
    if (header.bits & TAUDT_CPPOBJ) != 0 {
        out.push("__cppobj".to_string());
    }
    if (header.bits & TAUDT_VFTABLE) != 0 {
        out.push("__vftable".to_string());
    }
    if (header.bits & TAUDT_FIXED) != 0 {
        out.push("__fixed".to_string());
    }
    if (header.bits & TAUDT_TUPLE) != 0 {
        out.push("__tuple".to_string());
    }
    if (header.bits & TAUDT_IFACE) != 0 {
        out.push("__interface".to_string());
    }

    out.extend(collect_attr_tokens(
        header,
        TAUDT_UNALIGNED
            | TAUDT_MSSTRUCT
            | TAUDT_CPPOBJ
            | TAUDT_VFTABLE
            | TAUDT_FLDREPR
            | TAUDT_FIXED
            | TAUDT_TUPLE
            | TAUDT_IFACE,
    ));
    out
}

fn collect_enum_attr_tokens(header: &ParsedAttrHeader) -> Vec<String> {
    let mut out = Vec::new();
    if (header.bits & TAENUM_64BIT) != 0 {
        out.push("__enum64".to_string());
    }
    if (header.bits & TAENUM_UNSIGNED) != 0 {
        out.push("__enum_unsigned".to_string());
    }
    if (header.bits & TAENUM_SIGNED) != 0 {
        out.push("__enum_signed".to_string());
    }
    if (header.bits & TAENUM_OCT) != 0 {
        out.push("__enum_octal".to_string());
    }
    if (header.bits & TAENUM_BIN) != 0 {
        out.push("__enum_binary".to_string());
    }
    if (header.bits & TAENUM_NUMSIGN) != 0 {
        out.push("__enum_numsign".to_string());
    }
    if (header.bits & TAENUM_LZERO) != 0 {
        out.push("__enum_lzero".to_string());
    }

    out.extend(collect_attr_tokens(
        header,
        TAENUM_64BIT
            | TAENUM_UNSIGNED
            | TAENUM_SIGNED
            | TAENUM_OCT
            | TAENUM_BIN
            | TAENUM_NUMSIGN
            | TAENUM_LZERO,
    ));
    out
}

fn format_type_attr_token(attr: &TypeAttr) -> String {
    let key = format_attr_key(&attr.key);
    let value = format_attr_value(attr);
    if value.is_empty() {
        format!("__attribute__(({key}))")
    } else {
        format!("__attribute__(({key}({value})))")
    }
}

fn format_attr_key(key: &[u8]) -> String {
    if key == [1] {
        return "value_repr".to_string();
    }
    if key
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || *b == b'_' || *b == b':')
    {
        return String::from_utf8_lossy(key).into_owned();
    }
    escape_bytes(key)
}

fn format_attr_value(attr: &TypeAttr) -> String {
    if attr.value.is_empty() {
        return String::new();
    }

    if attr.key.as_slice() == b"__org_arrdim" {
        if let Some(vals) = decode_attr_dd_values(&attr.value, 2) {
            return format!("{},{}", vals[0], vals[1]);
        }
    } else if attr.key.as_slice() == b"format" {
        if let Some(vals) = decode_attr_dd_values(&attr.value, 3) {
            let func_name = match vals[0] {
                0 => "printf",
                1 => "scanf",
                2 => "strftime",
                3 => "strfmon",
                _ => "?",
            };
            return format!("{func_name},{},{}", vals[1], vals[2]);
        }
    }

    if is_printable_ascii(&attr.value) {
        String::from_utf8_lossy(&attr.value).into_owned()
    } else {
        escape_bytes(&attr.value)
    }
}

fn decode_attr_dd_values(buf: &[u8], count: usize) -> Option<Vec<u32>> {
    let mut out = Vec::with_capacity(count);
    let mut off = 0usize;
    for _ in 0..count {
        let (v, consumed) = unpack_dd(&buf[off..]);
        if consumed == 0 {
            return None;
        }
        out.push(v);
        off += consumed;
    }
    if off != buf.len() {
        return None;
    }
    Some(out)
}

fn is_printable_ascii(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .all(|b| b.is_ascii_graphic() || *b == b' ' || *b == b'\t')
}

fn format_shifted_attr(parent: &TypeNode, delta: i32) -> String {
    format!(
        "__shifted({}, {})",
        parent.render(None),
        format_signed_delta(delta)
    )
}

fn format_signed_delta(delta: i32) -> String {
    if delta < 0 {
        format!("-0x{:X}", delta.unsigned_abs())
    } else if delta < 10 {
        delta.to_string()
    } else {
        format!("0x{delta:X}")
    }
}

fn format_reg1(reg: i32, off: i32) -> String {
    if off == 0 {
        format!("R{reg}")
    } else {
        format!("R{reg}^{off}")
    }
}

fn format_reg2(reglo: i32, reghi: i32) -> String {
    format!("R{reghi}:R{reglo}")
}

fn format_stack_offset(v: u64) -> String {
    let signed = v as i64;
    format!("^{signed}")
}

fn format_rrel(reg: i32, off: u64) -> String {
    let dist = off as i64;
    if dist < 0 {
        format!("[R{reg}-0x{:X}]", dist.unsigned_abs())
    } else {
        format!("[R{reg}+0x{:X}]", dist as u64)
    }
}

fn format_ea(ea: u64) -> String {
    format!("@0x{ea:X}")
}

fn callconv_keyword(raw: u32) -> Option<String> {
    let base = if raw <= CM_CC_LAST_USERCALL {
        raw & u32::from(CM_CC_MASK)
    } else {
        raw
    };

    let known = match base as u8 {
        CM_CC_CDECL => Some("__cdecl"),
        CM_CC_STDCALL => Some("__stdcall"),
        CM_CC_PASCAL => Some("__pascal"),
        CM_CC_FASTCALL => Some("__fastcall"),
        CM_CC_THISCALL => Some("__thiscall"),
        CM_CC_SWIFT => Some("__swiftcall"),
        CM_CC_GOLANG => Some("__golang"),
        CM_CC_SPECIAL | CM_CC_SPECIALE => Some("__usercall"),
        CM_CC_SPECIALP => Some("__userpurge"),
        _ => None,
    };

    if let Some(k) = known {
        return Some(k.to_string());
    }
    if raw > CM_CC_LAST_USERCALL {
        return Some(format!("__cc(0x{raw:X})"));
    }
    None
}

fn is_user_cc(raw: u32) -> bool {
    raw >= u32::from(CM_CC_SPECIALE) && raw <= CM_CC_LAST_USERCALL
}

fn is_vararg_cc(raw: u32) -> bool {
    if raw > CM_CC_LAST_USERCALL {
        return false;
    }
    let cc = raw & !0x0F;
    cc == u32::from(CM_CC_ELLIPSIS) || cc == u32::from(CM_CC_SPECIALE)
}

fn format_arg_flags(flags: u32) -> Vec<&'static str> {
    let mut out = Vec::new();
    if (flags & FAI_UNUSED) != 0 {
        out.push("__unused");
    }
    if (flags & FAI_HIDDEN) != 0 {
        out.push("__hidden");
    }
    if (flags & FAI_RETPTR) != 0 {
        out.push("__return_ptr");
    }
    if (flags & FAI_STRUCT) != 0 {
        out.push("__struct_ptr");
    }
    if (flags & FAI_ARRAY) != 0 {
        out.push("__array_ptr");
    }
    out
}

fn simple_type_name(base: u8, flags: u8) -> String {
    match base {
        BT_VOID => match flags {
            BTMT_SIZE0 => "void".to_string(),
            BTMT_SIZE12 => "_BYTE".to_string(),
            BTMT_SIZE48 => "_DWORD".to_string(),
            BTMT_SIZE128 => "_OWORD".to_string(),
            _ => "void".to_string(),
        },
        BT_UNK => match flags {
            BTMT_SIZE12 => "_WORD".to_string(),
            BTMT_SIZE48 => "_QWORD".to_string(),
            BTMT_SIZE128 => "_UNKNOWN".to_string(),
            _ => "_UNKNOWN".to_string(),
        },
        BT_INT8 => match flags {
            BTMT_CHAR => "char".to_string(),
            BTMT_USIGNED => "unsigned char".to_string(),
            BTMT_SIGNED => "__int8".to_string(),
            _ => "__int8".to_string(),
        },
        BT_INT16 => match flags {
            BTMT_USIGNED => "unsigned __int16".to_string(),
            _ => "__int16".to_string(),
        },
        BT_INT32 => match flags {
            BTMT_USIGNED => "unsigned __int32".to_string(),
            _ => "__int32".to_string(),
        },
        BT_INT64 => match flags {
            BTMT_USIGNED => "unsigned __int64".to_string(),
            _ => "__int64".to_string(),
        },
        BT_INT128 => match flags {
            BTMT_USIGNED => "unsigned __int128".to_string(),
            _ => "__int128".to_string(),
        },
        BT_INT => match flags {
            BTMT_USIGNED => "unsigned int".to_string(),
            BTMT_SIGNED => "signed int".to_string(),
            BTMT_CHAR => "__seg".to_string(),
            BTMT_UNKSIGN => "int".to_string(),
            _ => "int".to_string(),
        },
        BT_BOOL => match flags {
            BTMT_BOOL1 => "_BOOL1".to_string(),
            BTMT_BOOL2 => "_BOOL2".to_string(),
            BTMT_BOOL4 => "_BOOL4".to_string(),
            BTMT_DEFBOOL => "bool".to_string(),
            _ => "bool".to_string(),
        },
        BT_FLOAT => match flags {
            BTMT_FLOAT => "float".to_string(),
            BTMT_DOUBLE => "double".to_string(),
            BTMT_LNGDBL => "long double".to_string(),
            BTMT_SPECFLT => "_TBYTE".to_string(),
            _ => "float".to_string(),
        },
        _ => format!("<type base=0x{base:02x} flags=0x{flags:02x}>"),
    }
}

fn is_sdacl_byte(t: u8) -> bool {
    ((t & !TYPE_FLAGS_MASK) ^ TYPE_MODIF_MASK) <= BT_VOID
}

/// Independently framed field names, without claiming a decoded type or argument
/// position. Reject the entire list on malformed framing or textual content.
pub(crate) fn decode_field_names(fields: &[u8]) -> Option<Vec<&str>> {
    if fields.len() > 8192 {
        return None;
    }
    let mut decoder = Decoder::new(&[], fields);
    let mut names = Vec::new();
    let mut entries = 0;
    while !decoder.fields.is_empty() {
        if decoder.fields[0] == 0 {
            return decoder.fields.iter().all(|b| *b == 0).then_some(names);
        }
        entries += 1;
        if entries > 64 {
            return None;
        }
        let length = usize::try_from(decoder.read_dt_from_fields().ok()?).ok()?;
        let (name, rest) = decoder.fields.split_at_checked(length)?;
        let name = std::str::from_utf8(name).ok()?;
        if name.chars().any(char::is_control) {
            return None;
        }
        if !name.is_empty() {
            names.push(name);
        }
        decoder.fields = rest;
    }
    Some(names)
}

pub fn decode_tinfo_decl(type_bytes: &[u8], fields_bytes: &[u8]) -> Result<String, String> {
    if type_bytes.is_empty() {
        return Err("empty type string".to_string());
    }
    let mut decoder = Decoder::new(type_bytes, fields_bytes);
    let ty = decoder.parse_type()?;
    Ok(ty.render(None))
}

pub fn escape_bytes(bytes: &[u8]) -> String {
    let mut out = String::new();
    for &b in bytes {
        for ch in std::ascii::escape_default(b) {
            out.push(ch as char);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::decode_tinfo_decl;

    #[test]
    fn independent_field_names_validate_lengths_text_and_bounds() {
        use super::decode_field_names;
        assert_eq!(
            decode_field_names(b"\x04foo\x01\x04bar\0"),
            Some(vec!["foo", "bar"])
        );
        assert_eq!(decode_field_names(&[]), Some(vec![]));
        assert_eq!(decode_field_names(&[0, 0]), Some(vec![]));
        // Independently derived dt transitions: the encoded integer is length+1.
        for (prefix, length) in [
            (vec![0x7f], 126),
            (vec![0x80, 1], 127),
            (vec![0x81, 1], 128),
        ] {
            let mut fields = prefix;
            fields.extend(std::iter::repeat_n(b'x', length));
            assert_eq!(decode_field_names(&fields).unwrap()[0].len(), length);
            fields.pop();
            assert!(decode_field_names(&fields).is_none());
        }
        for fields in [
            &b"\x04fo"[..],
            &[0x80],
            &[0x80, 0],
            b"\x04f\0o",
            b"\x03\xffx",
            b"\0\x02x",
            b"\x02\n",
        ] {
            assert!(decode_field_names(fields).is_none(), "{fields:?}");
        }
        assert!(decode_field_names(&[1; 64]).is_some());
        assert!(decode_field_names(&[1; 65]).is_none());
        assert!(decode_field_names(&[0; 8192]).is_some());
        assert!(decode_field_names(&[0; 8193]).is_none());
    }

    fn dt(v: u8) -> Vec<u8> {
        vec![v + 1]
    }

    fn de_small(v: u8) -> u8 {
        v | 0x40
    }

    #[test]
    fn decodes_typeref() {
        let ty = [0x3D, 5, b'i', b'n', b't', b't'];
        let got = decode_tinfo_decl(&ty, &[]).unwrap();
        assert_eq!(got, "intt");
    }

    #[test]
    fn decodes_pointer_to_typeref() {
        let ty = [0x0A, 0x3D, 5, b'i', b'n', b't', b't'];
        let got = decode_tinfo_decl(&ty, &[]).unwrap();
        assert_eq!(got, "intt *");
    }

    #[test]
    fn decodes_simple_struct_members_from_fields() {
        let mut ty = vec![0x0D];
        ty.extend_from_slice(&dt((2 << 3) as u8));
        ty.push(0x11);
        ty.push(0x11);

        let fields = [2, b'a', 2, b'b'];
        let got = decode_tinfo_decl(&ty, &fields).unwrap();
        assert!(got.contains("struct"));
        assert!(
            got.contains("_BYTE a")
                || got.contains("_WORD a")
                || got.contains("void a")
                || got.contains("_BYTE b")
                || got.contains("__int8 a")
        );
    }

    #[test]
    fn decodes_extended_type_attrs() {
        let ty = [
            0x04, // __int32
            0xFE, 0x10, // tah bits: HASATTRS
            0x02, // dt(1) attrs
            0x02, b'k', // key "k"
            0x02, b'v', // value "v"
        ];
        let got = decode_tinfo_decl(&ty, &[]).unwrap();
        assert!(got.contains("__attribute__((k(v)))"));
    }

    #[test]
    fn decodes_usercall_arglocs() {
        let ty = [
            0x0C, // function
            0xF0, // __usercall
            0x04, // return __int32
            0x01, // old-style argloc: R0 (return)
            0x02, // dt(1) argument count
            0x04, // arg0 type __int32
            0x02, // old-style argloc: R1
        ];

        let got = decode_tinfo_decl(&ty, &[]).unwrap();
        assert!(got.contains("__usercall"));
        assert!(got.contains("@<R0>"));
        assert!(got.contains("@<R1>"));
    }

    #[test]
    fn decodes_shifted_pointer_attrs() {
        let ty = [
            0x0A, // pointer
            0xFE,
            0x80,
            0x01, // tah bits: TAPTR_SHIFTED
            0x04, // pointee: __int32
            0x3D,
            0x02,
            b'S',        // parent typeref "S"
            de_small(4), // delta
        ];

        let got = decode_tinfo_decl(&ty, &[]).unwrap();
        assert!(got.contains("__shifted("));
    }
}
