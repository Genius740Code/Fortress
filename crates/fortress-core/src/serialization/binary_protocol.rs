//! Binary Protocol Implementation
//!
//! This module provides a high-performance binary serialization format
//! optimized for Rust-to-Rust communication within Fortress.

use std::collections::HashMap;
use std::io::{Read, Write, Cursor};
use byteorder::{ReadBytesExt, WriteBytesExt, LittleEndian};
use serde::{Serialize, Deserialize, de::{DeserializeSeed, Visitor, SeqAccess, MapAccess, EnumAccess, VariantAccess}};
use crate::error::{FortressError, Result};

// Manual trait definitions for compatibility with older serde versions
trait TupleAccess<'de> {
    type Error;
    fn next_element_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>, Self::Error>
    where
        T: serde::de::DeserializeSeed<'de>;
}

trait StructAccess<'de> {
    type Error;
    fn field<T>(&mut self, seed: T) -> Result<T::Value, Self::Error>
    where
        T: serde::de::DeserializeSeed<'de>;
    fn skip_field(&mut self) -> Result<bool, Self::Error>;
}

/// Binary protocol version
const BINARY_PROTOCOL_VERSION: u8 = 1;

/// Binary protocol header size
const HEADER_SIZE: usize = 16;

/// Binary protocol for high-performance serialization
pub struct BinaryProtocol {
    /// Type registry for efficient serialization
    type_registry: HashMap<String, TypeDescriptor>,
    /// String interning for deduplication
    string_intern: HashMap<String, u32>,
    /// Next string ID
    next_string_id: u32,
}

/// Type descriptor for efficient serialization
#[derive(Debug, Clone)]
struct TypeDescriptor {
    /// Type name
    name: String,
    /// Type ID
    id: u32,
    /// Field descriptors
    fields: Vec<FieldDescriptor>,
}

/// Field descriptor for type fields
#[derive(Debug, Clone)]
struct FieldDescriptor {
    /// Field name
    name: String,
    /// Field type
    field_type: FieldType,
    /// Field index
    index: u32,
}

/// Field types supported by binary protocol
#[derive(Debug, Clone, PartialEq)]
enum FieldType {
    Bool,
    U8,
    U16,
    U32,
    U64,
    I8,
    I16,
    I32,
    I64,
    F32,
    F64,
    String,
    Bytes,
    Vec(Box<FieldType>),
    Map(Box<FieldType>, Box<FieldType>),
    Option(Box<FieldType>),
    Struct(String),
    Enum(String),
}

impl BinaryProtocol {
    /// Create a new binary protocol instance
    pub fn new() -> Result<Self> {
        Ok(Self {
            type_registry: HashMap::new(),
            string_intern: HashMap::new(),
            next_string_id: 1,
        })
    }

    /// Serialize data to binary format
    pub fn serialize<T>(&self, data: &T) -> Result<Vec<u8>>
    where
        T: Serialize,
    {
        let mut buffer = Vec::new();
        
        // Write header
        self.write_header(&mut buffer)?;
        
        // Serialize the data
        let mut serializer = BinarySerializer::new(&mut buffer, self);
        data.serialize(&mut serializer)?;
        
        Ok(buffer)
    }

    /// Deserialize data from binary format
    pub fn deserialize<T>(&self, data: &[u8]) -> Result<T>
    where
        T: for<'de> Deserialize<'de>,
    {
        let mut cursor = Cursor::new(data);
        
        // Read and validate header
        self.read_header(&mut cursor)?;
        
        // Deserialize the data
        let mut deserializer = BinaryDeserializer::new(&mut cursor, self);
        let result = T::deserialize(&mut deserializer)?;
        
        Ok(result)
    }

    /// Write protocol header
    fn write_header(&self, buffer: &mut Vec<u8>) -> Result<()> {
        // Protocol magic bytes
        buffer.extend_from_slice(b"FTRB"); // Fortress Binary
        
        // Protocol version
        buffer.push(BINARY_PROTOCOL_VERSION);
        
        // Flags (reserved for future use)
        buffer.write_u32::<LittleEndian>(0)?;
        
        // Reserved
        buffer.write_u64::<LittleEndian>(0)?;
        
        Ok(())
    }

    /// Read and validate protocol header
    fn read_header(&self, cursor: &mut Cursor<&[u8]>) -> Result<()> {
        let mut magic = [0u8; 4];
        cursor.read_exact(&mut magic)?;
        
        if magic != b"FTRB" {
            return Err(FortressError::serialization("Invalid magic bytes", 
                format!("Expected FTRB, got {:?}", magic)));
        }
        
        let version = cursor.read_u8()?;
        if version != BINARY_PROTOCOL_VERSION {
            return Err(FortressError::serialization("Unsupported protocol version", 
                format!("Version {}, expected {}", version, BINARY_PROTOCOL_VERSION)));
        }
        
        // Skip flags and reserved fields
        cursor.set_position(cursor.position() + 12);
        
        Ok(())
    }

    /// Get or create string ID for interning
    fn get_string_id(&mut self, string: &str) -> u32 {
        if let Some(&id) = self.string_intern.get(string) {
            id
        } else {
            let id = self.next_string_id;
            self.next_string_id += 1;
            self.string_intern.insert(string.to_string(), id);
            id
        }
    }

    /// Get string from ID
    fn get_string(&self, id: u32) -> Option<&str> {
        self.string_intern.iter()
            .find(|(_, &string_id)| string_id == id)
            .map(|(string, _)| string.as_str())
    }
}

/// Binary serializer implementation
struct BinarySerializer<'a> {
    buffer: &'a mut Vec<u8>,
    protocol: &'a BinaryProtocol,
}

impl<'a> BinarySerializer<'a> {
    fn new(buffer: &'a mut Vec<u8>, protocol: &'a BinaryProtocol) -> Self {
        Self { buffer, protocol }
    }

    fn write_varint(&mut self, value: u64) -> Result<()> {
        let mut value = value;
        loop {
            let mut byte = (value & 0x7F) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            self.buffer.push(byte);
            if value == 0 {
                break;
            }
        }
        Ok(())
    }

    fn write_string(&mut self, string: &str) -> Result<()> {
        self.write_varint(string.len() as u64)?;
        self.buffer.extend_from_slice(string.as_bytes());
        Ok(())
    }

    fn write_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        self.write_varint(bytes.len() as u64)?;
        self.buffer.extend_from_slice(bytes);
        Ok(())
    }
}

impl<'a, 'w> serde::Serializer for &'a mut BinarySerializer<'w> {
    type Error = FortressError;
    type Ok = ();
    type SerializeSeq = Self;
    type SerializeTuple = Self;
    type SerializeTupleStruct = Self;
    type SerializeTupleVariant = Self;
    type SerializeMap = Self;
    type SerializeStruct = Self;
    type SerializeStructVariant = Self;

    fn serialize_bool(self, v: bool) -> Result<Self::Ok> {
        self.buffer.push(v as u8);
        Ok(())
    }

    fn serialize_i8(self, v: i8) -> Result<Self::Ok> {
        self.buffer.push(v as u8);
        Ok(())
    }

    fn serialize_i16(self, v: i16) -> Result<Self::Ok> {
        self.buffer.write_i16::<LittleEndian>(v)?;
        Ok(())
    }

    fn serialize_i32(self, v: i32) -> Result<Self::Ok> {
        self.buffer.write_i32::<LittleEndian>(v)?;
        Ok(())
    }

    fn serialize_i64(self, v: i64) -> Result<Self::Ok> {
        self.buffer.write_i64::<LittleEndian>(v)?;
        Ok(())
    }

    fn serialize_u8(self, v: u8) -> Result<Self::Ok> {
        self.buffer.push(v);
        Ok(())
    }

    fn serialize_u16(self, v: u16) -> Result<Self::Ok> {
        self.buffer.write_u16::<LittleEndian>(v)?;
        Ok(())
    }

    fn serialize_u32(self, v: u32) -> Result<Self::Ok> {
        self.buffer.write_u32::<LittleEndian>(v)?;
        Ok(())
    }

    fn serialize_u64(self, v: u64) -> Result<Self::Ok> {
        self.buffer.write_u64::<LittleEndian>(v)?;
        Ok(())
    }

    fn serialize_f32(self, v: f32) -> Result<Self::Ok> {
        self.buffer.write_f32::<LittleEndian>(v)?;
        Ok(())
    }

    fn serialize_f64(self, v: f64) -> Result<Self::Ok> {
        self.buffer.write_f64::<LittleEndian>(v)?;
        Ok(())
    }

    fn serialize_char(self, v: char) -> Result<Self::Ok> {
        self.write_string(&v.to_string())?;
        Ok(())
    }

    fn serialize_str(self, v: &str) -> Result<Self::Ok> {
        self.write_string(v)?;
        Ok(())
    }

    fn serialize_bytes(self, v: &[u8]) -> Result<Self::Ok> {
        self.write_bytes(v)?;
        Ok(())
    }

    fn serialize_none(self) -> Result<Self::Ok> {
        self.buffer.push(0);
        Ok(())
    }

    fn serialize_some<T: ?Sized>(self, value: &T) -> Result<Self::Ok>
    where
        T: serde::Serialize,
    {
        self.buffer.push(1);
        value.serialize(self)?;
        Ok(())
    }

    fn serialize_unit(self) -> Result<Self::Ok> {
        Ok(())
    }

    fn serialize_unit_struct(self, _name: &'static str) -> Result<Self::Ok> {
        Ok(())
    }

    fn serialize_unit_variant(
        self,
        _name: &'static str,
        variant_index: u32,
        _variant: &'static str,
    ) -> Result<Self::Ok> {
        self.write_varint(variant_index as u64)?;
        Ok(())
    }

    fn serialize_newtype_struct<T: ?Sized>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<Self::Ok>
    where
        T: serde::Serialize,
    {
        value.serialize(self)?;
        Ok(())
    }

    fn serialize_newtype_variant<T: ?Sized>(
        self,
        _name: &'static str,
        variant_index: u32,
        _variant: &'static str,
        value: &T,
    ) -> Result<Self::Ok>
    where
        T: serde::Serialize,
    {
        self.write_varint(variant_index as u64)?;
        value.serialize(self)?;
        Ok(())
    }

    fn serialize_seq(self, len: Option<usize>) -> Result<Self::SerializeSeq> {
        if let Some(len) = len {
            self.write_varint(len as u64)?;
        } else {
            // For sequences without known length, we'll use a marker
            self.buffer.push(0xFF);
        }
        Ok(self)
    }

    fn serialize_tuple(self, len: usize) -> Result<Self::SerializeTuple> {
        self.write_varint(len as u64)?;
        Ok(self)
    }

    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleStruct> {
        self.write_varint(len as u64)?;
        Ok(self)
    }

    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        variant_index: u32,
        _variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleVariant> {
        self.write_varint(variant_index as u64)?;
        self.write_varint(len as u64)?;
        Ok(self)
    }

    fn serialize_map(self, len: Option<usize>) -> Result<Self::SerializeMap> {
        if let Some(len) = len {
            self.write_varint(len as u64)?;
        } else {
            self.buffer.push(0xFF);
        }
        Ok(self)
    }

    fn serialize_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStruct> {
        self.write_varint(len as u64)?;
        Ok(self)
    }

    fn serialize_struct_variant(
        self,
        _name: &'static str,
        variant_index: u32,
        _variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStructVariant> {
        self.write_varint(variant_index as u64)?;
        self.write_varint(len as u64)?;
        Ok(self)
    }
}

impl<'a, 'w> serde::ser::SerializeSeq for &'a mut BinarySerializer<'w> {
    type Error = FortressError;
    type Ok = ();

    fn serialize_element<T: ?Sized>(&mut self, value: &T) -> Result<()>
    where
        T: serde::Serialize,
    {
        value.serialize(&mut **self)?;
        Ok(())
    }

    fn end(self) -> Result<Self::Ok> {
        Ok(())
    }
}

impl<'a, 'w> serde::ser::SerializeTuple for &'a mut BinarySerializer<'w> {
    type Error = FortressError;
    type Ok = ();

    fn serialize_element<T: ?Sized>(&mut self, value: &T) -> Result<()>
    where
        T: serde::Serialize,
    {
        value.serialize(&mut **self)?;
        Ok(())
    }

    fn end(self) -> Result<Self::Ok> {
        Ok(())
    }
}

impl<'a, 'w> serde::ser::SerializeTupleStruct for &'a mut BinarySerializer<'w> {
    type Error = FortressError;
    type Ok = ();

    fn serialize_field<T: ?Sized>(&mut self, value: &T) -> Result<()>
    where
        T: serde::Serialize,
    {
        value.serialize(&mut **self)?;
        Ok(())
    }

    fn end(self) -> Result<Self::Ok> {
        Ok(())
    }
}

impl<'a, 'w> serde::ser::SerializeTupleVariant for &'a mut BinarySerializer<'w> {
    type Error = FortressError;
    type Ok = ();

    fn serialize_field<T: ?Sized>(&mut self, value: &T) -> Result<()>
    where
        T: serde::Serialize,
    {
        value.serialize(&mut **self)?;
        Ok(())
    }

    fn end(self) -> Result<Self::Ok> {
        Ok(())
    }
}

impl<'a, 'w> serde::ser::SerializeMap for &'a mut BinarySerializer<'w> {
    type Error = FortressError;
    type Ok = ();

    fn serialize_key<T: ?Sized>(&mut self, key: &T) -> Result<()>
    where
        T: serde::Serialize,
    {
        key.serialize(&mut **self)?;
        Ok(())
    }

    fn serialize_value<T: ?Sized>(&mut self, value: &T) -> Result<()>
    where
        T: serde::Serialize,
    {
        value.serialize(&mut **self)?;
        Ok(())
    }

    fn end(self) -> Result<Self::Ok> {
        Ok(())
    }
}

impl<'a, 'w> serde::ser::SerializeStruct for &'a mut BinarySerializer<'w> {
    type Error = FortressError;
    type Ok = ();

    fn serialize_field<T: ?Sized>(&mut self, _key: &'static str, value: &T) -> Result<()>
    where
        T: serde::Serialize,
    {
        value.serialize(&mut **self)?;
        Ok(())
    }

    fn end(self) -> Result<Self::Ok> {
        Ok(())
    }
}

impl<'a, 'w> serde::ser::SerializeStructVariant for &'a mut BinarySerializer<'w> {
    type Error = FortressError;
    type Ok = ();

    fn serialize_field<T: ?Sized>(&mut self, _key: &'static str, value: &T) -> Result<()>
    where
        T: serde::Serialize,
    {
        value.serialize(&mut **self)?;
        Ok(())
    }

    fn end(self) -> Result<Self::Ok> {
        Ok(())
    }
}

/// Binary deserializer implementation
struct BinaryDeserializer<'a> {
    cursor: Cursor<&'a [u8]>,
    protocol: &'a BinaryProtocol,
}

impl<'a> BinaryDeserializer<'a> {
    fn new(data: &'a [u8], protocol: &'a BinaryProtocol) -> Self {
        Self {
            cursor: Cursor::new(data),
            protocol,
        }
    }

    fn read_varint(&mut self) -> Result<u64> {
        let mut result = 0u64;
        let mut shift = 0;
        
        loop {
            let byte = self.cursor.read_u8()?;
            result |= ((byte & 0x7F) as u64) << shift;
            shift += 7;
            if byte & 0x80 == 0 {
                break;
            }
        }
        
        Ok(result)
    }

    fn read_string(&mut self) -> Result<String> {
        let len = self.read_varint()? as usize;
        let mut bytes = vec![0u8; len];
        self.cursor.read_exact(&mut bytes)?;
        Ok(String::from_utf8(bytes)?)
    }

    fn read_bytes(&mut self) -> Result<Vec<u8>> {
        let len = self.read_varint()? as usize;
        let mut bytes = vec![0u8; len];
        self.cursor.read_exact(&mut bytes)?;
        Ok(bytes)
    }
}

impl<'a, 'de> serde::de::Deserializer<'de> for &'a mut BinaryDeserializer<'a> {
    type Error = FortressError;

    fn deserialize_any<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: serde::de::Visitor<'de>,
    {
        Err(FortressError::serialization("deserialize_any not supported", "Use specific deserialize methods"))
    }

    fn deserialize_bool<V>(self, visitor: V) -> Result<V::Value>
    where
        V: serde::de::Visitor<'de>,
    {
        let value = self.cursor.read_u8()? != 0;
        visitor.visit_bool(value)
    }

    fn deserialize_i8<V>(self, visitor: V) -> Result<V::Value>
    where
        V: serde::de::Visitor<'de>,
    {
        let value = self.cursor.read_i8()?;
        visitor.visit_i8(value)
    }

    fn deserialize_i16<V>(self, visitor: V) -> Result<V::Value>
    where
        V: serde::de::Visitor<'de>,
    {
        let value = self.cursor.read_i16::<LittleEndian>()?;
        visitor.visit_i16(value)
    }

    fn deserialize_i32<V>(self, visitor: V) -> Result<V::Value>
    where
        V: serde::de::Visitor<'de>,
    {
        let value = self.cursor.read_i32::<LittleEndian>()?;
        visitor.visit_i32(value)
    }

    fn deserialize_i64<V>(self, visitor: V) -> Result<V::Value>
    where
        V: serde::de::Visitor<'de>,
    {
        let value = self.cursor.read_i64::<LittleEndian>()?;
        visitor.visit_i64(value)
    }

    fn deserialize_u8<V>(self, visitor: V) -> Result<V::Value>
    where
        V: serde::de::Visitor<'de>,
    {
        let value = self.cursor.read_u8()?;
        visitor.visit_u8(value)
    }

    fn deserialize_u16<V>(self, visitor: V) -> Result<V::Value>
    where
        V: serde::de::Visitor<'de>,
    {
        let value = self.cursor.read_u16::<LittleEndian>()?;
        visitor.visit_u16(value)
    }

    fn deserialize_u32<V>(self, visitor: V) -> Result<V::Value>
    where
        V: serde::de::Visitor<'de>,
    {
        let value = self.cursor.read_u32::<LittleEndian>()?;
        visitor.visit_u32(value)
    }

    fn deserialize_u64<V>(self, visitor: V) -> Result<V::Value>
    where
        V: serde::de::Visitor<'de>,
    {
        let value = self.cursor.read_u64::<LittleEndian>()?;
        visitor.visit_u64(value)
    }

    fn deserialize_f32<V>(self, visitor: V) -> Result<V::Value>
    where
        V: serde::de::Visitor<'de>,
    {
        let value = self.cursor.read_f32::<LittleEndian>()?;
        visitor.visit_f32(value)
    }

    fn deserialize_f64<V>(self, visitor: V) -> Result<V::Value>
    where
        V: serde::de::Visitor<'de>,
    {
        let value = self.cursor.read_f64::<LittleEndian>()?;
        visitor.visit_f64(value)
    }

    fn deserialize_char<V>(self, visitor: V) -> Result<V::Value>
    where
        V: serde::de::Visitor<'de>,
    {
        let string = self.read_string()?;
        let chars: Vec<char> = string.chars().collect();
        if chars.len() != 1 {
            return Err(FortressError::serialization("Expected single character", string));
        }
        visitor.visit_char(chars[0])
    }

    fn deserialize_str<V>(self, visitor: V) -> Result<V::Value>
    where
        V: serde::de::Visitor<'de>,
    {
        let string = self.read_string()?;
        visitor.visit_str(&string)
    }

    fn deserialize_string<V>(self, visitor: V) -> Result<V::Value>
    where
        V: serde::de::Visitor<'de>,
    {
        let string = self.read_string()?;
        visitor.visit_string(string)
    }

    fn deserialize_bytes<V>(self, visitor: V) -> Result<V::Value>
    where
        V: serde::de::Visitor<'de>,
    {
        let bytes = self.read_bytes()?;
        visitor.visit_bytes(&bytes)
    }

    fn deserialize_byte_buf<V>(self, visitor: V) -> Result<V::Value>
    where
        V: serde::de::Visitor<'de>,
    {
        let bytes = self.read_bytes()?;
        visitor.visit_byte_buf(bytes)
    }

    fn deserialize_option<V>(self, visitor: V) -> Result<V::Value>
    where
        V: serde::de::Visitor<'de>,
    {
        let marker = self.cursor.read_u8()?;
        if marker == 0 {
            visitor.visit_none()
        } else {
            visitor.visit_some(self)
        }
    }

    fn deserialize_unit<V>(self, visitor: V) -> Result<V::Value>
    where
        V: serde::de::Visitor<'de>,
    {
        visitor.visit_unit()
    }

    fn deserialize_unit_struct<V>(self, _name: &'static str, visitor: V) -> Result<V::Value>
    where
        V: serde::de::Visitor<'de>,
    {
        visitor.visit_unit()
    }

    fn deserialize_newtype_struct<V>(self, _name: &'static str, visitor: V) -> Result<V::Value>
    where
        V: serde::de::Visitor<'de>,
    {
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_seq<V>(self, visitor: V) -> Result<V::Value>
    where
        V: serde::de::Visitor<'de>,
    {
        let len = self.read_varint()? as usize;
        visitor.visit_seq(BinarySeqAccess::new(self, len))
    }

    fn deserialize_tuple<V>(self, len: usize, visitor: V) -> Result<V::Value>
    where
        V: serde::de::Visitor<'de>,
    {
        visitor.visit_tuple(BinaryTupleAccess::new(self, len))
    }

    fn deserialize_tuple_struct<V>(self, _name: &'static str, len: usize, visitor: V) -> Result<V::Value>
    where
        V: serde::de::Visitor<'de>,
    {
        visitor.visit_tuple_struct(BinaryTupleAccess::new(self, len))
    }

    fn deserialize_map<V>(self, visitor: V) -> Result<V::Value>
    where
        V: serde::de::Visitor<'de>,
    {
        let len = self.read_varint()? as usize;
        visitor.visit_map(BinaryMapAccess::new(self, len))
    }

    fn deserialize_struct<V>(
        self,
        _name: &'static str,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value>
    where
        V: serde::de::Visitor<'de>,
    {
        visitor.visit_struct(BinaryStructAccess::new(self, fields.len()))
    }

    fn deserialize_enum<V>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value>
    where
        V: serde::de::Visitor<'de>,
    {
        visitor.visit_enum(BinaryEnumAccess::new(self))
    }

    fn deserialize_identifier<V>(self, visitor: V) -> Result<V::Value>
    where
        V: serde::de::Visitor<'de>,
    {
        self.deserialize_u32(visitor)
    }

    fn deserialize_ignored_any<V>(self, visitor: V) -> Result<V::Value>
    where
        V: serde::de::Visitor<'de>,
    {
        self.deserialize_any(visitor)
    }
}

// Helper structs for deserialization
struct BinarySeqAccess<'a> {
    deserializer: &'a mut BinaryDeserializer<'a>,
    remaining: usize,
}

impl<'a> BinarySeqAccess<'a> {
    fn new(deserializer: &'a mut BinaryDeserializer<'a>, len: usize) -> Self {
        Self {
            deserializer,
            remaining: len,
        }
    }
}

impl<'a, 'de> serde::de::SeqAccess<'de> for BinarySeqAccess<'a> {
    type Error = FortressError;

    fn next_element_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>>
    where
        T: serde::de::DeserializeSeed<'de>,
    {
        if self.remaining == 0 {
            return Ok(None);
        }
        self.remaining -= 1;
        Ok(Some(seed.deserialize(&mut *self.deserializer)?))
    }

    fn size_hint(&self) -> Option<usize> {
        Some(self.remaining)
    }
}

struct BinaryTupleAccess<'a> {
    deserializer: &'a mut BinaryDeserializer<'a>,
    remaining: usize,
}

impl<'a> BinaryTupleAccess<'a> {
    fn new(deserializer: &'a mut BinaryDeserializer<'a>, len: usize) -> Self {
        Self {
            deserializer,
            remaining: len,
        }
    }
}

impl<'a, 'de> TupleAccess<'de> for BinaryTupleAccess<'a> {
    type Error = FortressError;

    fn next_element_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>>
    where
        T: serde::de::DeserializeSeed<'de>,
    {
        if self.remaining == 0 {
            return Ok(None);
        }
        self.remaining -= 1;
        Ok(Some(seed.deserialize(&mut *self.deserializer)?))
    }
}

struct BinaryStructAccess<'a> {
    deserializer: &'a mut BinaryDeserializer<'a>,
    remaining: usize,
}

impl<'a> BinaryStructAccess<'a> {
    fn new(deserializer: &'a mut BinaryDeserializer<'a>, len: usize) -> Self {
        Self {
            deserializer,
            remaining: len,
        }
    }
}

impl<'a, 'de> serde::de::SeqAccess<'de> for BinaryStructAccess<'a> {
    type Error = FortressError;

    fn next_element_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>>
    where
        T: serde::de::DeserializeSeed<'de>,
    {
        if self.remaining == 0 {
            return Ok(None);
        }
        self.remaining -= 1;
        Ok(Some(seed.deserialize(&mut *self.deserializer)?))
    }

    fn size_hint(&self) -> Option<usize> {
        Some(self.remaining)
    }
}

impl<'a, 'de> serde::de::MapAccess<'de> for BinaryStructAccess<'a> {
    type Error = FortressError;

    fn next_key_seed<K>(&mut self, seed: K) -> Result<Option<K::Value>>
    where
        K: serde::de::DeserializeSeed<'de>,
    {
        if self.remaining == 0 {
            return Ok(None);
        }
        self.remaining -= 1;
        Ok(Some(seed.deserialize(&mut *self.deserializer)?))
    }

    fn next_value_seed<V>(&mut self, seed: V) -> Result<V::Value>
    where
        V: serde::de::DeserializeSeed<'de>,
    {
        seed.deserialize(&mut *self.deserializer)
    }
}

impl<'a, 'de> StructAccess<'de> for BinaryStructAccess<'a> {
    type Error = FortressError;

    fn field<T>(&mut self, seed: T) -> Result<T::Value>
    where
        T: serde::de::DeserializeSeed<'de>,
    {
        seed.deserialize(&mut *self.deserializer)
    }

    fn skip_field(&mut self) -> Result<bool> {
        // For simplicity, we'll skip by reading and discarding
        // In a real implementation, this would be more sophisticated
        Ok(true)
    }
}

struct BinaryMapAccess<'a> {
    deserializer: &'a mut BinaryDeserializer<'a>,
    remaining: usize,
}

impl<'a> BinaryMapAccess<'a> {
    fn new(deserializer: &'a mut BinaryDeserializer<'a>, len: usize) -> Self {
        Self {
            deserializer,
            remaining: len,
        }
    }
}

impl<'a, 'de> serde::de::MapAccess<'de> for BinaryMapAccess<'a> {
    type Error = FortressError;

    fn next_key_seed<K>(&mut self, seed: K) -> Result<Option<K::Value>>
    where
        K: serde::de::DeserializeSeed<'de>,
    {
        if self.remaining == 0 {
            return Ok(None);
        }
        self.remaining -= 1;
        Ok(Some(seed.deserialize(&mut *self.deserializer)?))
    }

    fn next_value_seed<V>(&mut self, seed: V) -> Result<V::Value>
    where
        V: serde::de::DeserializeSeed<'de>,
    {
        seed.deserialize(&mut *self.deserializer)
    }
}

struct BinaryEnumAccess<'a> {
    deserializer: &'a mut BinaryDeserializer<'a>,
}

impl<'a> BinaryEnumAccess<'a> {
    fn new(deserializer: &'a mut BinaryDeserializer<'a>) -> Self {
        Self { deserializer }
    }
}

impl<'a, 'de> serde::de::EnumAccess<'de> for BinaryEnumAccess<'a> {
    type Error = FortressError;
    type Variant = Self;

    fn variant_seed<V>(self, seed: V) -> Result<(V::Value, Self::Variant)>
    where
        V: serde::de::DeserializeSeed<'de>,
    {
        let variant_index = self.deserializer.read_varint()?;
        let value = seed.deserialize(variant_index.into_deserializer())?;
        Ok((value, self))
    }
}

impl<'a, 'de> serde::de::VariantAccess<'de> for BinaryEnumAccess<'a> {
    type Error = FortressError;

    fn unit_variant(self) -> Result<()> {
        Ok(())
    }

    fn newtype_variant_seed<T>(self, seed: T) -> Result<T::Value>
    where
        T: serde::de::DeserializeSeed<'de>,
    {
        seed.deserialize(self.deserializer)
    }

    fn tuple_variant<V>(self, len: usize, visitor: V) -> Result<V::Value>
    where
        V: serde::de::Visitor<'de>,
    {
        visitor.visit_tuple(BinaryTupleAccess::new(self.deserializer, len))
    }

    fn struct_variant<V>(self, fields: &'static [&'static str], visitor: V) -> Result<V::Value>
    where
        V: serde::de::Visitor<'de>,
    {
        visitor.visit_struct(BinaryStructAccess::new(self.deserializer, fields.len()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct TestData {
        id: u64,
        name: String,
        active: bool,
        data: Vec<u8>,
    }

    #[test]
    fn test_binary_protocol_basic() {
        let protocol = BinaryProtocol::new().unwrap();
        
        let test_data = TestData {
            id: 12345,
            name: "test".to_string(),
            active: true,
            data: vec![1, 2, 3, 4, 5],
        };

        // Test serialization
        let serialized = protocol.serialize(&test_data).unwrap();
        assert!(serialized.len() > HEADER_SIZE);

        // Test deserialization
        let deserialized: TestData = protocol.deserialize(&serialized).unwrap();
        assert_eq!(deserialized, test_data);
    }

    #[test]
    fn test_binary_protocol_complex() {
        let protocol = BinaryProtocol::new().unwrap();
        
        let complex_data = vec![
            ("key1".to_string(), 123),
            ("key2".to_string(), 456),
            ("key3".to_string(), 789),
        ];

        // Test serialization
        let serialized = protocol.serialize(&complex_data).unwrap();
        assert!(serialized.len() > HEADER_SIZE);

        // Test deserialization
        let deserialized: Vec<(String, i32)> = protocol.deserialize(&serialized).unwrap();
        assert_eq!(deserialized, complex_data);
    }

    #[test]
    fn test_header_validation() {
        let protocol = BinaryProtocol::new().unwrap();
        
        let test_data = TestData {
            id: 123,
            name: "test".to_string(),
            active: true,
            data: vec![1, 2, 3],
        };

        let serialized = protocol.serialize(&test_data).unwrap();

        // Corrupt the header
        let mut corrupted = serialized.clone();
        corrupted[0] = 0xFF;

        // Should fail deserialization
        let result: Result<TestData> = protocol.deserialize(&corrupted);
        assert!(result.is_err());
    }
}
