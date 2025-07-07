// Generic Ciphersuite Trait
use frost_core::{
    Group,
    Field,
};

pub enum BytesOrder {
    BigEndian,
    LittleEndian,
}

pub trait ScalarSerializationFormat {
    fn bytes_order() -> BytesOrder;
}
pub trait Ciphersuite: frost_core::Ciphersuite + ScalarSerializationFormat {}

pub(crate) type Scalar<C> = <<<C as frost_core::Ciphersuite>::Group as Group>::Field as Field>::Scalar;
pub(crate) type Element<C> = <<C as frost_core::Ciphersuite>::Group as Group>::Element;
