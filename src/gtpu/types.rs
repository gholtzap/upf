#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    EchoRequest,
    EchoResponse,
    ErrorIndication,
    EndMarker,
    GPDU,
    Unknown(u8),
}

impl From<u8> for MessageType {
    fn from(value: u8) -> Self {
        match value {
            1 => MessageType::EchoRequest,
            2 => MessageType::EchoResponse,
            26 => MessageType::ErrorIndication,
            254 => MessageType::EndMarker,
            255 => MessageType::GPDU,
            v => MessageType::Unknown(v),
        }
    }
}

impl From<MessageType> for u8 {
    fn from(value: MessageType) -> Self {
        match value {
            MessageType::EchoRequest => 1,
            MessageType::EchoResponse => 2,
            MessageType::ErrorIndication => 26,
            MessageType::EndMarker => 254,
            MessageType::GPDU => 255,
            MessageType::Unknown(v) => v,
        }
    }
}

pub const GTPU_VERSION: u8 = 1;
pub const GTPU_PORT: u16 = 2152;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtensionHeaderType {
    NoMoreExtensionHeaders,
    Reserved,
    UdpPort,
    PdcpPduNumber,
    LongPdcpPduNumber,
    ServiceClassIndicator,
    RanContainer,
    PduSessionContainer,
    Unknown(u8),
}

impl From<u8> for ExtensionHeaderType {
    fn from(value: u8) -> Self {
        match value {
            0 => ExtensionHeaderType::NoMoreExtensionHeaders,
            1 => ExtensionHeaderType::Reserved,
            64 => ExtensionHeaderType::UdpPort,
            192 => ExtensionHeaderType::PdcpPduNumber,
            193 => ExtensionHeaderType::LongPdcpPduNumber,
            32 => ExtensionHeaderType::ServiceClassIndicator,
            129 => ExtensionHeaderType::RanContainer,
            133 => ExtensionHeaderType::PduSessionContainer,
            v => ExtensionHeaderType::Unknown(v),
        }
    }
}

impl From<ExtensionHeaderType> for u8 {
    fn from(value: ExtensionHeaderType) -> Self {
        match value {
            ExtensionHeaderType::NoMoreExtensionHeaders => 0,
            ExtensionHeaderType::Reserved => 1,
            ExtensionHeaderType::UdpPort => 64,
            ExtensionHeaderType::PdcpPduNumber => 192,
            ExtensionHeaderType::LongPdcpPduNumber => 193,
            ExtensionHeaderType::ServiceClassIndicator => 32,
            ExtensionHeaderType::RanContainer => 129,
            ExtensionHeaderType::PduSessionContainer => 133,
            ExtensionHeaderType::Unknown(v) => v,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionHeader {
    pub extension_type: ExtensionHeaderType,
    pub content: Vec<u8>,
}
