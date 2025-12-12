use std::net::Ipv4Addr;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    HeartbeatRequest = 1,
    HeartbeatResponse = 2,
    PfdManagementRequest = 3,
    PfdManagementResponse = 4,
    AssociationSetupRequest = 5,
    AssociationSetupResponse = 6,
    AssociationUpdateRequest = 7,
    AssociationUpdateResponse = 8,
    AssociationReleaseRequest = 9,
    AssociationReleaseResponse = 10,
    NodeReportRequest = 12,
    NodeReportResponse = 13,
    SessionSetEstablishmentRequest = 50,
    SessionSetEstablishmentResponse = 51,
    SessionEstablishmentRequest = 52,
    SessionEstablishmentResponse = 53,
    SessionModificationRequest = 54,
    SessionModificationResponse = 55,
    SessionDeletionRequest = 56,
    SessionDeletionResponse = 57,
    SessionReportRequest = 58,
    SessionReportResponse = 59,
    Unknown(u8),
}

impl From<u8> for MessageType {
    fn from(value: u8) -> Self {
        match value {
            1 => MessageType::HeartbeatRequest,
            2 => MessageType::HeartbeatResponse,
            3 => MessageType::PfdManagementRequest,
            4 => MessageType::PfdManagementResponse,
            5 => MessageType::AssociationSetupRequest,
            6 => MessageType::AssociationSetupResponse,
            7 => MessageType::AssociationUpdateRequest,
            8 => MessageType::AssociationUpdateResponse,
            9 => MessageType::AssociationReleaseRequest,
            10 => MessageType::AssociationReleaseResponse,
            12 => MessageType::NodeReportRequest,
            13 => MessageType::NodeReportResponse,
            50 => MessageType::SessionSetEstablishmentRequest,
            51 => MessageType::SessionSetEstablishmentResponse,
            52 => MessageType::SessionEstablishmentRequest,
            53 => MessageType::SessionEstablishmentResponse,
            54 => MessageType::SessionModificationRequest,
            55 => MessageType::SessionModificationResponse,
            56 => MessageType::SessionDeletionRequest,
            57 => MessageType::SessionDeletionResponse,
            58 => MessageType::SessionReportRequest,
            59 => MessageType::SessionReportResponse,
            v => MessageType::Unknown(v),
        }
    }
}

impl From<MessageType> for u8 {
    fn from(value: MessageType) -> Self {
        match value {
            MessageType::HeartbeatRequest => 1,
            MessageType::HeartbeatResponse => 2,
            MessageType::PfdManagementRequest => 3,
            MessageType::PfdManagementResponse => 4,
            MessageType::AssociationSetupRequest => 5,
            MessageType::AssociationSetupResponse => 6,
            MessageType::AssociationUpdateRequest => 7,
            MessageType::AssociationUpdateResponse => 8,
            MessageType::AssociationReleaseRequest => 9,
            MessageType::AssociationReleaseResponse => 10,
            MessageType::NodeReportRequest => 12,
            MessageType::NodeReportResponse => 13,
            MessageType::SessionSetEstablishmentRequest => 50,
            MessageType::SessionSetEstablishmentResponse => 51,
            MessageType::SessionEstablishmentRequest => 52,
            MessageType::SessionEstablishmentResponse => 53,
            MessageType::SessionModificationRequest => 54,
            MessageType::SessionModificationResponse => 55,
            MessageType::SessionDeletionRequest => 56,
            MessageType::SessionDeletionResponse => 57,
            MessageType::SessionReportRequest => 58,
            MessageType::SessionReportResponse => 59,
            MessageType::Unknown(v) => v,
        }
    }
}

pub const PFCP_VERSION: u8 = 1;
pub const PFCP_PORT: u16 = 8805;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CauseValue {
    RequestAccepted = 1,
    RequestRejected = 64,
    SessionContextNotFound = 65,
    MandatoryIeMissing = 66,
    ConditionalIeMissing = 67,
    InvalidLength = 68,
    MandatoryIeIncorrect = 69,
    InvalidForwardingPolicy = 70,
    InvalidFTeidAllocationOption = 71,
    NoEstablishedPfcpAssociation = 72,
    RuleCreationModificationFailure = 73,
    PfcpEntityInCongestion = 74,
    NoResourcesAvailable = 75,
    ServiceNotSupported = 76,
    SystemFailure = 77,
    Unknown(u8),
}

impl From<u8> for CauseValue {
    fn from(value: u8) -> Self {
        match value {
            1 => CauseValue::RequestAccepted,
            64 => CauseValue::RequestRejected,
            65 => CauseValue::SessionContextNotFound,
            66 => CauseValue::MandatoryIeMissing,
            67 => CauseValue::ConditionalIeMissing,
            68 => CauseValue::InvalidLength,
            69 => CauseValue::MandatoryIeIncorrect,
            70 => CauseValue::InvalidForwardingPolicy,
            71 => CauseValue::InvalidFTeidAllocationOption,
            72 => CauseValue::NoEstablishedPfcpAssociation,
            73 => CauseValue::RuleCreationModificationFailure,
            74 => CauseValue::PfcpEntityInCongestion,
            75 => CauseValue::NoResourcesAvailable,
            76 => CauseValue::ServiceNotSupported,
            77 => CauseValue::SystemFailure,
            v => CauseValue::Unknown(v),
        }
    }
}

impl From<CauseValue> for u8 {
    fn from(value: CauseValue) -> Self {
        match value {
            CauseValue::RequestAccepted => 1,
            CauseValue::RequestRejected => 64,
            CauseValue::SessionContextNotFound => 65,
            CauseValue::MandatoryIeMissing => 66,
            CauseValue::ConditionalIeMissing => 67,
            CauseValue::InvalidLength => 68,
            CauseValue::MandatoryIeIncorrect => 69,
            CauseValue::InvalidForwardingPolicy => 70,
            CauseValue::InvalidFTeidAllocationOption => 71,
            CauseValue::NoEstablishedPfcpAssociation => 72,
            CauseValue::RuleCreationModificationFailure => 73,
            CauseValue::PfcpEntityInCongestion => 74,
            CauseValue::NoResourcesAvailable => 75,
            CauseValue::ServiceNotSupported => 76,
            CauseValue::SystemFailure => 77,
            CauseValue::Unknown(v) => v,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeId {
    Ipv4(Ipv4Addr),
    Ipv6([u8; 16]),
    Fqdn(String),
}
