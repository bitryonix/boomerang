//! Stable message-tag registry for all wire-visible payloads.

use super::{TaggedMessage, WireDecodeError};

/// One entry in the stable protocol message registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageRegistryEntry {
    pub tag: MessageTag,
    pub name: &'static str,
    pub type_name: &'static str,
}

macro_rules! message_tag_registry {
    ($(($tag:literal, $name:ident, $type:path)),+ $(,)?) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[repr(u16)]
        pub enum MessageTag {
            $(
                $name = $tag,
            )+
        }

        impl MessageTag {
            pub const fn as_u16(self) -> u16 {
                self as u16
            }

            pub const fn name(self) -> &'static str {
                match self {
                    $(
                        Self::$name => stringify!($name),
                    )+
                }
            }

            pub const fn type_name(self) -> &'static str {
                match self {
                    $(
                        Self::$name => stringify!($type),
                    )+
                }
            }

            pub const fn registry() -> &'static [MessageRegistryEntry] {
                &MESSAGE_REGISTRY
            }

            pub fn try_from_u16(value: u16) -> Result<Self, WireDecodeError> {
                match value {
                    $(
                        $tag => Ok(Self::$name),
                    )+
                    _ => Err(WireDecodeError::UnknownMessageTag(value)),
                }
            }
        }

        impl TryFrom<u16> for MessageTag {
            type Error = WireDecodeError;

            fn try_from(value: u16) -> Result<Self, Self::Error> {
                Self::try_from_u16(value)
            }
        }

        $(
            impl TaggedMessage for $type {
                const TAG: MessageTag = MessageTag::$name;
            }
        )+

        const MESSAGE_REGISTRY: [MessageRegistryEntry; message_tag_registry!(@count $($name)+)] = [
            $(
                MessageRegistryEntry {
                    tag: MessageTag::$name,
                    name: stringify!($name),
                    type_name: stringify!($type),
                },
            )+
        ];
    };
    (@count $($name:ident)+) => {
        <[()]>::len(&[$(message_tag_registry!(@unit $name)),+])
    };
    (@unit $name:ident) => {
        ()
    };
}

message_tag_registry! {
    // 0x1000 - 0x1fff reserved for setup messages.
    (0x1000, SetupBoomletIsoMessage1, protocol::messages::setup::from_boomlet::to_iso::SetupBoomletIsoMessage1),
    (0x1001, SetupBoomletIsoMessage2, protocol::messages::setup::from_boomlet::to_iso::SetupBoomletIsoMessage2),
    (0x1002, SetupBoomletIsoMessage3, protocol::messages::setup::from_boomlet::to_iso::SetupBoomletIsoMessage3),
    (0x1003, SetupBoomletIsoMessage4, protocol::messages::setup::from_boomlet::to_iso::SetupBoomletIsoMessage4),
    (0x1004, SetupBoomletIsoMessage5, protocol::messages::setup::from_boomlet::to_iso::SetupBoomletIsoMessage5),
    (0x1005, SetupBoomletIsoMessage6, protocol::messages::setup::from_boomlet::to_iso::SetupBoomletIsoMessage6),
    (0x1006, SetupBoomletNisoMessage1, protocol::messages::setup::from_boomlet::to_niso::SetupBoomletNisoMessage1),
    (0x1007, SetupBoomletNisoMessage10, protocol::messages::setup::from_boomlet::to_niso::SetupBoomletNisoMessage10),
    (0x1008, SetupBoomletNisoMessage11, protocol::messages::setup::from_boomlet::to_niso::SetupBoomletNisoMessage11),
    (0x1009, SetupBoomletNisoMessage12, protocol::messages::setup::from_boomlet::to_niso::SetupBoomletNisoMessage12),
    (0x100A, SetupBoomletNisoMessage2, protocol::messages::setup::from_boomlet::to_niso::SetupBoomletNisoMessage2),
    (0x100B, SetupBoomletNisoMessage3, protocol::messages::setup::from_boomlet::to_niso::SetupBoomletNisoMessage3),
    (0x100C, SetupBoomletNisoMessage4, protocol::messages::setup::from_boomlet::to_niso::SetupBoomletNisoMessage4),
    (0x100D, SetupBoomletNisoMessage5, protocol::messages::setup::from_boomlet::to_niso::SetupBoomletNisoMessage5),
    (0x100E, SetupBoomletNisoMessage6, protocol::messages::setup::from_boomlet::to_niso::SetupBoomletNisoMessage6),
    (0x100F, SetupBoomletNisoMessage7, protocol::messages::setup::from_boomlet::to_niso::SetupBoomletNisoMessage7),
    (0x1010, SetupBoomletNisoMessage8, protocol::messages::setup::from_boomlet::to_niso::SetupBoomletNisoMessage8),
    (0x1011, SetupBoomletNisoMessage9, protocol::messages::setup::from_boomlet::to_niso::SetupBoomletNisoMessage9),
    (0x1012, SetupBoomletwoIsoMessage1, protocol::messages::setup::from_boomletwo::to_iso::SetupBoomletwoIsoMessage1),
    (0x1013, SetupBoomletwoIsoMessage2, protocol::messages::setup::from_boomletwo::to_iso::SetupBoomletwoIsoMessage2),
    (0x1014, SetupIsoBoomletMessage1, protocol::messages::setup::from_iso::to_boomlet::SetupIsoBoomletMessage1),
    (0x1015, SetupIsoBoomletMessage2, protocol::messages::setup::from_iso::to_boomlet::SetupIsoBoomletMessage2),
    (0x1016, SetupIsoBoomletMessage3, protocol::messages::setup::from_iso::to_boomlet::SetupIsoBoomletMessage3),
    (0x1017, SetupIsoBoomletMessage4, protocol::messages::setup::from_iso::to_boomlet::SetupIsoBoomletMessage4),
    (0x1018, SetupIsoBoomletMessage5, protocol::messages::setup::from_iso::to_boomlet::SetupIsoBoomletMessage5),
    (0x1019, SetupIsoBoomletMessage6, protocol::messages::setup::from_iso::to_boomlet::SetupIsoBoomletMessage6),
    (0x101A, SetupIsoBoomletwoMessage1, protocol::messages::setup::from_iso::to_boomletwo::SetupIsoBoomletwoMessage1),
    (0x101B, SetupIsoBoomletwoMessage2, protocol::messages::setup::from_iso::to_boomletwo::SetupIsoBoomletwoMessage2),
    (0x101C, SetupIsoStMessage1, protocol::messages::setup::from_iso::to_st::SetupIsoStMessage1),
    (0x101D, SetupIsoStMessage2, protocol::messages::setup::from_iso::to_st::SetupIsoStMessage2),
    (0x101E, SetupIsoStMessage3, protocol::messages::setup::from_iso::to_st::SetupIsoStMessage3),
    (0x101F, SetupIsoOutput1, protocol::messages::setup::from_iso::to_user::SetupIsoOutput1),
    (0x1020, SetupIsoOutput2, protocol::messages::setup::from_iso::to_user::SetupIsoOutput2),
    (0x1021, SetupIsoOutput3, protocol::messages::setup::from_iso::to_user::SetupIsoOutput3),
    (0x1022, SetupIsoOutput4, protocol::messages::setup::from_iso::to_user::SetupIsoOutput4),
    (0x1023, SetupIsoOutput5, protocol::messages::setup::from_iso::to_user::SetupIsoOutput5),
    (0x1024, SetupNisoBoomletMessage1, protocol::messages::setup::from_niso::to_boomlet::SetupNisoBoomletMessage1),
    (0x1025, SetupNisoBoomletMessage10, protocol::messages::setup::from_niso::to_boomlet::SetupNisoBoomletMessage10),
    (0x1026, SetupNisoBoomletMessage11, protocol::messages::setup::from_niso::to_boomlet::SetupNisoBoomletMessage11),
    (0x1027, SetupNisoBoomletMessage12, protocol::messages::setup::from_niso::to_boomlet::SetupNisoBoomletMessage12),
    (0x1028, SetupNisoBoomletMessage2, protocol::messages::setup::from_niso::to_boomlet::SetupNisoBoomletMessage2),
    (0x1029, SetupNisoBoomletMessage3, protocol::messages::setup::from_niso::to_boomlet::SetupNisoBoomletMessage3),
    (0x102A, SetupNisoBoomletMessage4, protocol::messages::setup::from_niso::to_boomlet::SetupNisoBoomletMessage4),
    (0x102B, SetupNisoBoomletMessage5, protocol::messages::setup::from_niso::to_boomlet::SetupNisoBoomletMessage5),
    (0x102C, SetupNisoBoomletMessage6, protocol::messages::setup::from_niso::to_boomlet::SetupNisoBoomletMessage6),
    (0x102D, SetupNisoBoomletMessage7, protocol::messages::setup::from_niso::to_boomlet::SetupNisoBoomletMessage7),
    (0x102E, SetupNisoBoomletMessage8, protocol::messages::setup::from_niso::to_boomlet::SetupNisoBoomletMessage8),
    (0x102F, SetupNisoBoomletMessage9, protocol::messages::setup::from_niso::to_boomlet::SetupNisoBoomletMessage9),
    (0x1030, SetupNisoPeerNisoMessage1, protocol::messages::setup::from_niso::to_niso::SetupNisoPeerNisoMessage1),
    (0x1031, SetupNisoPeerNisoMessage2, protocol::messages::setup::from_niso::to_niso::SetupNisoPeerNisoMessage2),
    (0x1032, SetupNisoPeerNisoMessage3, protocol::messages::setup::from_niso::to_niso::SetupNisoPeerNisoMessage3),
    (0x1033, SetupNisoPeerNisoMessage4, protocol::messages::setup::from_niso::to_niso::SetupNisoPeerNisoMessage4),
    (0x1034, SetupNisoSarMessage1, protocol::messages::setup::from_niso::to_sar::SetupNisoSarMessage1),
    (0x1035, SetupNisoSarMessage2, protocol::messages::setup::from_niso::to_sar::SetupNisoSarMessage2),
    (0x1036, SetupNisoStMessage1, protocol::messages::setup::from_niso::to_st::SetupNisoStMessage1),
    (0x1037, SetupNisoStMessage2, protocol::messages::setup::from_niso::to_st::SetupNisoStMessage2),
    (0x1038, SetupNisoOutput1, protocol::messages::setup::from_niso::to_user::SetupNisoOutput1),
    (0x1039, SetupNisoOutput2, protocol::messages::setup::from_niso::to_user::SetupNisoOutput2),
    (0x103A, SetupNisoOutput3, protocol::messages::setup::from_niso::to_user::SetupNisoOutput3),
    (0x103B, SetupNisoWtMessage1, protocol::messages::setup::from_niso::to_wt::SetupNisoWtMessage1),
    (0x103C, SetupNisoWtMessage2, protocol::messages::setup::from_niso::to_wt::SetupNisoWtMessage2),
    (0x103D, SetupNisoWtMessage3, protocol::messages::setup::from_niso::to_wt::SetupNisoWtMessage3),
    (0x103E, SetupPhoneSarMessage1, protocol::messages::setup::from_phone::to_sar::SetupPhoneSarMessage1),
    (0x103F, SetupPhoneSarMessage2, protocol::messages::setup::from_phone::to_sar::SetupPhoneSarMessage2),
    (0x1040, SetupPhoneOutput1, protocol::messages::setup::from_phone::to_user::SetupPhoneOutput1),
    (0x1041, SetupPhoneOutput2, protocol::messages::setup::from_phone::to_user::SetupPhoneOutput2),
    (0x1042, SetupSarPhoneMessage1, protocol::messages::setup::from_sar::to_phone::SetupSarPhoneMessage1),
    (0x1043, SetupSarPhoneMessage2, protocol::messages::setup::from_sar::to_phone::SetupSarPhoneMessage2),
    (0x1044, SetupSarWtMessage1, protocol::messages::setup::from_sar::to_wt::SetupSarWtMessage1),
    (0x1045, SetupStIsoMessage1, protocol::messages::setup::from_st::to_iso::SetupStIsoMessage1),
    (0x1046, SetupStIsoMessage2, protocol::messages::setup::from_st::to_iso::SetupStIsoMessage2),
    (0x1047, SetupStIsoMessage3, protocol::messages::setup::from_st::to_iso::SetupStIsoMessage3),
    (0x1048, SetupStNisoMessage1, protocol::messages::setup::from_st::to_niso::SetupStNisoMessage1),
    (0x1049, SetupStOutput1, protocol::messages::setup::from_st::to_user::SetupStOutput1),
    (0x104A, SetupStOutput2, protocol::messages::setup::from_st::to_user::SetupStOutput2),
    (0x104B, SetupStOutput3, protocol::messages::setup::from_st::to_user::SetupStOutput3),
    (0x104C, SetupStOutput4, protocol::messages::setup::from_st::to_user::SetupStOutput4),
    (0x104D, SetupIsoInput1, protocol::messages::setup::from_user::to_iso::SetupIsoInput1),
    (0x104E, SetupIsoInput2, protocol::messages::setup::from_user::to_iso::SetupIsoInput2),
    (0x104F, SetupIsoInput3, protocol::messages::setup::from_user::to_iso::SetupIsoInput3),
    (0x1050, SetupIsoInput4, protocol::messages::setup::from_user::to_iso::SetupIsoInput4),
    (0x1051, SetupIsoInput5, protocol::messages::setup::from_user::to_iso::SetupIsoInput5),
    (0x1052, SetupNisoInput1, protocol::messages::setup::from_user::to_niso::SetupNisoInput1),
    (0x1053, SetupNisoInput2, protocol::messages::setup::from_user::to_niso::SetupNisoInput2),
    (0x1054, SetupNisoInput3, protocol::messages::setup::from_user::to_niso::SetupNisoInput3),
    (0x1055, SetupNisoInput4, protocol::messages::setup::from_user::to_niso::SetupNisoInput4),
    (0x1056, SetupNisoInput5, protocol::messages::setup::from_user::to_niso::SetupNisoInput5),
    (0x1057, SetupPhoneInput1, protocol::messages::setup::from_user::to_phone::SetupPhoneInput1),
    (0x1058, SetupPhoneInput2, protocol::messages::setup::from_user::to_phone::SetupPhoneInput2),
    (0x1059, SetupStInput1, protocol::messages::setup::from_user::to_st::SetupStInput1),
    (0x105A, SetupStInput2, protocol::messages::setup::from_user::to_st::SetupStInput2),
    (0x105B, SetupStInput3, protocol::messages::setup::from_user::to_st::SetupStInput3),
    (0x105C, SetupUserPeersOutOfBandMessage1, protocol::messages::setup::from_user::to_user::SetupUserPeersOutOfBandMessage1),
    (0x105D, SetupWtNisoMessage1, protocol::messages::setup::from_wt::to_niso::SetupWtNisoMessage1),
    (0x105E, SetupWtNisoMessage2, protocol::messages::setup::from_wt::to_niso::SetupWtNisoMessage2),
    (0x105F, SetupWtNisoMessage3, protocol::messages::setup::from_wt::to_niso::SetupWtNisoMessage3),
    (0x1060, SetupWtSarMessage1, protocol::messages::setup::from_wt::to_sar::SetupWtSarMessage1),
    // 0x2000 - 0x2fff reserved for withdrawal messages.
    (0x2000, WithdrawalBoomletIsoMessage1, protocol::messages::withdrawal::from_boomlet::to_iso::WithdrawalBoomletIsoMessage1),
    (0x2001, WithdrawalBoomletIsoMessage2, protocol::messages::withdrawal::from_boomlet::to_iso::WithdrawalBoomletIsoMessage2),
    (0x2002, WithdrawalBoomletNisoMessage1, protocol::messages::withdrawal::from_boomlet::to_niso::WithdrawalBoomletNisoMessage1),
    (0x2003, WithdrawalBoomletNisoMessage2, protocol::messages::withdrawal::from_boomlet::to_niso::WithdrawalBoomletNisoMessage2),
    (0x2004, WithdrawalBoomletNisoMessage3, protocol::messages::withdrawal::from_boomlet::to_niso::WithdrawalBoomletNisoMessage3),
    (0x2005, WithdrawalBoomletNisoMessage4, protocol::messages::withdrawal::from_boomlet::to_niso::WithdrawalBoomletNisoMessage4),
    (0x2006, WithdrawalBoomletNisoMessage5, protocol::messages::withdrawal::from_boomlet::to_niso::WithdrawalBoomletNisoMessage5),
    (0x2007, WithdrawalBoomletNisoMessage6, protocol::messages::withdrawal::from_boomlet::to_niso::WithdrawalBoomletNisoMessage6),
    (0x2008, WithdrawalBoomletNisoMessage7, protocol::messages::withdrawal::from_boomlet::to_niso::WithdrawalBoomletNisoMessage7),
    (0x2009, WithdrawalBoomletNisoMessage8, protocol::messages::withdrawal::from_boomlet::to_niso::WithdrawalBoomletNisoMessage8),
    (0x200A, WithdrawalBoomletNisoMessage9, protocol::messages::withdrawal::from_boomlet::to_niso::WithdrawalBoomletNisoMessage9),
    (0x200B, WithdrawalIsoBoomletMessage1, protocol::messages::withdrawal::from_iso::to_boomlet::WithdrawalIsoBoomletMessage1),
    (0x200C, WithdrawalIsoBoomletMessage2, protocol::messages::withdrawal::from_iso::to_boomlet::WithdrawalIsoBoomletMessage2),
    (0x200D, WithdrawalIsoOutput1, protocol::messages::withdrawal::from_iso::to_user::WithdrawalIsoOutput1),
    (0x200E, WithdrawalNisoBoomletMessage1, protocol::messages::withdrawal::from_niso::to_boomlet::WithdrawalNisoBoomletMessage1),
    (0x200F, WithdrawalNisoBoomletMessage2, protocol::messages::withdrawal::from_niso::to_boomlet::WithdrawalNisoBoomletMessage2),
    (0x2010, WithdrawalNisoBoomletMessage3, protocol::messages::withdrawal::from_niso::to_boomlet::WithdrawalNisoBoomletMessage3),
    (0x2011, WithdrawalNisoBoomletMessage4, protocol::messages::withdrawal::from_niso::to_boomlet::WithdrawalNisoBoomletMessage4),
    (0x2012, WithdrawalNisoBoomletMessage5, protocol::messages::withdrawal::from_niso::to_boomlet::WithdrawalNisoBoomletMessage5),
    (0x2013, WithdrawalNisoBoomletMessage6, protocol::messages::withdrawal::from_niso::to_boomlet::WithdrawalNisoBoomletMessage6),
    (0x2014, WithdrawalNisoBoomletMessage7, protocol::messages::withdrawal::from_niso::to_boomlet::WithdrawalNisoBoomletMessage7),
    (0x2015, WithdrawalNisoBoomletMessage8, protocol::messages::withdrawal::from_niso::to_boomlet::WithdrawalNisoBoomletMessage8),
    (0x2016, WithdrawalNisoBoomletMessage9, protocol::messages::withdrawal::from_niso::to_boomlet::WithdrawalNisoBoomletMessage9),
    (0x2017, WithdrawalNisoStMessage1, protocol::messages::withdrawal::from_niso::to_st::WithdrawalNisoStMessage1),
    (0x2018, WithdrawalNisoStMessage2, protocol::messages::withdrawal::from_niso::to_st::WithdrawalNisoStMessage2),
    (0x2019, WithdrawalNisoStMessage3, protocol::messages::withdrawal::from_niso::to_st::WithdrawalNisoStMessage3),
    (0x201A, WithdrawalNisoOutput1, protocol::messages::withdrawal::from_niso::to_user::WithdrawalNisoOutput1),
    (0x201B, WithdrawalNisoWtMessage1, protocol::messages::withdrawal::from_niso::to_wt::WithdrawalNisoWtMessage1),
    (0x201C, WithdrawalNisoWtMessage2, protocol::messages::withdrawal::from_niso::to_wt::WithdrawalNisoWtMessage2),
    (0x201D, WithdrawalNisoWtMessage3, protocol::messages::withdrawal::from_niso::to_wt::WithdrawalNisoWtMessage3),
    (0x201E, WithdrawalNisoWtMessage4, protocol::messages::withdrawal::from_niso::to_wt::WithdrawalNisoWtMessage4),
    (0x201F, WithdrawalNisoWtMessage5, protocol::messages::withdrawal::from_niso::to_wt::WithdrawalNisoWtMessage5),
    (0x2020, WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage1, protocol::messages::withdrawal::from_non_initiator_boomlet::to_non_initiator_niso::WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage1),
    (0x2021, WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage2, protocol::messages::withdrawal::from_non_initiator_boomlet::to_non_initiator_niso::WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage2),
    (0x2022, WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage3, protocol::messages::withdrawal::from_non_initiator_boomlet::to_non_initiator_niso::WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage3),
    (0x2023, WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage4, protocol::messages::withdrawal::from_non_initiator_boomlet::to_non_initiator_niso::WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage4),
    (0x2024, WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage5, protocol::messages::withdrawal::from_non_initiator_boomlet::to_non_initiator_niso::WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage5),
    (0x2025, WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage6, protocol::messages::withdrawal::from_non_initiator_boomlet::to_non_initiator_niso::WithdrawalNonInitiatorBoomletNonInitiatorNisoMessage6),
    (0x2026, WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage1, protocol::messages::withdrawal::from_non_initiator_niso::to_non_initiator_boomlet::WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage1),
    (0x2027, WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage2, protocol::messages::withdrawal::from_non_initiator_niso::to_non_initiator_boomlet::WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage2),
    (0x2028, WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage3, protocol::messages::withdrawal::from_non_initiator_niso::to_non_initiator_boomlet::WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage3),
    (0x2029, WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage4, protocol::messages::withdrawal::from_non_initiator_niso::to_non_initiator_boomlet::WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage4),
    (0x202A, WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage5, protocol::messages::withdrawal::from_non_initiator_niso::to_non_initiator_boomlet::WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage5),
    (0x202B, WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage6, protocol::messages::withdrawal::from_non_initiator_niso::to_non_initiator_boomlet::WithdrawalNonInitiatorNisoNonInitiatorBoomletMessage6),
    (0x202C, WithdrawalNonInitiatorNisoNonInitiatorStMessage1, protocol::messages::withdrawal::from_non_initiator_niso::to_non_initiator_st::WithdrawalNonInitiatorNisoNonInitiatorStMessage1),
    (0x202D, WithdrawalNonInitiatorNisoNonInitiatorStMessage2, protocol::messages::withdrawal::from_non_initiator_niso::to_non_initiator_st::WithdrawalNonInitiatorNisoNonInitiatorStMessage2),
    (0x202E, WithdrawalNonInitiatorNisoOutput1, protocol::messages::withdrawal::from_non_initiator_niso::to_user::WithdrawalNonInitiatorNisoOutput1),
    (0x202F, WithdrawalNonInitiatorNisoWtMessage1, protocol::messages::withdrawal::from_non_initiator_niso::to_wt::WithdrawalNonInitiatorNisoWtMessage1),
    (0x2030, WithdrawalNonInitiatorNisoWtMessage2, protocol::messages::withdrawal::from_non_initiator_niso::to_wt::WithdrawalNonInitiatorNisoWtMessage2),
    (0x2031, WithdrawalNonInitiatorNisoWtMessage3, protocol::messages::withdrawal::from_non_initiator_niso::to_wt::WithdrawalNonInitiatorNisoWtMessage3),
    (0x2032, WithdrawalNonInitiatorSarWtMessage1, protocol::messages::withdrawal::from_non_initiator_sar::to_wt::WithdrawalNonInitiatorSarWtMessage1),
    (0x2033, WithdrawalNonInitiatorStNonInitiatorNisoMessage1, protocol::messages::withdrawal::from_non_initiator_st::to_non_initiator_niso::WithdrawalNonInitiatorStNonInitiatorNisoMessage1),
    (0x2034, WithdrawalNonInitiatorStNonInitiatorNisoMessage2, protocol::messages::withdrawal::from_non_initiator_st::to_non_initiator_niso::WithdrawalNonInitiatorStNonInitiatorNisoMessage2),
    (0x2035, WithdrawalNonInitiatorStOutput1, protocol::messages::withdrawal::from_non_initiator_st::to_user::WithdrawalNonInitiatorStOutput1),
    (0x2036, WithdrawalNonInitiatorStOutput2, protocol::messages::withdrawal::from_non_initiator_st::to_user::WithdrawalNonInitiatorStOutput2),
    (0x2037, WithdrawalSarWtMessage1, protocol::messages::withdrawal::from_sar::to_wt::WithdrawalSarWtMessage1),
    (0x2038, WithdrawalSarWtMessage2, protocol::messages::withdrawal::from_sar::to_wt::WithdrawalSarWtMessage2),
    (0x2039, WithdrawalStNisoMessage1, protocol::messages::withdrawal::from_st::to_niso::WithdrawalStNisoMessage1),
    (0x203A, WithdrawalStNisoMessage2, protocol::messages::withdrawal::from_st::to_niso::WithdrawalStNisoMessage2),
    (0x203B, WithdrawalStNisoMessage3, protocol::messages::withdrawal::from_st::to_niso::WithdrawalStNisoMessage3),
    (0x203C, WithdrawalStOutput1, protocol::messages::withdrawal::from_st::to_user::WithdrawalStOutput1),
    (0x203D, WithdrawalStOutput2, protocol::messages::withdrawal::from_st::to_user::WithdrawalStOutput2),
    (0x203E, WithdrawalStOutput3, protocol::messages::withdrawal::from_st::to_user::WithdrawalStOutput3),
    (0x203F, WithdrawalIsoInput1, protocol::messages::withdrawal::from_user::to_iso::WithdrawalIsoInput1),
    (0x2040, WithdrawalNisoInput1, protocol::messages::withdrawal::from_user::to_niso::WithdrawalNisoInput1),
    (0x2041, WithdrawalNisoInput2, protocol::messages::withdrawal::from_user::to_niso::WithdrawalNisoInput2),
    (0x2042, WithdrawalNonInitiatorNisoInput1, protocol::messages::withdrawal::from_user::to_non_initiator_niso::WithdrawalNonInitiatorNisoInput1),
    (0x2043, WithdrawalNonInitiatorStInput1, protocol::messages::withdrawal::from_user::to_non_initiator_st::WithdrawalNonInitiatorStInput1),
    (0x2044, WithdrawalNonInitiatorStInput2, protocol::messages::withdrawal::from_user::to_non_initiator_st::WithdrawalNonInitiatorStInput2),
    (0x2045, WithdrawalStInput1, protocol::messages::withdrawal::from_user::to_st::WithdrawalStInput1),
    (0x2046, WithdrawalStInput2, protocol::messages::withdrawal::from_user::to_st::WithdrawalStInput2),
    (0x2047, WithdrawalStInput3, protocol::messages::withdrawal::from_user::to_st::WithdrawalStInput3),
    (0x2048, WithdrawalWtNisoMessage1, protocol::messages::withdrawal::from_wt::to_niso::WithdrawalWtNisoMessage1),
    (0x2049, WithdrawalWtNisoMessage2, protocol::messages::withdrawal::from_wt::to_niso::WithdrawalWtNisoMessage2),
    (0x204A, WithdrawalWtNisoMessage3, protocol::messages::withdrawal::from_wt::to_niso::WithdrawalWtNisoMessage3),
    (0x204B, WithdrawalWtNisoMessage4, protocol::messages::withdrawal::from_wt::to_niso::WithdrawalWtNisoMessage4),
    (0x204C, WithdrawalWtNonInitiatorNisoMessage1, protocol::messages::withdrawal::from_wt::to_non_initiator_niso::WithdrawalWtNonInitiatorNisoMessage1),
    (0x204D, WithdrawalWtNonInitiatorNisoMessage2, protocol::messages::withdrawal::from_wt::to_non_initiator_niso::WithdrawalWtNonInitiatorNisoMessage2),
    (0x204E, WithdrawalWtNonInitiatorNisoMessage3, protocol::messages::withdrawal::from_wt::to_non_initiator_niso::WithdrawalWtNonInitiatorNisoMessage3),
    (0x204F, WithdrawalWtNonInitiatorSarMessage1, protocol::messages::withdrawal::from_wt::to_non_initiator_sar::WithdrawalWtNonInitiatorSarMessage1),
    (0x2050, WithdrawalWtSarMessage1, protocol::messages::withdrawal::from_wt::to_sar::WithdrawalWtSarMessage1),
    (0x2051, WithdrawalWtSarMessage2, protocol::messages::withdrawal::from_wt::to_sar::WithdrawalWtSarMessage2),
    // 0x3000 - 0x30ff reserved for control/shared messages.
    (0x3000, TransportHello, crate::control::TransportHello),
    (0x3001, TransportReady, crate::control::TransportReady),
    (0x3002, TransportResetState, crate::control::TransportResetState),
    (0x3003, SetupNisoPeerNisoParcel1, crate::control::SetupNisoPeerNisoParcel1),
    (0x3004, SetupNisoPeerNisoParcel2, crate::control::SetupNisoPeerNisoParcel2),
    (0x3005, SetupNisoPeerNisoParcel3, crate::control::SetupNisoPeerNisoParcel3),
    (0x3006, SetupNisoPeerNisoParcel4, crate::control::SetupNisoPeerNisoParcel4),
    (0x3007, QueryNisoState, crate::control::QueryNisoState),
    (0x3008, NisoStateSnapshot, crate::control::NisoStateSnapshot),
}
