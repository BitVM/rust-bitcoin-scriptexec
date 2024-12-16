use bitcoin::opcodes::{all::*, OP_0, OP_FALSE, OP_NOP2, OP_NOP3, OP_TRUE};
use bitcoin::Opcode;

/// Parses a string into a Bitcoin script opcode
///
/// Accepts both the full opcode name (e.g. "OP_CHECKSIG") and the shorter version without the "OP_" prefix
/// (e.g. "CHECKSIG")
///
/// # Examples
///
/// ```
/// use bitcoin::opcodes::all::*;
/// # use bitcoin_scriptexec::parse_opcode;
///
/// assert_eq!(parse_opcode("OP_CHECKSIG").unwrap(), OP_CHECKSIG);
/// assert_eq!(parse_opcode("CHECKSIG").unwrap(), OP_CHECKSIG);
/// assert_eq!(parse_opcode("OP_1").unwrap(), OP_PUSHNUM_1);
/// assert!(parse_opcode("INVALID").is_err());
/// ```
/// Parses a string into a Bitcoin script [`Opcode`].
pub fn parse_opcode(s: &str) -> Result<Opcode, ()> {
    match s {
        // Special cases with aliases
        "OP_0" => Ok(OP_0),
        "OP_TRUE" | "TRUE" => Ok(OP_TRUE),
        "OP_FALSE" | "FALSE" => Ok(OP_FALSE),
        "OP_NOP2" | "NOP2" => Ok(OP_NOP2),
        "OP_NOP3" | "NOP3" => Ok(OP_NOP3),
        "OP_1" => Ok(OP_PUSHNUM_1),
        "OP_2" => Ok(OP_PUSHNUM_2),
        "OP_3" => Ok(OP_PUSHNUM_3),
        "OP_4" => Ok(OP_PUSHNUM_4),
        "OP_5" => Ok(OP_PUSHNUM_5),
        "OP_6" => Ok(OP_PUSHNUM_6),
        "OP_7" => Ok(OP_PUSHNUM_7),
        "OP_8" => Ok(OP_PUSHNUM_8),
        "OP_9" => Ok(OP_PUSHNUM_9),
        "OP_10" => Ok(OP_PUSHNUM_10),
        "OP_11" => Ok(OP_PUSHNUM_11),
        "OP_12" => Ok(OP_PUSHNUM_12),
        "OP_13" => Ok(OP_PUSHNUM_13),
        "OP_14" => Ok(OP_PUSHNUM_14),
        "OP_15" => Ok(OP_PUSHNUM_15),
        "OP_16" => Ok(OP_PUSHNUM_16),

        // Match both with and without OP_ prefix for all other opcodes
        s => {
            let opcode_name = if s.starts_with("OP_") {
                s
            } else {
                &format!("OP_{}", s)
            };

            match opcode_name {
                // PUSHBYTES variants
                "OP_PUSHBYTES_0" => Ok(OP_PUSHBYTES_0),
                "OP_PUSHBYTES_1" => Ok(OP_PUSHBYTES_1),
                "OP_PUSHBYTES_2" => Ok(OP_PUSHBYTES_2),
                "OP_PUSHBYTES_3" => Ok(OP_PUSHBYTES_3),
                "OP_PUSHBYTES_4" => Ok(OP_PUSHBYTES_4),
                "OP_PUSHBYTES_5" => Ok(OP_PUSHBYTES_5),
                "OP_PUSHBYTES_6" => Ok(OP_PUSHBYTES_6),
                "OP_PUSHBYTES_7" => Ok(OP_PUSHBYTES_7),
                "OP_PUSHBYTES_8" => Ok(OP_PUSHBYTES_8),
                "OP_PUSHBYTES_9" => Ok(OP_PUSHBYTES_9),
                "OP_PUSHBYTES_10" => Ok(OP_PUSHBYTES_10),
                "OP_PUSHBYTES_11" => Ok(OP_PUSHBYTES_11),
                "OP_PUSHBYTES_12" => Ok(OP_PUSHBYTES_12),
                "OP_PUSHBYTES_13" => Ok(OP_PUSHBYTES_13),
                "OP_PUSHBYTES_14" => Ok(OP_PUSHBYTES_14),
                "OP_PUSHBYTES_15" => Ok(OP_PUSHBYTES_15),
                "OP_PUSHBYTES_16" => Ok(OP_PUSHBYTES_16),
                "OP_PUSHBYTES_17" => Ok(OP_PUSHBYTES_17),
                "OP_PUSHBYTES_18" => Ok(OP_PUSHBYTES_18),
                "OP_PUSHBYTES_19" => Ok(OP_PUSHBYTES_19),
                "OP_PUSHBYTES_20" => Ok(OP_PUSHBYTES_20),
                "OP_PUSHBYTES_21" => Ok(OP_PUSHBYTES_21),
                "OP_PUSHBYTES_22" => Ok(OP_PUSHBYTES_22),
                "OP_PUSHBYTES_23" => Ok(OP_PUSHBYTES_23),
                "OP_PUSHBYTES_24" => Ok(OP_PUSHBYTES_24),
                "OP_PUSHBYTES_25" => Ok(OP_PUSHBYTES_25),
                "OP_PUSHBYTES_26" => Ok(OP_PUSHBYTES_26),
                "OP_PUSHBYTES_27" => Ok(OP_PUSHBYTES_27),
                "OP_PUSHBYTES_28" => Ok(OP_PUSHBYTES_28),
                "OP_PUSHBYTES_29" => Ok(OP_PUSHBYTES_29),
                "OP_PUSHBYTES_30" => Ok(OP_PUSHBYTES_30),
                "OP_PUSHBYTES_31" => Ok(OP_PUSHBYTES_31),
                "OP_PUSHBYTES_32" => Ok(OP_PUSHBYTES_32),
                "OP_PUSHBYTES_33" => Ok(OP_PUSHBYTES_33),
                "OP_PUSHBYTES_34" => Ok(OP_PUSHBYTES_34),
                "OP_PUSHBYTES_35" => Ok(OP_PUSHBYTES_35),
                "OP_PUSHBYTES_36" => Ok(OP_PUSHBYTES_36),
                "OP_PUSHBYTES_37" => Ok(OP_PUSHBYTES_37),
                "OP_PUSHBYTES_38" => Ok(OP_PUSHBYTES_38),
                "OP_PUSHBYTES_39" => Ok(OP_PUSHBYTES_39),
                "OP_PUSHBYTES_40" => Ok(OP_PUSHBYTES_40),
                "OP_PUSHBYTES_41" => Ok(OP_PUSHBYTES_41),
                "OP_PUSHBYTES_42" => Ok(OP_PUSHBYTES_42),
                "OP_PUSHBYTES_43" => Ok(OP_PUSHBYTES_43),
                "OP_PUSHBYTES_44" => Ok(OP_PUSHBYTES_44),
                "OP_PUSHBYTES_45" => Ok(OP_PUSHBYTES_45),
                "OP_PUSHBYTES_46" => Ok(OP_PUSHBYTES_46),
                "OP_PUSHBYTES_47" => Ok(OP_PUSHBYTES_47),
                "OP_PUSHBYTES_48" => Ok(OP_PUSHBYTES_48),
                "OP_PUSHBYTES_49" => Ok(OP_PUSHBYTES_49),
                "OP_PUSHBYTES_50" => Ok(OP_PUSHBYTES_50),
                "OP_PUSHBYTES_51" => Ok(OP_PUSHBYTES_51),
                "OP_PUSHBYTES_52" => Ok(OP_PUSHBYTES_52),
                "OP_PUSHBYTES_53" => Ok(OP_PUSHBYTES_53),
                "OP_PUSHBYTES_54" => Ok(OP_PUSHBYTES_54),
                "OP_PUSHBYTES_55" => Ok(OP_PUSHBYTES_55),
                "OP_PUSHBYTES_56" => Ok(OP_PUSHBYTES_56),
                "OP_PUSHBYTES_57" => Ok(OP_PUSHBYTES_57),
                "OP_PUSHBYTES_58" => Ok(OP_PUSHBYTES_58),
                "OP_PUSHBYTES_59" => Ok(OP_PUSHBYTES_59),
                "OP_PUSHBYTES_60" => Ok(OP_PUSHBYTES_60),
                "OP_PUSHBYTES_61" => Ok(OP_PUSHBYTES_61),
                "OP_PUSHBYTES_62" => Ok(OP_PUSHBYTES_62),
                "OP_PUSHBYTES_63" => Ok(OP_PUSHBYTES_63),
                "OP_PUSHBYTES_64" => Ok(OP_PUSHBYTES_64),
                "OP_PUSHBYTES_65" => Ok(OP_PUSHBYTES_65),
                "OP_PUSHBYTES_66" => Ok(OP_PUSHBYTES_66),
                "OP_PUSHBYTES_67" => Ok(OP_PUSHBYTES_67),
                "OP_PUSHBYTES_68" => Ok(OP_PUSHBYTES_68),
                "OP_PUSHBYTES_69" => Ok(OP_PUSHBYTES_69),
                "OP_PUSHBYTES_70" => Ok(OP_PUSHBYTES_70),
                "OP_PUSHBYTES_71" => Ok(OP_PUSHBYTES_71),
                "OP_PUSHBYTES_72" => Ok(OP_PUSHBYTES_72),
                "OP_PUSHBYTES_73" => Ok(OP_PUSHBYTES_73),
                "OP_PUSHBYTES_74" => Ok(OP_PUSHBYTES_74),
                "OP_PUSHBYTES_75" => Ok(OP_PUSHBYTES_75),

                // Regular opcodes
                "OP_PUSHDATA1" => Ok(OP_PUSHDATA1),
                "OP_PUSHDATA2" => Ok(OP_PUSHDATA2),
                "OP_PUSHDATA4" => Ok(OP_PUSHDATA4),
                "OP_PUSHNUM_NEG1" => Ok(OP_PUSHNUM_NEG1),
                "OP_RESERVED" => Ok(OP_RESERVED),
                "OP_NOP" => Ok(OP_NOP),
                "OP_VER" => Ok(OP_VER),
                "OP_IF" => Ok(OP_IF),
                "OP_NOTIF" => Ok(OP_NOTIF),
                "OP_VERIF" => Ok(OP_VERIF),
                "OP_VERNOTIF" => Ok(OP_VERNOTIF),
                "OP_ELSE" => Ok(OP_ELSE),
                "OP_ENDIF" => Ok(OP_ENDIF),
                "OP_VERIFY" => Ok(OP_VERIFY),
                "OP_RETURN" => Ok(OP_RETURN),
                "OP_TOALTSTACK" => Ok(OP_TOALTSTACK),
                "OP_FROMALTSTACK" => Ok(OP_FROMALTSTACK),
                "OP_2DROP" => Ok(OP_2DROP),
                "OP_2DUP" => Ok(OP_2DUP),
                "OP_3DUP" => Ok(OP_3DUP),
                "OP_2OVER" => Ok(OP_2OVER),
                "OP_2ROT" => Ok(OP_2ROT),
                "OP_2SWAP" => Ok(OP_2SWAP),
                "OP_IFDUP" => Ok(OP_IFDUP),
                "OP_DEPTH" => Ok(OP_DEPTH),
                "OP_DROP" => Ok(OP_DROP),
                "OP_DUP" => Ok(OP_DUP),
                "OP_NIP" => Ok(OP_NIP),
                "OP_OVER" => Ok(OP_OVER),
                "OP_PICK" => Ok(OP_PICK),
                "OP_ROLL" => Ok(OP_ROLL),
                "OP_ROT" => Ok(OP_ROT),
                "OP_SWAP" => Ok(OP_SWAP),
                "OP_TUCK" => Ok(OP_TUCK),
                "OP_CAT" => Ok(OP_CAT),
                "OP_SUBSTR" => Ok(OP_SUBSTR),
                "OP_LEFT" => Ok(OP_LEFT),
                "OP_RIGHT" => Ok(OP_RIGHT),
                "OP_SIZE" => Ok(OP_SIZE),
                "OP_INVERT" => Ok(OP_INVERT),
                "OP_AND" => Ok(OP_AND),
                "OP_OR" => Ok(OP_OR),
                "OP_XOR" => Ok(OP_XOR),
                "OP_EQUAL" => Ok(OP_EQUAL),
                "OP_EQUALVERIFY" => Ok(OP_EQUALVERIFY),
                "OP_RESERVED1" => Ok(OP_RESERVED1),
                "OP_RESERVED2" => Ok(OP_RESERVED2),
                "OP_1ADD" => Ok(OP_1ADD),
                "OP_1SUB" => Ok(OP_1SUB),
                "OP_2MUL" => Ok(OP_2MUL),
                "OP_2DIV" => Ok(OP_2DIV),
                "OP_NEGATE" => Ok(OP_NEGATE),
                "OP_ABS" => Ok(OP_ABS),
                "OP_NOT" => Ok(OP_NOT),
                "OP_0NOTEQUAL" => Ok(OP_0NOTEQUAL),
                "OP_ADD" => Ok(OP_ADD),
                "OP_SUB" => Ok(OP_SUB),
                "OP_MUL" => Ok(OP_MUL),
                "OP_DIV" => Ok(OP_DIV),
                "OP_MOD" => Ok(OP_MOD),
                "OP_LSHIFT" => Ok(OP_LSHIFT),
                "OP_RSHIFT" => Ok(OP_RSHIFT),
                "OP_BOOLAND" => Ok(OP_BOOLAND),
                "OP_BOOLOR" => Ok(OP_BOOLOR),
                "OP_NUMEQUAL" => Ok(OP_NUMEQUAL),
                "OP_NUMEQUALVERIFY" => Ok(OP_NUMEQUALVERIFY),
                "OP_NUMNOTEQUAL" => Ok(OP_NUMNOTEQUAL),
                "OP_LESSTHAN" => Ok(OP_LESSTHAN),
                "OP_GREATERTHAN" => Ok(OP_GREATERTHAN),
                "OP_LESSTHANOREQUAL" => Ok(OP_LESSTHANOREQUAL),
                "OP_GREATERTHANOREQUAL" => Ok(OP_GREATERTHANOREQUAL),
                "OP_MIN" => Ok(OP_MIN),
                "OP_MAX" => Ok(OP_MAX),
                "OP_WITHIN" => Ok(OP_WITHIN),
                "OP_RIPEMD160" => Ok(OP_RIPEMD160),
                "OP_SHA1" => Ok(OP_SHA1),
                "OP_SHA256" => Ok(OP_SHA256),
                "OP_HASH160" => Ok(OP_HASH160),
                "OP_HASH256" => Ok(OP_HASH256),
                "OP_CODESEPARATOR" => Ok(OP_CODESEPARATOR),
                "OP_CHECKSIG" => Ok(OP_CHECKSIG),
                "OP_CHECKSIGVERIFY" => Ok(OP_CHECKSIGVERIFY),
                "OP_CHECKMULTISIG" => Ok(OP_CHECKMULTISIG),
                "OP_CHECKMULTISIGVERIFY" => Ok(OP_CHECKMULTISIGVERIFY),
                "OP_NOP1" => Ok(OP_NOP1),
                "OP_CLTV" => Ok(OP_CLTV),
                "OP_CSV" => Ok(OP_CSV),
                "OP_NOP4" => Ok(OP_NOP4),
                "OP_NOP5" => Ok(OP_NOP5),
                "OP_NOP6" => Ok(OP_NOP6),
                "OP_NOP7" => Ok(OP_NOP7),
                "OP_NOP8" => Ok(OP_NOP8),
                "OP_NOP9" => Ok(OP_NOP9),
                "OP_NOP10" => Ok(OP_NOP10),
                "OP_CHECKSIGADD" => Ok(OP_CHECKSIGADD),

                // RETURN variants
                "OP_RETURN_187" => Ok(OP_RETURN_187),
                "OP_RETURN_188" => Ok(OP_RETURN_188),
                "OP_RETURN_189" => Ok(OP_RETURN_189),
                "OP_RETURN_190" => Ok(OP_RETURN_190),
                "OP_RETURN_191" => Ok(OP_RETURN_191),
                "OP_RETURN_192" => Ok(OP_RETURN_192),
                "OP_RETURN_193" => Ok(OP_RETURN_193),
                "OP_RETURN_194" => Ok(OP_RETURN_194),
                "OP_RETURN_195" => Ok(OP_RETURN_195),
                "OP_RETURN_196" => Ok(OP_RETURN_196),
                "OP_RETURN_197" => Ok(OP_RETURN_197),
                "OP_RETURN_198" => Ok(OP_RETURN_198),
                "OP_RETURN_199" => Ok(OP_RETURN_199),
                "OP_RETURN_200" => Ok(OP_RETURN_200),
                "OP_RETURN_201" => Ok(OP_RETURN_201),
                "OP_RETURN_202" => Ok(OP_RETURN_202),
                "OP_RETURN_203" => Ok(OP_RETURN_203),
                "OP_RETURN_204" => Ok(OP_RETURN_204),
                "OP_RETURN_205" => Ok(OP_RETURN_205),
                "OP_RETURN_206" => Ok(OP_RETURN_206),
                "OP_RETURN_207" => Ok(OP_RETURN_207),
                "OP_RETURN_208" => Ok(OP_RETURN_208),
                "OP_RETURN_209" => Ok(OP_RETURN_209),
                "OP_RETURN_210" => Ok(OP_RETURN_210),
                "OP_RETURN_211" => Ok(OP_RETURN_211),
                "OP_RETURN_212" => Ok(OP_RETURN_212),
                "OP_RETURN_213" => Ok(OP_RETURN_213),
                "OP_RETURN_214" => Ok(OP_RETURN_214),
                "OP_RETURN_215" => Ok(OP_RETURN_215),
                "OP_RETURN_216" => Ok(OP_RETURN_216),
                "OP_RETURN_217" => Ok(OP_RETURN_217),
                "OP_RETURN_218" => Ok(OP_RETURN_218),
                "OP_RETURN_219" => Ok(OP_RETURN_219),
                "OP_RETURN_220" => Ok(OP_RETURN_220),
                "OP_RETURN_221" => Ok(OP_RETURN_221),
                "OP_RETURN_222" => Ok(OP_RETURN_222),
                "OP_RETURN_223" => Ok(OP_RETURN_223),
                "OP_RETURN_224" => Ok(OP_RETURN_224),
                "OP_RETURN_225" => Ok(OP_RETURN_225),
                "OP_RETURN_226" => Ok(OP_RETURN_226),
                "OP_RETURN_227" => Ok(OP_RETURN_227),
                "OP_RETURN_228" => Ok(OP_RETURN_228),
                "OP_RETURN_229" => Ok(OP_RETURN_229),
                "OP_RETURN_230" => Ok(OP_RETURN_230),
                "OP_RETURN_231" => Ok(OP_RETURN_231),
                "OP_RETURN_232" => Ok(OP_RETURN_232),
                "OP_RETURN_233" => Ok(OP_RETURN_233),
                "OP_RETURN_234" => Ok(OP_RETURN_234),
                "OP_RETURN_235" => Ok(OP_RETURN_235),
                "OP_RETURN_236" => Ok(OP_RETURN_236),
                "OP_RETURN_237" => Ok(OP_RETURN_237),
                "OP_RETURN_238" => Ok(OP_RETURN_238),
                "OP_RETURN_239" => Ok(OP_RETURN_239),
                "OP_RETURN_240" => Ok(OP_RETURN_240),
                "OP_RETURN_241" => Ok(OP_RETURN_241),
                "OP_RETURN_242" => Ok(OP_RETURN_242),
                "OP_RETURN_243" => Ok(OP_RETURN_243),
                "OP_RETURN_244" => Ok(OP_RETURN_244),
                "OP_RETURN_245" => Ok(OP_RETURN_245),
                "OP_RETURN_246" => Ok(OP_RETURN_246),
                "OP_RETURN_247" => Ok(OP_RETURN_247),
                "OP_RETURN_248" => Ok(OP_RETURN_248),
                "OP_RETURN_249" => Ok(OP_RETURN_249),
                "OP_RETURN_250" => Ok(OP_RETURN_250),
                "OP_RETURN_251" => Ok(OP_RETURN_251),
                "OP_RETURN_252" => Ok(OP_RETURN_252),
                "OP_RETURN_253" => Ok(OP_RETURN_253),
                "OP_RETURN_254" => Ok(OP_RETURN_254),
                "OP_INVALIDOPCODE" => Ok(OP_INVALIDOPCODE),

                _ => Err(()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_opcodes() {
        assert_eq!(parse_opcode("OP_0").unwrap(), OP_0);
        assert_eq!(parse_opcode("OP_FALSE").unwrap(), OP_FALSE);
        assert_eq!(parse_opcode("FALSE").unwrap(), OP_FALSE);
        assert_eq!(parse_opcode("OP_TRUE").unwrap(), OP_TRUE);
        assert_eq!(parse_opcode("TRUE").unwrap(), OP_TRUE);
    }

    #[test]
    fn test_numeric_opcodes() {
        assert_eq!(parse_opcode("OP_1").unwrap(), OP_PUSHNUM_1);
        assert_eq!(parse_opcode("OP_2").unwrap(), OP_PUSHNUM_2);
        assert_eq!(parse_opcode("OP_3").unwrap(), OP_PUSHNUM_3);
        assert_eq!(parse_opcode("OP_16").unwrap(), OP_PUSHNUM_16);
    }

    #[test]
    fn test_pushbytes() {
        assert_eq!(parse_opcode("OP_PUSHBYTES_0").unwrap(), OP_PUSHBYTES_0);
        assert_eq!(parse_opcode("OP_PUSHBYTES_1").unwrap(), OP_PUSHBYTES_1);
        assert_eq!(parse_opcode("OP_PUSHBYTES_75").unwrap(), OP_PUSHBYTES_75);
    }

    #[test]
    fn test_conditional_opcodes() {
        assert_eq!(parse_opcode("OP_IF").unwrap(), OP_IF);
        assert_eq!(parse_opcode("OP_NOTIF").unwrap(), OP_NOTIF);
        assert_eq!(parse_opcode("OP_ELSE").unwrap(), OP_ELSE);
        assert_eq!(parse_opcode("OP_ENDIF").unwrap(), OP_ENDIF);
    }

    #[test]
    fn test_stack_opcodes() {
        assert_eq!(parse_opcode("OP_DUP").unwrap(), OP_DUP);
        assert_eq!(parse_opcode("OP_DROP").unwrap(), OP_DROP);
        assert_eq!(parse_opcode("OP_SWAP").unwrap(), OP_SWAP);
        assert_eq!(parse_opcode("OP_RETURN").unwrap(), OP_RETURN);
    }

    #[test]
    fn test_alt_names() {
        assert_eq!(parse_opcode("DUP").unwrap(), OP_DUP);
        assert_eq!(parse_opcode("DROP").unwrap(), OP_DROP);
        assert_eq!(parse_opcode("SWAP").unwrap(), OP_SWAP);
    }

    #[test]
    fn test_invalid_opcodes() {
        assert!(parse_opcode("OP_INVALID").is_err());
        assert!(parse_opcode("INVALID").is_err());
        assert!(parse_opcode("").is_err());
    }
}
