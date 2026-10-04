use hex;
use jni::objects::{GlobalRef, JByteArray, JClass, JObject, JString, JValue};
use jni::{JNIEnv, JavaVM};
use log::LevelFilter;
use log::{info, trace};
use log4rs;
use log4rs::{
    append::console::ConsoleAppender,
    config::{Appender, Root},
};
use openssl::rsa::{Padding, Rsa};
use openssl::symm::{Cipher, Crypter, Mode};
use serde::Deserialize;
use std::error;
use std::fs::{self};
use std::panic;
use std::sync::{Mutex, Once, OnceLock};

use emvpt::*;

static JVM: OnceLock<JavaVM> = OnceLock::new();
static CALLBACK: Mutex<Option<GlobalRef>> = Mutex::new(None);
static APDU_RESPONSE: Mutex<Vec<u8>> = Mutex::new(Vec::new());
// Commands sent to the card, to check the command order and data of a transaction
static SENT_COMMANDS: Mutex<Vec<Vec<u8>>> = Mutex::new(Vec::new());

#[no_mangle]
pub extern "system" fn Java_emvcardsimulator_SimulatorTest_sendApduResponse(
    env: JNIEnv,
    _class: JClass,
    response_apdu: JByteArray,
) {
    set_apdu_response(env, response_apdu);
}

#[no_mangle]
pub extern "system" fn Java_emvcardsimulator_PrivateCardTest_sendApduResponse(
    env: JNIEnv,
    _class: JClass,
    response_apdu: JByteArray,
) {
    set_apdu_response(env, response_apdu);
}

fn set_apdu_response(env: JNIEnv, response_apdu: JByteArray) {
    let mut apdu_response = APDU_RESPONSE.lock().unwrap();
    apdu_response.clear();
    apdu_response.extend_from_slice(&env.convert_byte_array(&response_apdu).unwrap()[..]);
    trace!("RESPONSE: {:02X?}", apdu_response);
}

struct JavaSmartCardConnection {}

impl ApduInterface for JavaSmartCardConnection {
    fn send_apdu(&self, apdu: &[u8]) -> Result<Vec<u8>, ()> {
        trace!("CALLING {:02X?}", apdu);
        SENT_COMMANDS.lock().unwrap().push(apdu.to_vec());

        let mut env = JVM.get().unwrap().get_env().unwrap();
        // Clone the reference so the lock is not held during the Java callback
        let callback = CALLBACK.lock().unwrap().clone().unwrap();

        let request_apdu = env.byte_array_from_slice(apdu).unwrap();
        env.call_method(
            &callback,
            "sendApduRequest",
            "([B)V",
            &[JValue::Object(&request_apdu)],
        )
        .unwrap();

        let output = APDU_RESPONSE.lock().unwrap().clone();

        Ok(output)
    }
}

static LOGGING: Once = Once::new();

fn init_logging() -> Result<(), Box<dyn error::Error>> {
    let stdout: ConsoleAppender = ConsoleAppender::builder().build();
    let config = log4rs::config::Config::builder()
        .appender(Appender::builder().build("stdout", Box::new(stdout)))
        .build(Root::builder().appender("stdout").build(LevelFilter::Debug));

    if let Err(e) = log4rs::init_config(config.unwrap()) {
        return Err(Box::new(e));
    }

    Ok(())
}

// Disables logging for as long as the guard is alive
struct LoggingSuppressed {
    previous_level: LevelFilter,
}

impl LoggingSuppressed {
    fn new() -> Self {
        let previous_level = log::max_level();
        log::set_max_level(LevelFilter::Off);
        LoggingSuppressed { previous_level }
    }
}

impl Drop for LoggingSuppressed {
    fn drop(&mut self) {
        log::set_max_level(self.previous_level);
    }
}

// APDU script entry, see lib/src/main/java/emvcardsimulator/api/ApduScript.java
#[derive(Deserialize, Clone)]
struct ApduRequestResponse {
    // Empty in a card_information entry, which describes the card and is not sent to the card
    #[serde(default)]
    req: String,
    #[serde(default)]
    res: String,
}

impl ApduRequestResponse {
    fn to_raw_vec(s: &String) -> Vec<u8> {
        hex::decode(s.replace(" ", "")).unwrap()
    }

    fn execute_setup_apdus(connection: &mut EmvConnection, setup_file: &str) -> Result<(), String> {
        // Setup the app ICC data
        let card_setup_data: Vec<ApduRequestResponse> =
            serde_yaml::from_str(&fs::read_to_string(setup_file).unwrap()).unwrap();

        // Personalization APDUs carry keys and other sensitive card data, keep them out of the logs
        let _logging_suppressed = LoggingSuppressed::new();

        for apdu in card_setup_data.into_iter().filter(|apdu| !apdu.req.is_empty()) {
            let request = ApduRequestResponse::to_raw_vec(&apdu.req);
            let response = ApduRequestResponse::to_raw_vec(&apdu.res);

            let (response_trailer, _) = connection.send_apdu(&request);
            if &response_trailer[..] != &response[..] {
                return Err(format!(
                    "Response not what expected! setup_file:{}, expected:{:02X?}, actual:{:02X?}",
                    setup_file,
                    &response[..],
                    &response_trailer[..]
                ));
            }
        }

        Ok(())
    }
}

// ICC Application Cryptogram Master Key MK_AC personalized in card_setup_app_apdus.yaml
const AC_MASTER_KEY: &str = "0123456789ABCDEFFEDCBA9876543210";
// Authorisation Response Codes of the issuer, approved in the settings.yaml of the tests: '00' approved and '05' do not honour (ISO 8583)
const AUTHORISATION_RESPONSE_CODE: &[u8] = b"00";
const AUTHORISATION_RESPONSE_CODE_DECLINED: &[u8] = b"05";
// Unable to go online, offline approved (EMV Book 4, A6)
const AUTHORISATION_RESPONSE_CODE_UNABLE_TO_GO_ONLINE: &[u8] = b"Y3";

fn triple_des_encrypt(double_length_key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut key = double_length_key.to_vec();
    key.extend_from_slice(&double_length_key[0..8]);

    let mut crypter = Crypter::new(Cipher::des_ede3(), Mode::Encrypt, &key, None).unwrap();
    crypter.pad(false);

    let mut output = vec![0; data.len() + 8];
    let mut length = crypter.update(data, &mut output).unwrap();
    length += crypter.finalize(&mut output[length..]).unwrap();
    output.truncate(length);
    output
}

/// Application Cryptogram Session Key, EMV Book 2 A1.3.1 Common Session Key Derivation Option
fn application_cryptogram_session_key(master_key: &[u8], atc: &[u8]) -> Vec<u8> {

    let mut diversification = vec![0u8; 16];
    diversification[0..2].copy_from_slice(atc);
    diversification[2] = 0xF0;
    diversification[8..10].copy_from_slice(atc);
    diversification[10] = 0x0F;
    triple_des_encrypt(master_key, &diversification)
}

/// ISO/IEC 9797-1 MAC Algorithm 3 with padding method 2, EMV Book 2 A1.2.1
fn retail_mac(double_length_key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut padded = data.to_vec();
    padded.push(0x80);
    while padded.len() % 8 != 0 {
        padded.push(0x00);
    }

    // Single DES with the left key half, the last block with the whole key: DES(KL, DES-1(KR, DES(KL, block)))
    let single_length_key = [&double_length_key[0..8], &double_length_key[0..8]].concat();
    let block_count = padded.len() / 8;
    let mut block = vec![0u8; 8];
    for (i, data_block) in padded.chunks(8).enumerate() {
        for (b, d) in block.iter_mut().zip(data_block) {
            *b ^= d;
        }

        if i + 1 < block_count {
            block = triple_des_encrypt(&single_length_key, &block);
        } else {
            block = triple_des_encrypt(double_length_key, &block);
        }
    }
    block
}

/// Issuer Authentication Data (tag 91) with ARPC Method 1 as the issuer would generate it.
/// EMV Book 2, A1.3.1 session key derivation and 8.2.1 ARPC Method 1: ARPC || ARC
fn issuer_authentication_data(
    master_key: &[u8],
    arqc: &[u8],
    atc: &[u8],
    authorisation_response_code: &[u8],
) -> Vec<u8> {
    let session_key = application_cryptogram_session_key(master_key, atc);

    let mut y = arqc.to_vec();
    y[0] ^= authorisation_response_code[0];
    y[1] ^= authorisation_response_code[1];

    let mut result = triple_des_encrypt(&session_key, &y);
    result.extend_from_slice(authorisation_response_code);
    result
}

/// Issuer Authentication Data (tag 91) with ARPC Method 2 as the issuer would generate it.
/// EMV Book 2, A1.3.1 session key derivation and 8.2.2 ARPC Method 2: ARPC (4) || CSU (4), without Proprietary Authentication Data
fn issuer_authentication_data_method_2(
    master_key: &[u8],
    arqc: &[u8],
    atc: &[u8],
    card_status_update: &[u8],
) -> Vec<u8> {
    let session_key = application_cryptogram_session_key(master_key, atc);

    let mut data = arqc.to_vec();
    data.extend_from_slice(card_status_update);

    let mut result = retail_mac(&session_key, &data)[0..4].to_vec();
    result.extend_from_slice(card_status_update);
    result
}

/// Values of the data objects in a Data Object List (e.g. CDOL1 related data) from the terminal tags
fn data_object_list_data(connection: &EmvConnection, dol_tag: &str) -> Vec<u8> {
    let dol = connection.get_tag_value(dol_tag).unwrap();
    DataObjectList::process_data_object_list(connection, &dol[..])
        .unwrap()
        .get_tag_list_tag_values(connection)
}

// Cryptogram Version Numbers and their offset in the Issuer Application Data
const VISA_CRYPTOGRAM_VERSION_18: (u8, usize) = (0x12, 2);
const MASTERCARD_CRYPTOGRAM_VERSION_14: (u8, usize) = (0x14, 1);

/// Issuer verification of the Authorisation Request Cryptogram (9F26) the ICC generated with MK_AC
/// over CDOL1 related data || AIP || ATC || Issuer Application Data
fn verify_authorisation_request_cryptogram(
    connection: &EmvConnection,
    master_key: &[u8],
    cdol1_data: &[u8],
    cryptogram_version: (u8, usize),
) {
    let aip = connection.get_tag_value("82").unwrap();
    let atc = connection.get_tag_value("9F36").unwrap();
    let issuer_application_data = connection.get_tag_value("9F10").unwrap();
    let (version, offset) = cryptogram_version;
    assert_eq!(
        issuer_application_data[offset], version,
        "Cryptogram Version Number in Issuer Application Data"
    );

    let mut data = cdol1_data.to_vec();
    data.extend_from_slice(aip);
    data.extend_from_slice(atc);
    data.extend_from_slice(issuer_application_data);
    let expected_arqc = retail_mac(&application_cryptogram_session_key(master_key, atc), &data);

    assert_eq!(
        connection.get_tag_value("9F26").unwrap(),
        &expected_arqc,
        "ARQC does not match the issuer calculated one"
    );
}

fn pin_entry() -> Result<String, ()> {
    Ok("1234".to_string())
}

fn start_transaction(connection: &mut EmvConnection) -> Result<(), ()> {
    // force transaction date as 24.07.2020
    connection.add_tag("9A", b"\x20\x07\x24".to_vec());

    // force unpreditable number
    connection.add_tag("9F37", b"\x01\x23\x45\x67".to_vec());
    connection.settings.terminal.use_random = false;

    // transaction amount 0,01 EUR
    connection.add_tag("9F02", b"\x00\x00\x00\x00\x00\x01".to_vec());

    Ok(())
}

fn setup_connection(connection: &mut EmvConnection) -> Result<(), ()> {
    connection.contactless = false;
    connection.pse_application_select_callback = None;
    connection.pin_callback = Some(&pin_entry);
    connection.amount_callback = None;
    connection.start_transaction_callback = Some(&start_transaction);

    Ok(())
}

fn execute_setup_apdus(connection: &mut EmvConnection, setup_files: &[&str]) {
    for setup_file in setup_files {
        ApduRequestResponse::execute_setup_apdus(connection, setup_file).unwrap();
    }
}

/// Select the only application of the (P)PSE, personalize the application and select it
fn select_application(
    connection: &mut EmvConnection,
    kernel_identifier: Option<u8>,
    app_setup_files: &[&str],
) -> EmvApplication {
    let applications = connection
        .handle_select_payment_system_environment()
        .unwrap();

    // Directory Entry of the PPSE, EMV Contactless Book B, Table 3-3
    if let Some(kernel_identifier) = kernel_identifier {
        assert_eq!(
            connection.get_tag_value("9F2A").unwrap(),
            &vec![kernel_identifier],
            "Kernel Identifier"
        );
    }

    execute_setup_apdus(connection, app_setup_files);

    let application = applications[0].clone();
    connection
        .handle_select_payment_application(&application)
        .unwrap();

    application
}

/// Contact transaction: DDA, enciphered offline PIN and online authorisation. The terminal completes the transaction with the
/// second GENERATE AC requesting a TC or an AAC by the Authorisation Response Code (EMV Book 4, 6.3.8 and 12.2.1), the issuer
/// response has Issuer Authentication Data for EXTERNAL AUTHENTICATE unless the terminal was unable to go online.
fn contact_transaction_with(
    connection: &mut EmvConnection,
    authorisation_response_code: &[u8],
    final_cryptogram_type: CryptogramType,
) {
    setup_connection(connection).unwrap();

    // Setup the PSE ICC data
    execute_setup_apdus(connection, &["../config/card_setup_pse_apdus.yaml"]);

    let application =
        select_application(connection, None, &["../config/card_setup_app_apdus.yaml"]);

    connection.start_transaction(&application).unwrap();

    connection.process_settings().unwrap();

    let search_tag = b"\x9f\x36";
    connection.handle_get_data(&search_tag[..]).unwrap();

    connection.handle_card_verification_methods().unwrap();

    connection.handle_terminal_risk_management().unwrap();

    connection.handle_offline_data_authentication().unwrap();

    connection.handle_terminal_action_analysis().unwrap();

    assert!(matches!(
        connection.handle_1st_generate_ac().unwrap(),
        CryptogramType::AuthorisationRequestCryptogram
    ));

    connection.add_tag("8A", authorisation_response_code.to_vec());
    if authorisation_response_code != AUTHORISATION_RESPONSE_CODE_UNABLE_TO_GO_ONLINE {
        // Online authorisation response from the issuer
        let arqc = connection.get_tag_value("9F26").unwrap().clone();
        let atc = connection.get_tag_value("9F36").unwrap().clone();
        connection.add_tag(
            "91",
            issuer_authentication_data(
                &hex::decode(AC_MASTER_KEY).unwrap(),
                &arqc,
                &atc,
                authorisation_response_code,
            ),
        );

        connection.handle_issuer_authentication_data().unwrap();
        assert!(
            !connection
                .settings
                .terminal
                .tvr
                .issuer_authentication_failed
        );
    }

    let cryptogram_type = connection.handle_2nd_generate_ac().unwrap();
    assert_eq!(
        cryptogram_type as u8, final_cryptogram_type as u8,
        "Cryptogram type of the second GENERATE AC"
    );

    // Consume logs that the card gathered
    execute_setup_apdus(connection, &["../config/card_log_consume_apdus.yaml"]);
    assert!(consume_logs(connection) > 0, "Card log entries");
}

/// Contact transaction approved online
fn contact_transaction(connection: &mut EmvConnection) {
    contact_transaction_with(
        connection,
        AUTHORISATION_RESPONSE_CODE,
        CryptogramType::TransactionCertificate,
    );
}

/// Contact transaction declined online, the terminal requests an AAC in the second GENERATE AC
fn contact_declined_transaction(connection: &mut EmvConnection) {
    contact_transaction_with(
        connection,
        AUTHORISATION_RESPONSE_CODE_DECLINED,
        CryptogramType::ApplicationAuthenticationCryptogram,
    );
}

/// Contact transaction where the terminal is unable to go online and approves offline, the card approves with a TC
fn contact_unable_to_go_online_transaction(connection: &mut EmvConnection) {
    contact_transaction_with(
        connection,
        AUTHORISATION_RESPONSE_CODE_UNABLE_TO_GO_ONLINE,
        CryptogramType::TransactionCertificate,
    );
}

// Default maximum number of the card log entries
const MAX_LOG_ENTRIES: usize = 10;

/// Consume the card log entries until 'Record not found', returns the number of entries. The number depends on the
/// transport protocol: with T=0 the log has also the '61xx' and GET RESPONSE exchanges.
fn consume_logs(connection: &mut EmvConnection) -> usize {
    let mut entries = 0;
    loop {
        let (response_trailer, _) = connection.send_apdu(b"\x80\x06\x00\x00\x00");
        if response_trailer[..] == b"\x6A\x83"[..] {
            return entries;
        }
        assert_eq!(&response_trailer[..], b"\x90\x00", "Log entry response");

        entries += 1;
        assert!(entries <= MAX_LOG_ENTRIES, "Card log entries");
    }
}

// Relay resistance timing personalized in card_setup_app_mastercard_contactless_apdus.yaml, in units of hundreds of microseconds:
// Min Time For Processing Relay Resistance APDU || Max Time For Processing Relay Resistance APDU ||
// Device Estimated Transmission Time For Relay Resistance R-APDU
const RELAY_RESISTANCE_TIMING: &[u8] = b"\x00\x00\x00\xC8\x00\x12";

/// Mastercard contactless transaction (EMV Contactless Book C-2, Kernel 2): Relay Resistance Protocol, cardholder verification,
/// CDA with the relay resistance data in the ICC Dynamic Data and online authorisation of the ARQC.
/// The card is personalized with the PPSE setup file and the setup files applied after card_setup_app_apdus.yaml, the transaction
/// is checked against the expected CVM Results and Mastercard CVR of the ARQC.
fn mastercard_contactless_transaction_with(
    connection: &mut EmvConnection,
    ppse_setup_file: &str,
    app_setup_files: &[&str],
    cvm_results: &[u8],
    cvr: &[u8],
) {
    setup_connection(connection).unwrap();
    connection.contactless = true;

    execute_setup_apdus(connection, &[ppse_setup_file]);

    let mut setup_files = vec!["../config/card_setup_app_apdus.yaml"];
    setup_files.extend_from_slice(app_setup_files);
    let application = select_application(connection, Some(0x02), &setup_files);

    SENT_COMMANDS.lock().unwrap().clear();
    connection.start_transaction(&application).unwrap();

    let aip = connection.get_tag_value("82").unwrap().clone();
    assert!(connection.icc.capabilities.cda, "CDA supported in AIP");
    assert_eq!(
        aip[1] & 0x01,
        0x01,
        "Relay Resistance Protocol supported in AIP"
    );

    // EXCHANGE RELAY RESISTANCE DATA right after GET PROCESSING OPTIONS, before READ RECORD (EMV Contactless Book C-2, 3.10)
    let commands = SENT_COMMANDS.lock().unwrap().clone();
    let get_processing_options = commands
        .iter()
        .position(|c| c.starts_with(b"\x80\xA8"))
        .unwrap();
    assert!(commands[get_processing_options + 1].starts_with(b"\x80\xEA"));
    assert!(commands[get_processing_options + 2].starts_with(b"\x00\xB2"));

    // Terminal Relay Resistance Entropy is the Unpredictable Number
    let relay_resistance_data = connection.icc.relay_resistance_data.clone().unwrap();
    assert_eq!(
        &relay_resistance_data[0..4],
        &connection.get_tag_value("9F37").unwrap()[..]
    );
    assert_eq!(&relay_resistance_data[8..], RELAY_RESISTANCE_TIMING);
    assert_eq!(
        connection.settings.terminal.tvr.relay_resistance_performed,
        RelayResistancePerformed::Performed
    );

    connection.handle_card_verification_methods().unwrap();
    assert_eq!(
        connection.get_tag_value("9F34").unwrap(),
        &cvm_results.to_vec(),
        "CVM Results"
    );

    connection.handle_terminal_risk_management().unwrap();

    // CDA is performed with the GENERATE AC
    connection.handle_offline_data_authentication().unwrap();

    connection.handle_terminal_action_analysis().unwrap();

    // Signed Dynamic Application Data is verified within GENERATE AC, 9F26 is recovered from it
    let cryptogram_type = connection.handle_1st_generate_ac().unwrap();
    assert!(matches!(
        cryptogram_type,
        CryptogramType::AuthorisationRequestCryptogram
    ));

    // ICC Dynamic Data: ICC Dynamic Number, CID, AC, Transaction Data Hash Code and relay resistance data (EMV Contactless Book C-2, Table 6.8)
    let unpredictable_number = connection.get_tag_value("9F37").unwrap().clone();
    let icc_dynamic_data = connection
        .validate_signed_dynamic_application_data(&unpredictable_number[..])
        .unwrap();
    let icc_dynamic_number_length = icc_dynamic_data[0] as usize;
    assert_eq!(
        icc_dynamic_data.len(),
        1 + icc_dynamic_number_length + 1 + 8 + 20 + relay_resistance_data.len()
    );
    assert!(
        icc_dynamic_data.ends_with(&relay_resistance_data),
        "Relay resistance data in the ICC Dynamic Data"
    );

    assert_eq!(
        &connection.get_tag_value("9F10").unwrap()[2..8],
        cvr,
        "Mastercard CVR"
    );

    // Online authorisation, no second GENERATE AC in a contactless transaction
    let cdol1_data = data_object_list_data(connection, "8C");
    verify_authorisation_request_cryptogram(
        connection,
        &hex::decode(AC_MASTER_KEY).unwrap(),
        &cdol1_data,
        MASTERCARD_CRYPTOGRAM_VERSION_14,
    );
}

/// Mastercard contactless transaction without CVM: Kernel 2 does not support offline PIN and the terminal does not support online PIN
fn mastercard_contactless_transaction(connection: &mut EmvConnection) {
    mastercard_contactless_transaction_with(
        connection,
        "../config/card_setup_ppse_mastercard_apdus.yaml",
        &["../config/card_setup_app_mastercard_contactless_apdus.yaml"],
        // CVM Results: No CVM required was successful
        &[0x1F, 0x03, 0x02],
        // CVR: second GENERATE AC not requested, ARQC, CDA in the first GENERATE AC, PIN Try Counter 3, domestic transaction
        &[0xA0, 0x40, 0x03, 0x02, 0x00, 0x00],
    );
}

// ICC private key of card_setup_app_apdus.yaml, the ICC PIN Encipherment key as the profile has no separate one
const ICC_PRIVATE_KEY_FILE: &str = "../config/icc_1234560012345608_e_3_private_key.pem";

/// Decipher the enciphered PIN data of a VERIFY command with the ICC private key like the card does, returns the PIN
/// (EMV Book 2, 7.2: '7F' || PIN block || ICC Unpredictable Number || random padding)
fn decipher_pin(verify_command: &[u8]) -> String {
    let key = Rsa::private_key_from_pem(&fs::read(ICC_PRIVATE_KEY_FILE).unwrap()).unwrap();
    let enciphered_pin_data = &verify_command[5..5 + verify_command[4] as usize];

    let mut plaintext = vec![0u8; key.size() as usize];
    key.private_decrypt(enciphered_pin_data, &mut plaintext, Padding::NONE)
        .unwrap();
    assert_eq!(plaintext[0], 0x7F, "Enciphered PIN data header");

    // PIN block (EMV Book 3, 6.5.12): control '2' || PIN length || PIN digits || 'F' filler
    let pin_block = &plaintext[1..9];
    assert_eq!(pin_block[0] >> 4, 0x2, "PIN block control field");
    let pin_length = (pin_block[0] & 0x0F) as usize;
    hex::encode(&pin_block[1..])[..pin_length].to_string()
}

/// Mockstercard, a fake card scheme on top of Kernel 2, contactless card for a demonstration: the card asks for the
/// enciphered offline PIN and as it holds the ICC private key, it deciphers the PIN the cardholder entered on the terminal
fn mockstercard_contactless_pin_transaction(connection: &mut EmvConnection) {
    // A Kernel 2 reader does not do offline PIN, the demonstration needs a terminal that deviates from EMV Contactless Book C-2
    connection
        .settings
        .terminal
        .protocol_deviations
        .kernel_2_offline_pin = true;

    mastercard_contactless_transaction_with(
        connection,
        "../config/card_setup_ppse_mockstercard_apdus.yaml",
        &[
            "../config/card_setup_app_mastercard_contactless_apdus.yaml",
            "../config/card_setup_app_mockstercard_contactless_apdus.yaml",
        ],
        // CVM Results: enciphered PIN verified by ICC was successful
        &[0x44, 0x03, 0x02],
        // CVR: offline enciphered PIN verification performed and successful in addition to the CVR without CVM
        &[0xA7, 0x40, 0x03, 0x02, 0x00, 0x00],
    );

    assert_eq!(
        connection.get_tag_value("50").unwrap(),
        &b"MOCKSTERCARD".to_vec(),
        "Application Label"
    );

    let commands = SENT_COMMANDS.lock().unwrap().clone();
    let verify_command = commands
        .iter()
        .find(|c| c.starts_with(b"\x00\x20\x00\x88"))
        .expect("VERIFY with enciphered PIN");

    let pin = decipher_pin(verify_command);
    info!(
        "***** Mockstercard deciphered the cardholder PIN: {} *****",
        pin
    );
    assert_eq!(pin, pin_entry().unwrap());
}

/// Visa contactless transaction (EMV Contactless Book C-3, Kernel 3): qVSDC online cryptogram returned in GET PROCESSING OPTIONS,
/// fDDA and no CVM
fn visa_contactless_transaction(connection: &mut EmvConnection) {
    setup_connection(connection).unwrap();
    connection.contactless = true;
    connection.pin_callback = None;

    // Terminal Transaction Qualifiers: online cryptogram required, CVM not required
    let ttq = &mut connection.settings.terminal.terminal_transaction_qualifiers;
    ttq.online_cryptogram_required = true;
    ttq.cvm_required = false;

    execute_setup_apdus(connection, &["../config/card_setup_ppse_apdus.yaml"]);

    let application = select_application(
        connection,
        Some(0x03),
        &[
            "../config/card_setup_app_apdus.yaml",
            "../config/card_setup_app_visa_contactless_apdus.yaml",
        ],
    );

    connection.start_transaction(&application).unwrap();

    // Card completed the transaction in GET PROCESSING OPTIONS
    for tag in ["9F26", "9F27", "9F36", "9F10", "9F4B", "9F69"] {
        assert!(
            connection.get_tag_value(tag).is_some(),
            "{} in GET PROCESSING OPTIONS response",
            tag
        );
    }
    // PDOL related data as the card arranged it to CDOL1 related data for the Application Cryptogram
    let cdol1_data = data_object_list_data(connection, "8C");

    // No CVM: no cardholder verification in AIP, Card Transaction Qualifiers do not require online PIN or signature
    let aip = connection.get_tag_value("82").unwrap();
    assert_eq!(
        aip[0] & 0x10,
        0x00,
        "Cardholder verification supported in AIP"
    );
    let ctq = connection.get_tag_value("9F6C").unwrap();
    assert_eq!(ctq[0] & 0xC0, 0x00, "CTQ online PIN or signature required");

    connection.handle_terminal_risk_management().unwrap();

    connection.handle_offline_data_authentication().unwrap();
    assert!(!connection.settings.terminal.tvr.dda_failed, "fDDA failed");
    // ICC Dynamic Number recovered from the fDDA signature
    assert!(connection.get_tag_value("9F4C").is_some());

    connection.handle_terminal_action_analysis().unwrap();

    // Cryptogram from the GET PROCESSING OPTIONS response, no GENERATE AC
    let cryptogram_type = connection.handle_1st_generate_ac().unwrap();
    assert!(matches!(
        cryptogram_type,
        CryptogramType::AuthorisationRequestCryptogram
    ));

    verify_authorisation_request_cryptogram(
        connection,
        &hex::decode(AC_MASTER_KEY).unwrap(),
        &cdol1_data,
        VISA_CRYPTOGRAM_VERSION_18,
    );
}

/// Run a transaction against the simulated card of the Java callback, a failure is thrown as an AssertionError
fn run_transaction(
    env: JNIEnv<'static>,
    callback: JObject<'static>,
    name: &str,
    transaction: fn(&mut EmvConnection),
) {
    run_transaction_with_settings(env, callback, name, "../config/settings.yaml", transaction);
}

/// Run a transaction with the emvpt settings file against the simulated card of the Java callback
fn run_transaction_with_settings(
    mut env: JNIEnv<'static>,
    callback: JObject<'static>,
    name: &str,
    settings_file: &str,
    transaction: fn(&mut EmvConnection),
) {
    trace!("Simulator entry point called!");

    LOGGING.call_once(|| init_logging().unwrap());

    // Setup JVM and callback points to Simulator class

    let _ = JVM.set(env.get_java_vm().unwrap());

    *CALLBACK.lock().unwrap() = Some(env.new_global_ref(callback).unwrap());

    info!("===== START: {} =====", name);

    let result = panic::catch_unwind(|| {
        let mut connection = EmvConnection::new(settings_file).unwrap();
        let smart_card_connection = JavaSmartCardConnection {};
        connection.interface = Some(&smart_card_connection);

        transaction(&mut connection);
    });

    *CALLBACK.lock().unwrap() = None;

    info!(
        "===== {}: {} =====",
        if result.is_ok() { "PASSED" } else { "FAILED" },
        name
    );

    if let Err(cause) = result {
        // Exception of the Java callback is thrown as is
        if !env.exception_check().unwrap() {
            let message = match cause.downcast_ref::<String>() {
                Some(message) => message.clone(),
                None => cause
                    .downcast_ref::<&str>()
                    .map_or("Transaction failed".to_string(), |message| {
                        message.to_string()
                    }),
            };
            env.throw_new("java/lang/AssertionError", message).unwrap();
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_emvcardsimulator_SimulatorTest_entryPoint(
    env: JNIEnv<'static>,
    _class: JClass<'static>,
    callback: JObject<'static>,
) {
    run_transaction(env, callback, "Contact transaction", contact_transaction);
}

#[no_mangle]
pub extern "system" fn Java_emvcardsimulator_SimulatorTest_contactDeclinedEntryPoint(
    env: JNIEnv<'static>,
    _class: JClass<'static>,
    callback: JObject<'static>,
) {
    run_transaction(
        env,
        callback,
        "Contact transaction declined online",
        contact_declined_transaction,
    );
}

#[no_mangle]
pub extern "system" fn Java_emvcardsimulator_SimulatorTest_contactUnableToGoOnlineEntryPoint(
    env: JNIEnv<'static>,
    _class: JClass<'static>,
    callback: JObject<'static>,
) {
    run_transaction(
        env,
        callback,
        "Contact transaction unable to go online",
        contact_unable_to_go_online_transaction,
    );
}

#[no_mangle]
pub extern "system" fn Java_emvcardsimulator_SimulatorTest_mastercardContactlessEntryPoint(
    env: JNIEnv<'static>,
    _class: JClass<'static>,
    callback: JObject<'static>,
) {
    run_transaction(
        env,
        callback,
        "Mastercard contactless transaction",
        mastercard_contactless_transaction,
    );
}

#[no_mangle]
pub extern "system" fn Java_emvcardsimulator_SimulatorTest_mockstercardContactlessPinEntryPoint(
    env: JNIEnv<'static>,
    _class: JClass<'static>,
    callback: JObject<'static>,
) {
    run_transaction(
        env,
        callback,
        "Mockstercard (fake card scheme) contactless transaction with enciphered PIN",
        mockstercard_contactless_pin_transaction,
    );
}

#[no_mangle]
pub extern "system" fn Java_emvcardsimulator_SimulatorTest_visaContactlessEntryPoint(
    env: JNIEnv<'static>,
    _class: JClass<'static>,
    callback: JObject<'static>,
) {
    run_transaction(
        env,
        callback,
        "Visa contactless transaction",
        visa_contactless_transaction,
    );
}

// Private test card (PrivateCardTest): setup file of the card and the PIN of the cardholder
static PRIVATE_CARD_FILE: Mutex<String> = Mutex::new(String::new());
static PRIVATE_CARD_PIN: Mutex<String> = Mutex::new(String::new());
// emvpt settings of the private test cards, with the CA public keys of the cards
const PRIVATE_SETTINGS_FILE: &str = "../../../../private/config/settings.yaml";

const PPSE_AID: &[u8] = b"2PAY.SYS.DDF01";
const PSE_AID: &[u8] = b"1PAY.SYS.DDF01";

/// What the terminal, the issuer and the cardholder know of a private test card, from its setup file: application AIDs
/// (the terminal list of AIDs), ICC Application Cryptogram Master Key and CDOL1 (issuer) and PIN (cardholder)
struct PrivateCard {
    file: String,
    applications: Vec<Vec<u8>>,
    master_key: Option<Vec<u8>>,
    cdol1: Option<Vec<u8>>,
}

impl PrivateCard {
    fn load() -> PrivateCard {
        let file = PRIVATE_CARD_FILE.lock().unwrap().clone();
        let setup: Vec<ApduRequestResponse> =
            serde_yaml::from_str(&fs::read_to_string(&file).unwrap()).unwrap();

        let mut card = PrivateCard {
            file: file,
            applications: Vec::new(),
            master_key: None,
            cdol1: None,
        };
        let mut pin = String::from("1234");
        for apdu in setup.into_iter().filter(|apdu| !apdu.req.is_empty()) {
            let request = ApduRequestResponse::to_raw_vec(&apdu.req);
            let data = &request[5..];
            if request.starts_with(b"\x00\xA4\x04\x00") {
                let aid = data.to_vec();
                if aid != PPSE_AID && aid != PSE_AID && !card.applications.contains(&aid) {
                    card.applications.push(aid);
                }
            } else if request.starts_with(b"\x80\x00\x00\x07\x10") && card.master_key.is_none() {
                card.master_key = Some(data.to_vec());
            } else if request.starts_with(b"\x80\x00\x00\x01") {
                pin = hex::encode_upper(data).trim_end_matches('F').to_string();
            } else if request.starts_with(b"\x80\x04") && card.cdol1.is_none() {
                card.cdol1 = find_data_object(data, &[0x8C]);
            }
        }
        *PRIVATE_CARD_PIN.lock().unwrap() = pin;

        card
    }
}

fn private_card_pin_entry() -> Result<String, ()> {
    Ok(PRIVATE_CARD_PIN.lock().unwrap().clone())
}

/// Value of the first data object with the tag in BER-TLV coded data, constructed data objects are searched recursively
fn find_data_object(data: &[u8], tag: &[u8]) -> Option<Vec<u8>> {
    let mut i = 0;
    while i < data.len() {
        if data[i] == 0x00 || data[i] == 0xFF {
            i += 1;
            continue;
        }
        let tag_start = i;
        i += 1;
        if data[tag_start] & 0x1F == 0x1F {
            while i < data.len() && data[i] & 0x80 != 0 {
                i += 1;
            }
            i += 1;
        }
        let tag_end = i;
        if i >= data.len() {
            return None;
        }
        let mut length = data[i] as usize;
        i += 1;
        if length == 0x81 {
            length = data[i] as usize;
            i += 1;
        } else if length == 0x82 {
            length = ((data[i] as usize) << 8) | data[i + 1] as usize;
            i += 2;
        }
        if i + length > data.len() {
            return None;
        }
        let value = &data[i..i + length];
        if &data[tag_start..tag_end] == tag {
            return Some(value.to_vec());
        }
        if data[tag_start] & 0x20 != 0 {
            if let Some(found) = find_data_object(value, tag) {
                return Some(found);
            }
        }
        i += length;
    }
    None
}

/// Length of a data object in a Data Object List
fn data_object_list_entry_length(dol: &[u8], search_tag: &[u8]) -> Option<usize> {
    let mut i = 0;
    while i < dol.len() {
        let tag_start = i;
        i += 1;
        if dol[tag_start] & 0x1F == 0x1F {
            while dol[i] & 0x80 != 0 {
                i += 1;
            }
            i += 1;
        }
        let length = dol[i] as usize;
        if &dol[tag_start..i] == search_tag {
            return Some(length);
        }
        i += 1;
    }
    None
}

fn cryptogram_name(cryptogram_type: CryptogramType) -> &'static str {
    match cryptogram_type {
        CryptogramType::ApplicationAuthenticationCryptogram => "AAC",
        CryptogramType::AuthorisationRequestCryptogram => "ARQC",
        CryptogramType::TransactionCertificate => "TC",
    }
}

/// Issuer verification of the ARQC when the card has Visa Cryptogram Version Number 18 ('06' || DKI || '12' || CVR in Issuer
/// Application Data), returns a description of the result
fn verify_private_card_arqc(connection: &EmvConnection, card: &PrivateCard) -> String {
    let issuer_application_data = connection.get_tag_value("9F10").unwrap().clone();
    let master_key = match &card.master_key {
        Some(key) => key,
        None => return "ARQC not verified, no ICC Application Cryptogram Master Key".to_string(),
    };
    if issuer_application_data.len() != 7
        || issuer_application_data[0] != 0x06
        || issuer_application_data[2] != VISA_CRYPTOGRAM_VERSION_18.0
    {
        return format!(
            "ARQC not verified, Issuer Application Data {} is not CVN 18",
            hex::encode_upper(&issuer_application_data)
        );
    }

    // CDOL1 of the card, a qVSDC reader does not necessarily read the record with it
    let cdol1 = match &card.cdol1 {
        Some(cdol1) => cdol1,
        None => return "ARQC not verified, no CDOL1".to_string(),
    };
    let cdol1_data = if connection.contactless {
        cdol1_data_from_pdol_data(connection, cdol1)
    } else {
        DataObjectList::process_data_object_list(connection, cdol1)
            .unwrap()
            .get_tag_list_tag_values(connection)
    };
    verify_authorisation_request_cryptogram(
        connection,
        master_key,
        &cdol1_data,
        VISA_CRYPTOGRAM_VERSION_18,
    );
    "ARQC verified (CVN 18)".to_string()
}

/// qVSDC Application Cryptogram input of the simulator: PDOL related data of the GET PROCESSING OPTIONS command arranged as CDOL1
/// related data, data objects that are not in the PDOL are zero filled
fn cdol1_data_from_pdol_data(connection: &EmvConnection, cdol1: &[u8]) -> Vec<u8> {
    let pdol = connection.get_tag_value("9F38").cloned().unwrap_or_default();
    let commands = SENT_COMMANDS.lock().unwrap().clone();
    let get_processing_options = commands
        .iter()
        .rev()
        .find(|c| c.starts_with(b"\x80\xA8"))
        .expect("GET PROCESSING OPTIONS");
    // Command data: Command Template '83' || length || PDOL related data
    let pdol_data = &get_processing_options[7..7 + get_processing_options[6] as usize];

    let entries = |dol: &[u8]| -> Vec<(Vec<u8>, usize)> {
        let mut result = Vec::new();
        let mut i = 0;
        while i < dol.len() {
            let tag_start = i;
            i += 1;
            if dol[tag_start] & 0x1F == 0x1F {
                while dol[i] & 0x80 != 0 {
                    i += 1;
                }
                i += 1;
            }
            result.push((dol[tag_start..i].to_vec(), dol[i] as usize));
            i += 1;
        }
        result
    };

    let mut data = Vec::new();
    for (tag, length) in entries(cdol1) {
        let mut offset = 0;
        let mut value = vec![0x00; length];
        for (pdol_tag, pdol_length) in entries(&pdol) {
            if pdol_tag == tag {
                let copy_length = length.min(pdol_length);
                value[..copy_length].copy_from_slice(&pdol_data[offset..offset + copy_length]);
                break;
            }
            offset += pdol_length;
        }
        data.extend_from_slice(&value);
    }
    data
}

/// Online authorisation approved by the issuer: Authorisation Response Code '00' and Issuer Authentication Data with the ARPC
/// method given by the length of Issuer Authentication Data in CDOL2 (EMV Book 2, 8.2), CSU of Method 2 is zero
fn private_card_online_authorisation(connection: &mut EmvConnection, card: &PrivateCard) -> String {
    connection.add_tag("8A", AUTHORISATION_RESPONSE_CODE.to_vec());

    let cdol2 = connection.get_tag_value("8D").cloned().unwrap_or_default();
    let issuer_authentication_data_length = data_object_list_entry_length(&cdol2, &[0x91]);
    let result = match (&card.master_key, issuer_authentication_data_length) {
        (Some(master_key), Some(length)) => {
            let arqc = connection.get_tag_value("9F26").unwrap().clone();
            let atc = connection.get_tag_value("9F36").unwrap().clone();
            let (data, method) = if length == 10 {
                (issuer_authentication_data(master_key, &arqc, &atc, AUTHORISATION_RESPONSE_CODE), "ARPC Method 1")
            } else {
                (issuer_authentication_data_method_2(master_key, &arqc, &atc, &[0x00; 4]), "ARPC Method 2")
            };
            connection.add_tag("91", data);
            method
        }
        (None, _) => "no ARPC, no ICC Application Cryptogram Master Key",
        (Some(master_key), None) if connection.icc.capabilities.issuer_authentication => {
            // EXTERNAL AUTHENTICATE, the card has the simulator default ARPC Method 1 as the profile does not give the method
            let arqc = connection.get_tag_value("9F26").unwrap().clone();
            let atc = connection.get_tag_value("9F36").unwrap().clone();
            let data = issuer_authentication_data(master_key, &arqc, &atc, AUTHORISATION_RESPONSE_CODE);
            connection.add_tag("91", data);
            "ARPC Method 1 in EXTERNAL AUTHENTICATE"
        }
        (_, None) => "no ARPC, no Issuer Authentication Data in CDOL2",
    };

    connection.handle_issuer_authentication_data().unwrap();
    assert!(
        !connection.settings.terminal.tvr.issuer_authentication_failed,
        "Issuer authentication failed"
    );

    result.to_string()
}

fn private_card_tvr(connection: &EmvConnection) -> String {
    let tvr = &connection.settings.terminal.tvr;
    let mut flags = Vec::new();
    for (set, name) in [
        (tvr.offline_data_authentication_was_not_performed, "ODA not performed"),
        (tvr.sda_failed, "SDA failed"),
        (tvr.dda_failed, "DDA failed"),
        (tvr.cda_failed, "CDA failed"),
        (tvr.icc_data_missing, "ICC data missing"),
        (tvr.cardholder_verification_was_not_successful, "CVM not successful"),
        (tvr.unrecognised_cvm, "unrecognised CVM"),
        (tvr.online_pin_entered, "online PIN entered"),
        (tvr.expired_application, "expired application"),
        (tvr.requested_service_not_allowed_for_card_product, "service not allowed"),
    ] {
        if set {
            flags.push(name);
        }
    }
    format!("TVR: {}", if flags.is_empty() { "-".to_string() } else { flags.join(", ") })
}

/// Contact transaction of a private test card. The card has no PSE, so the terminal builds the candidate list with its list of
/// AIDs (EMV Book 1, 12.3.3), the terminal list is the AIDs of the card. The application with the highest priority is selected
/// (EMV Book 1, 12.4). An ARQC is authorised online and completed with the second GENERATE AC.
fn private_card_contact_transaction(connection: &mut EmvConnection) {
    let card = PrivateCard::load();
    setup_connection(connection).unwrap();
    connection.pin_callback = Some(&private_card_pin_entry);

    execute_setup_apdus(connection, &[&card.file]);

    let mut candidates: Vec<(u8, EmvApplication)> = Vec::new();
    for aid in &card.applications {
        let mut select = b"\x00\xA4\x04\x00".to_vec();
        select.push(aid.len() as u8);
        select.extend_from_slice(aid);
        select.push(0x00);
        let (response_trailer, response_data) = connection.send_apdu(&select);
        if response_trailer != b"\x90\x00" || response_data.is_empty() {
            info!("Application {} not available: {:02X?}", hex::encode_upper(aid), response_trailer);
            continue;
        }
        let priority = find_data_object(&response_data, &[0x87]).unwrap_or_default();
        // Application Priority Indicator b4-b1, '0' is no priority
        let order = match priority.first() {
            Some(p) if p & 0x0F != 0 => p & 0x0F,
            _ => 0x10,
        };
        candidates.push((
            order,
            EmvApplication {
                aid: aid.clone(),
                label: find_data_object(&response_data, &[0x50]).unwrap_or_default(),
                priority: priority,
                kernel_identifier: None,
            },
        ));
    }
    assert!(!candidates.is_empty(), "No application to select");
    candidates.sort_by_key(|(order, _)| *order);
    let application = candidates[0].1.clone();

    connection.handle_select_payment_application(&application).unwrap();
    connection.start_transaction(&application).expect("Transaction start");
    connection.handle_card_verification_methods().expect("Cardholder verification");
    connection.handle_terminal_risk_management().expect("Terminal risk management");
    connection.handle_offline_data_authentication().expect("Offline data authentication");
    connection.handle_terminal_action_analysis().expect("Terminal action analysis");

    let first = connection.handle_1st_generate_ac().expect("First GENERATE AC");
    let mut result = format!(
        "{} AIP {} CVM Results {} {}, first GENERATE AC {}",
        hex::encode_upper(&application.aid),
        hex::encode_upper(connection.get_tag_value("82").unwrap()),
        connection.get_tag_value("9F34").map_or("-".to_string(), hex::encode_upper),
        private_card_tvr(connection),
        cryptogram_name(first)
    );

    if let CryptogramType::AuthorisationRequestCryptogram = first {
        result += &format!(", {}", verify_private_card_arqc(connection, &card));
        result += &format!(", {}", private_card_online_authorisation(connection, &card));
        let second = connection.handle_2nd_generate_ac().expect("Second GENERATE AC");
        result += &format!(", second GENERATE AC {}", cryptogram_name(second));
        assert!(
            matches!(second, CryptogramType::TransactionCertificate),
            "Online approved transaction not completed with TC: {}",
            result
        );
    }

    info!("RESULT contact: {}", result);
}

/// Contactless transaction of a private test card: PPSE, qVSDC (EMV Contactless Book C-3) with the cryptogram in the GET PROCESSING
/// OPTIONS response, ARQC is verified by the issuer.
fn private_card_contactless_transaction(connection: &mut EmvConnection) {
    let card = PrivateCard::load();
    setup_connection(connection).unwrap();
    connection.contactless = true;
    connection.pin_callback = Some(&private_card_pin_entry);

    execute_setup_apdus(connection, &[&card.file]);
    SENT_COMMANDS.lock().unwrap().clear();

    let applications = connection
        .handle_select_payment_system_environment()
        .expect("PPSE");
    let application = applications[0].clone();

    connection.handle_select_payment_application(&application).unwrap();
    connection.start_transaction(&application).expect("Transaction start");
    connection.handle_terminal_risk_management().expect("Terminal risk management");
    connection.handle_offline_data_authentication().expect("Offline data authentication");
    connection.handle_terminal_action_analysis().expect("Terminal action analysis");

    let cryptogram_in_gpo = connection.get_tag_value("9F26").is_some();
    let first = connection.handle_1st_generate_ac().expect("Application Cryptogram");
    let mut result = format!(
        "{} AIP {} CTQ {} {}, {} {}",
        hex::encode_upper(&application.aid),
        hex::encode_upper(connection.get_tag_value("82").unwrap()),
        connection.get_tag_value("9F6C").map_or("-".to_string(), hex::encode_upper),
        private_card_tvr(connection),
        if cryptogram_in_gpo { "GET PROCESSING OPTIONS" } else { "GENERATE AC" },
        cryptogram_name(first)
    );

    if let CryptogramType::AuthorisationRequestCryptogram = first {
        result += &format!(", {}", verify_private_card_arqc(connection, &card));
    }

    info!("RESULT contactless: {}", result);
}

fn set_private_card(env: &mut JNIEnv, setup_file: &JString) {
    let file: String = env.get_string(setup_file).unwrap().into();
    *PRIVATE_CARD_FILE.lock().unwrap() = file;
}

#[no_mangle]
pub extern "system" fn Java_emvcardsimulator_PrivateCardTest_contactEntryPoint(
    mut env: JNIEnv<'static>,
    _class: JClass<'static>,
    callback: JObject<'static>,
    setup_file: JString<'static>,
) {
    set_private_card(&mut env, &setup_file);
    let name = format!("Private card contact transaction {}", PRIVATE_CARD_FILE.lock().unwrap());
    run_transaction_with_settings(env, callback, &name, PRIVATE_SETTINGS_FILE, private_card_contact_transaction);
}

#[no_mangle]
pub extern "system" fn Java_emvcardsimulator_PrivateCardTest_contactlessEntryPoint(
    mut env: JNIEnv<'static>,
    _class: JClass<'static>,
    callback: JObject<'static>,
    setup_file: JString<'static>,
) {
    set_private_card(&mut env, &setup_file);
    let name = format!("Private card contactless transaction {}", PRIVATE_CARD_FILE.lock().unwrap());
    run_transaction_with_settings(env, callback, &name, PRIVATE_SETTINGS_FILE, private_card_contactless_transaction);
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {}
}
