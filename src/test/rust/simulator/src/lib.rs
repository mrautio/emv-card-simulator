use hex;
use jni::objects::{GlobalRef, JByteArray, JClass, JObject, JValue};
use jni::{JNIEnv, JavaVM};
use log::LevelFilter;
use log::{info, trace};
use log4rs;
use log4rs::{
    append::console::ConsoleAppender,
    config::{Appender, Root},
};
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
// CLA INS of the commands sent to the card, to check the command order of a transaction
static SENT_COMMANDS: Mutex<Vec<[u8; 2]>> = Mutex::new(Vec::new());

#[no_mangle]
pub extern "system" fn Java_emvcardsimulator_SimulatorTest_sendApduResponse(
    env: JNIEnv,
    _class: JClass,
    response_apdu: JByteArray,
) {
    let mut apdu_response = APDU_RESPONSE.lock().unwrap();
    apdu_response.clear();
    apdu_response.extend_from_slice(&env.convert_byte_array(&response_apdu).unwrap()[..]);
    trace!("RESPONSE: {:02X?}", apdu_response);
}

struct JavaSmartCardConnection {}

impl ApduInterface for JavaSmartCardConnection {
    fn send_apdu(&self, apdu: &[u8]) -> Result<Vec<u8>, ()> {
        trace!("CALLING {:02X?}", apdu);
        SENT_COMMANDS.lock().unwrap().push([apdu[0], apdu[1]]);

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

#[derive(Deserialize, Clone)]
struct ApduRequestResponse {
    req: String,
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

        for apdu in card_setup_data {
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
// Authorisation Response Code '00' = approved
const AUTHORISATION_RESPONSE_CODE: &[u8] = b"00";

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
fn application_cryptogram_session_key(atc: &[u8]) -> Vec<u8> {
    let master_key = hex::decode(AC_MASTER_KEY).unwrap();

    let mut diversification = vec![0u8; 16];
    diversification[0..2].copy_from_slice(atc);
    diversification[2] = 0xF0;
    diversification[8..10].copy_from_slice(atc);
    diversification[10] = 0x0F;
    triple_des_encrypt(&master_key, &diversification)
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
fn issuer_authentication_data(arqc: &[u8], atc: &[u8]) -> Vec<u8> {
    let session_key = application_cryptogram_session_key(atc);

    let mut y = arqc.to_vec();
    y[0] ^= AUTHORISATION_RESPONSE_CODE[0];
    y[1] ^= AUTHORISATION_RESPONSE_CODE[1];

    let mut result = triple_des_encrypt(&session_key, &y);
    result.extend_from_slice(AUTHORISATION_RESPONSE_CODE);
    result
}

/// Values of the data objects in a Data Object List (e.g. CDOL1 related data) from the terminal tags
fn data_object_list_data(connection: &EmvConnection, dol_tag: &str) -> Vec<u8> {
    let dol = connection.get_tag_value(dol_tag).unwrap();
    DataObjectList::process_data_object_list(connection, &dol[..])
        .unwrap()
        .get_tag_list_tag_values(connection)
}

/// Issuer verification of the Authorisation Request Cryptogram (9F26) the ICC generated with MK_AC
/// over CDOL1 related data || AIP || ATC
fn verify_authorisation_request_cryptogram(connection: &EmvConnection, cdol1_data: &[u8]) {
    let aip = connection.get_tag_value("82").unwrap();
    let atc = connection.get_tag_value("9F36").unwrap();

    let mut data = cdol1_data.to_vec();
    data.extend_from_slice(aip);
    data.extend_from_slice(atc);
    let expected_arqc = retail_mac(&application_cryptogram_session_key(atc), &data);

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

/// Contact transaction: DDA, enciphered offline PIN, online authorisation with issuer authentication in the second GENERATE AC
fn contact_transaction(connection: &mut EmvConnection) {
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

    if let CryptogramType::AuthorisationRequestCryptogram =
        connection.handle_1st_generate_ac().unwrap()
    {
        // Online authorisation response from the issuer
        let arqc = connection.get_tag_value("9F26").unwrap().clone();
        let atc = connection.get_tag_value("9F36").unwrap().clone();
        connection.add_tag("8A", AUTHORISATION_RESPONSE_CODE.to_vec());
        connection.add_tag("91", issuer_authentication_data(&arqc, &atc));

        connection.handle_issuer_authentication_data().unwrap();
        connection.handle_2nd_generate_ac().unwrap();
    }

    // Consume logs that the card gathered
    execute_setup_apdus(connection, &["../config/card_log_consume_apdus.yaml"]);
}

// Relay resistance timing personalized in card_setup_app_mastercard_contactless_apdus.yaml, in units of hundreds of microseconds:
// Min Time For Processing Relay Resistance APDU || Max Time For Processing Relay Resistance APDU ||
// Device Estimated Transmission Time For Relay Resistance R-APDU
const RELAY_RESISTANCE_TIMING: &[u8] = b"\x00\x00\x00\xC8\x00\x12";

/// Mastercard contactless transaction (EMV Contactless Book C-2, Kernel 2): Relay Resistance Protocol, enciphered offline PIN,
/// CDA with the relay resistance data in the ICC Dynamic Data and online authorisation of the ARQC
fn mastercard_contactless_transaction(connection: &mut EmvConnection) {
    setup_connection(connection).unwrap();
    connection.contactless = true;

    execute_setup_apdus(
        connection,
        &["../config/card_setup_ppse_mastercard_apdus.yaml"],
    );

    let application = select_application(
        connection,
        Some(0x02),
        &[
            "../config/card_setup_app_apdus.yaml",
            "../config/card_setup_app_mastercard_contactless_apdus.yaml",
        ],
    );

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
    let get_processing_options = commands.iter().position(|c| c == b"\x80\xA8").unwrap();
    assert_eq!(commands[get_processing_options + 1], *b"\x80\xEA");
    assert_eq!(commands[get_processing_options + 2], *b"\x00\xB2");

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
    // CVM Results: enciphered PIN verified by ICC was successful
    assert_eq!(
        connection.get_tag_value("9F34").unwrap(),
        &vec![0x44, 0x03, 0x02]
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

    // Online authorisation, no second GENERATE AC in a contactless transaction
    let cdol1_data = data_object_list_data(connection, "8C");
    verify_authorisation_request_cryptogram(connection, &cdol1_data);
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

    verify_authorisation_request_cryptogram(connection, &cdol1_data);
}

/// Run a transaction against the simulated card of the Java callback, a failure is thrown as an AssertionError
fn run_transaction(
    mut env: JNIEnv<'static>,
    callback: JObject<'static>,
    name: &str,
    transaction: fn(&mut EmvConnection),
) {
    trace!("Simulator entry point called!");

    LOGGING.call_once(|| init_logging().unwrap());

    // Setup JVM and callback points to Simulator class

    let _ = JVM.set(env.get_java_vm().unwrap());

    *CALLBACK.lock().unwrap() = Some(env.new_global_ref(callback).unwrap());

    info!("===== START: {} =====", name);

    let result = panic::catch_unwind(|| {
        let mut connection = EmvConnection::new("../config/settings.yaml").unwrap();
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

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {}
}
