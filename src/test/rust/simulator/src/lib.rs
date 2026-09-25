use hex;
use jni::objects::{GlobalRef, JByteArray, JClass, JObject, JValue};
use jni::{JNIEnv, JavaVM};
use log::trace;
use log::LevelFilter;
use log4rs;
use log4rs::{
    append::console::ConsoleAppender,
    config::{Appender, Root},
};
use openssl::symm::{Cipher, Crypter, Mode};
use serde::Deserialize;
use std::error;
use std::fs::{self};
use std::sync::{Mutex, OnceLock};

use emvpt::*;

static JVM: OnceLock<JavaVM> = OnceLock::new();
static CALLBACK: Mutex<Option<GlobalRef>> = Mutex::new(None);
static APDU_RESPONSE: Mutex<Vec<u8>> = Mutex::new(Vec::new());

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

/// Issuer Authentication Data (tag 91) with ARPC Method 1 as the issuer would generate it.
/// EMV Book 2, A1.3.1 session key derivation and 8.2.1 ARPC Method 1: ARPC || ARC
fn issuer_authentication_data(arqc: &[u8], atc: &[u8]) -> Vec<u8> {
    let master_key = hex::decode(AC_MASTER_KEY).unwrap();

    let mut diversification = vec![0u8; 16];
    diversification[0..2].copy_from_slice(atc);
    diversification[2] = 0xF0;
    diversification[8..10].copy_from_slice(atc);
    diversification[10] = 0x0F;
    let session_key = triple_des_encrypt(&master_key, &diversification);

    let mut y = arqc.to_vec();
    y[0] ^= AUTHORISATION_RESPONSE_CODE[0];
    y[1] ^= AUTHORISATION_RESPONSE_CODE[1];

    let mut result = triple_des_encrypt(&session_key, &y);
    result.extend_from_slice(AUTHORISATION_RESPONSE_CODE);
    result
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

#[no_mangle]
pub extern "system" fn Java_emvcardsimulator_SimulatorTest_entryPoint(
    env: JNIEnv<'static>,
    _class: JClass<'static>,
    callback: JObject<'static>,
) {
    trace!("Simulator entry point called!");

    init_logging().unwrap();

    // Setup JVM and callback points to Simulator class

    let _ = JVM.set(env.get_java_vm().unwrap());

    *CALLBACK.lock().unwrap() = Some(env.new_global_ref(callback).unwrap());

    let mut connection = EmvConnection::new("../config/settings.yaml").unwrap();
    let smart_card_connection = JavaSmartCardConnection {};
    connection.interface = Some(&smart_card_connection);
    setup_connection(&mut connection).unwrap();

    // Setup the PSE ICC data
    ApduRequestResponse::execute_setup_apdus(
        &mut connection,
        "../config/card_setup_pse_apdus.yaml",
    )
    .unwrap();

    let applications = connection
        .handle_select_payment_system_environment()
        .unwrap();

    // Setup the app ICC data
    ApduRequestResponse::execute_setup_apdus(
        &mut connection,
        "../config/card_setup_app_apdus.yaml",
    )
    .unwrap();

    let application = &applications[0];
    connection
        .handle_select_payment_application(application)
        .unwrap();

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
    ApduRequestResponse::execute_setup_apdus(
        &mut connection,
        "../config/card_log_consume_apdus.yaml",
    )
    .unwrap();
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {}
}
