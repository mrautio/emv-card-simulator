use jni::JNIEnv;
use jni::objects::{GlobalRef, JClass, JObject};
use jni::sys::jbyteArray;
use serde::{Deserialize};
use hex;
use std::fs::{self};
use std::error;
use log4rs;
use log::{LevelFilter};
use log::{trace};
use log4rs::{
    append::console::ConsoleAppender,
    config::{Appender, Root}
};

use emvpt::*;

static mut ENV : Option<JNIEnv<'static>> = None;
static mut CALLBACK : Option<GlobalRef> = None;
static mut APDU_RESPONSE : Vec<u8> = Vec::new();

#[no_mangle]
pub extern "system" fn Java_emvcardsimulator_SimulatorTest_sendApduResponse(
    env: JNIEnv,
    _class: JClass,
    response_apdu: jbyteArray,
) {
    unsafe {
        APDU_RESPONSE.clear();
        APDU_RESPONSE.extend_from_slice(&env.convert_byte_array(response_apdu).unwrap()[..]);
        trace!("RESPONSE: {:02X?}", APDU_RESPONSE);
    }
}


fn java_card_apdu_interface(apdu : &[u8]) -> Result<Vec<u8>, ()> {
    trace!("CALLING {:02X?}", apdu);

    let mut output : Vec<u8> = Vec::new();

    unsafe {
        let request_apdu = ENV.as_ref().unwrap().byte_array_from_slice(apdu).unwrap();
        ENV.as_ref().unwrap().call_method(CALLBACK.as_ref().unwrap(), "sendApduRequest", "([B)V", &[request_apdu.into()]).unwrap();

        output.extend_from_slice(&APDU_RESPONSE[..]);
    }

    Ok(output)
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
    req : String,
    res : String
}

impl ApduRequestResponse {
    fn to_raw_vec(s : &String) -> Vec<u8> {
        hex::decode(s.replace(" ", "")).unwrap()
    }
}

fn execute_setup_apdus(connection : &mut EmvConnection, setup_file : &str) -> Result<(), String> {
    // Setup the app ICC data
    let card_setup_data : Vec<ApduRequestResponse> = serde_yaml::from_str(&fs::read_to_string(setup_file).unwrap()).unwrap();
    for apdu in card_setup_data {
        let request = ApduRequestResponse::to_raw_vec(&apdu.req);
        let response = ApduRequestResponse::to_raw_vec(&apdu.res);

        let (response_trailer, _) = connection.send_apdu(&request);
        if &response_trailer[..] != &response[..] {
            return Err(format!("Response not what expected! expected:{:02X?}, actual:{:02X?}", &response[..], &response_trailer[..]));
        }
    }

    Ok(())
}

#[no_mangle]
pub extern "system" fn Java_emvcardsimulator_SimulatorTest_entryPoint(
    env: JNIEnv<'static>,
    _class: JClass,
    callback: JObject,
) {
    trace!("Simulator entry point called!");

    init_logging().unwrap();

    unsafe {
        // Setup JVM and callback points to Simulator class

        ENV = Some(env);        

        let _jvm = ENV.as_ref().unwrap().get_java_vm().unwrap();

        CALLBACK = Some(ENV.as_ref().unwrap().new_global_ref(callback).unwrap());

        let mut connection = EmvConnection::new().unwrap();
        connection.interface = Some(ApduInterface::Function(java_card_apdu_interface));

        // Setup the PSE ICC data
        execute_setup_apdus(&mut connection, "../config/card_setup_pse_apdus.yaml").unwrap();

        let applications = connection.handle_select_payment_system_environment().unwrap();

        // Setup the app ICC data
        execute_setup_apdus(&mut connection, "../config/card_setup_app_apdus.yaml").unwrap();

        let application = &applications[0];
        connection.handle_select_payment_application(application).unwrap();

        connection.process_settings().unwrap();

        let search_tag = b"\x9f\x36";
        connection.handle_get_data(&search_tag[..]).unwrap();

        let data_authentication = connection.handle_get_processing_options().unwrap();

        let (issuer_pk_modulus, issuer_pk_exponent) = connection.get_issuer_public_key(application).unwrap();

        let tag_9f46_icc_pk_certificate = connection.get_tag_value("9F46").unwrap();
        let tag_9f47_icc_pk_exponent = connection.get_tag_value("9F47").unwrap();
        let tag_9f48_icc_pk_remainder = connection.get_tag_value("9F48");
        let (icc_pk_modulus, icc_pk_exponent) = connection.get_icc_public_key(
            tag_9f46_icc_pk_certificate, tag_9f47_icc_pk_exponent, tag_9f48_icc_pk_remainder,
            &issuer_pk_modulus[..], &issuer_pk_exponent[..],
            &data_authentication[..]).unwrap();

        connection.handle_dynamic_data_authentication(&icc_pk_modulus[..], &icc_pk_exponent[..]).unwrap();

        let ascii_pin = "1234".to_string();
        connection.handle_verify_plaintext_pin(ascii_pin.as_bytes()).unwrap();

        let icc_pin_pk_modulus = icc_pk_modulus.clone();
        let icc_pin_pk_exponent = icc_pk_exponent.clone();
        connection.handle_verify_enciphered_pin(ascii_pin.as_bytes(), &icc_pin_pk_modulus[..], &icc_pin_pk_exponent[..]).unwrap();

        // enciphered PIN OK
        connection.handle_generate_ac().unwrap();
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {}
}
