use clap::{App, Arg};
use emvpt::*;
use hex;
use log::{debug, error, warn, LevelFilter};
use log4rs;
use log4rs::{
    append::console::ConsoleAppender,
    config::{Appender, Root},
};
use pcsc::{Card, Context, Protocols, Scope, ShareMode, MAX_ATR_SIZE, MAX_BUFFER_SIZE};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fs::{self};
use std::str;
use std::sync::Once;

static LOGGING: Once = Once::new();

pub enum ReaderError {
    ReaderConnectionFailed(String),
    ReaderNotFound,
    CardConnectionFailed(String),
    CardNotFound,
}

pub struct SmartCardConnection {
    ctx: Option<Context>,
    card: Option<Card>,
    pub contactless: bool,
}

impl ApduInterface for SmartCardConnection {
    fn send_apdu(&self, apdu: &[u8]) -> Result<Vec<u8>, ()> {
        let mut output: Vec<u8> = Vec::new();

        let mut apdu_response_buffer = [0; MAX_BUFFER_SIZE];
        output.extend_from_slice(
            self.card
                .as_ref()
                .unwrap()
                .transmit(apdu, &mut apdu_response_buffer)
                .unwrap(),
        );

        Ok(output)
    }
}

impl SmartCardConnection {
    pub fn new() -> SmartCardConnection {
        SmartCardConnection {
            ctx: None,
            card: None,
            contactless: false,
        }
    }

    fn is_contactless_reader(&self, reader_name: &str) -> bool {
        if Regex::new(r"^ACS ACR12").unwrap().is_match(reader_name) {
            debug!("Card reader is deemed contactless");
            return true;
        }

        false
    }

    pub fn connect_to_card(&mut self) -> Result<(), ReaderError> {
        if !self.ctx.is_some() {
            self.ctx = match Context::establish(Scope::User) {
                Ok(ctx) => Some(ctx),
                Err(err) => {
                    return Err(ReaderError::ReaderConnectionFailed(format!(
                        "Failed to establish context: {}",
                        err
                    )));
                }
            };
        }

        let ctx = self.ctx.as_ref().unwrap();
        let readers_size = match ctx.list_readers_len() {
            Ok(readers_size) => readers_size,
            Err(err) => {
                return Err(ReaderError::ReaderConnectionFailed(format!(
                    "Failed to list readers size: {}",
                    err
                )));
            }
        };

        let mut readers_buf = vec![0; readers_size];
        let readers = match ctx.list_readers(&mut readers_buf) {
            Ok(readers) => readers,
            Err(err) => {
                return Err(ReaderError::ReaderConnectionFailed(format!(
                    "Failed to list readers: {}",
                    err
                )));
            }
        };

        for reader in readers {
            self.card = match ctx.connect(reader, ShareMode::Shared, Protocols::ANY) {
                Ok(card) => {
                    self.contactless = self.is_contactless_reader(reader.to_str().unwrap());

                    debug!(
                        "Card reader: {:?}, contactless:{}",
                        reader, self.contactless
                    );

                    Some(card)
                }
                _ => None,
            };

            if self.card.is_some() {
                break;
            }
        }

        if self.card.is_some() {
            const MAX_NAME_SIZE: usize = 2048;
            let mut names_buffer = [0; MAX_NAME_SIZE];
            let mut atr_buffer = [0; MAX_ATR_SIZE];
            let card_status = self
                .card
                .as_ref()
                .unwrap()
                .status2(&mut names_buffer, &mut atr_buffer)
                .unwrap();

            // https://www.eftlab.com/knowledge-base/171-atr-list-full/
            debug!("Card ATR:\n{:?}", card_status.atr());
            debug!("Card protocol: {:?}", card_status.protocol2().unwrap());
        } else {
            return Err(ReaderError::CardNotFound);
        }

        Ok(())
    }
}

fn init_logging() {
    LOGGING.call_once(|| {
        //     log4rs::init_file("../config/log4rs.yaml", Default::default()).unwrap();

        let stdout: ConsoleAppender = ConsoleAppender::builder().build();
        let config = log4rs::config::Config::builder()
            .appender(Appender::builder().build("stdout", Box::new(stdout)))
            .build(Root::builder().appender("stdout").build(LevelFilter::Trace))
            .unwrap();
        log4rs::init_config(config).unwrap();
    });
}

#[derive(Serialize, Deserialize, Clone)]
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
                    "Response not what expected! expected:{:02X?}, actual:{:02X?}",
                    &response[..],
                    &response_trailer[..]
                ));
            }
        }

        Ok(())
    }
}

fn run() -> Result<Option<String>, String> {
    init_logging();

    // TODO: Card cloning utility
    // TODO: Easier way to setup fuzzing
    // TODO: Data log dumping

    let matches = App::new("Card tool")
        .version("0.1")
        .about("Card configuration utility belt")
        .arg(
            Arg::with_name("load")
                .long("load")
                .help("Sends APDU commands from file to card")
                .value_name("FILE")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("send-apdu")
                .long("send-apdu")
                .help("Sends hex string APDU command")
                .value_name("COMMAND")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("settings")
                .short("s")
                .long("settings")
                .value_name("settings file")
                .help("Settings file location")
                .takes_value(true),
        )
        .get_matches();

    let mut connection = EmvConnection::new(
        &matches
            .value_of("settings")
            .unwrap_or("../config/settings.yaml")
            .to_string(),
    )
    .unwrap();

    let mut smart_card_connection = SmartCardConnection::new();

    if let Err(err) = smart_card_connection.connect_to_card() {
        match err {
            ReaderError::CardNotFound => {
                return Err("Card not found.".to_string());
            }
            _ => return Err("Could not connect to the reader".to_string()),
        }
    }
    connection.interface = Some(&smart_card_connection);

    if matches.is_present("send-apdu") {
        let request =
            ApduRequestResponse::to_raw_vec(&matches.value_of("send-apdu").unwrap().to_string());

        connection.send_apdu(&request);

        return Ok(None);
    } else if matches.is_present("load") {
        ApduRequestResponse::execute_setup_apdus(
            &mut connection,
            matches.value_of("load").unwrap(),
        )
        .unwrap();

        return Ok(None);
    }

    Err("No action performed".to_string())
}

fn main() {
    std::process::exit(match run() {
        Ok(None) => 0,
        Ok(msg) => {
            warn!("{:?}", msg);
            0
        }
        Err(err) => {
            error!("{:?}", err);
            1
        }
    });
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {}
}
