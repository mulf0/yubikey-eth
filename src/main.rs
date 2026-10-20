pub mod constants;

use ctap_hid_fido2::{
    Cfg, FidoKeyHidFactory,
    fidokey::{
        AssertionExtension as Gext, CredentialExtension as Mext, GetAssertionArgsBuilder,
        MakeCredentialArgsBuilder, get_info::InfoOption,
    },
    public_key_credential_user_entity::PublicKeyCredentialUserEntity,
    util, verifier,
};

fn main() {
    let cfg = Cfg::init();
    let device = FidoKeyHidFactory::create(&cfg).unwrap();

    let device_info = device.get_info();
    let mut pin_set = false;

    if let Ok(info) = device_info {
        for (name, enabled) in &info.options {
            if name == "clientPin" && *enabled == true {
                pin_set = true;
            }
        }
    }

    let mut pk_id: Vec<u8> = vec![0u8; 8];

    rand::fill(&mut pk_id);

    println!("{:?}", pk_id);

    let user_metadata = PublicKeyCredentialUserEntity {
        id: pk_id,
        name: String::from("Username"),
        display_name: String::from("Display name"),
    };

    let mut pin = String::new();

    if pin_set == false {
        println!("Please set a pin for your device");
        std::io::stdin()
            .read_line(&mut pin)
            .expect("Could not process input");

        pin = pin.trim().to_string();
        let set_new_pin = device
            .set_new_pin(&pin)
            .expect("Could not set pin, please try again");
    } else {
        println!("Enter your pin");
        std::io::stdin()
            .read_line(&mut pin)
            .expect("Could not process input");

        pin = pin.trim().to_string();
    }

    let rp_ids = device.credential_management_enumerate_rps(Some(&pin));
    if let Ok(rps) = rp_ids {
        println!("{:?}", rps);
    }

    let challenge = verifier::create_challenge();
    let ext = Mext::HmacSecret(Some(true));

    let make_credential_args = MakeCredentialArgsBuilder::new(constants::RPID, &challenge)
        .pin(&pin)
        .resident_key()
        .user_entity(&user_metadata)
        .extensions(&[ext])
        .build();

    let attestation = device
        .make_credential_with_args(&make_credential_args)
        .unwrap();
    println!("-- Register Success");

    let find = attestation
        .extensions
        .iter()
        .find(|it| matches!(it, Mext::HmacSecret(_)));

    if let Some(Mext::HmacSecret(is_hmac_secret)) = find {
        println!("--- HMAC Secret = {:?}", is_hmac_secret.unwrap());
    } else {
        println!("--- HMAC Secret Not Found");
    }

    println!("Attestation");
    println!("{}", attestation);
    println!("-- Verify Attestation");

    let verify_result = verifier::verify_attestation(constants::RPID, &challenge, &attestation);

    if verify_result.is_success {
        println!("-- Verify Attestation Success");
    } else {
        println!("-- ! Verify Attestation Failed");
    }

    println!("- Authenticate");
    let challenge = verifier::create_challenge();

    let ext = Gext::create_hmac_secret_from_string(constants::HMAC_SALT);

    let get_assertion_args = GetAssertionArgsBuilder::new(constants::RPID, &challenge)
        .pin(pin.as_str())
        .extensions(&[ext])
        .build();

    let mut assertions = device
        .get_assertion_with_args(&get_assertion_args)
        .expect("Could not get assertions");

    println!("{:?}", assertions);

    println!("-- Authenticate Success");

    let find = assertions[0]
        .extensions
        .iter()
        .find(|it| matches!(it, Gext::HmacSecret2(_)));

    if let Some(Gext::HmacSecret(hmac_secret)) = find {
        let res = hmac_secret.as_ref().unwrap();
        println!("--- HMAC Secret = {}", util::to_hex_str(res));
    } else {
        println!("--- HMAC Secret 2 Not Found");
    }
    println!("Assertion");
    println!("{}", assertions[0]);

    println!("-- Verify Assertion");
    let is_success = verifier::verify_assertion(
        constants::RPID,
        &verify_result.credential_public_key,
        &challenge,
        &assertions[0],
    );
    if is_success {
        println!("-- Verify Assertion Success");
    } else {
        println!("-- ! Verify Assertion Failed");
    }

    println!();
}
