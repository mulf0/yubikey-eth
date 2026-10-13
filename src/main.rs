pub mod constants;

use ctap_hid_fido2::{
    Cfg, FidoKeyHid, FidoKeyHidFactory,
    fidokey::{
        AssertionExtension as Gext, CredentialExtension as Mext, CredentialSupportedKeyType,
        GetAssertionArgsBuilder, MakeCredentialArgsBuilder, get_info::InfoOption,
    },
    get_fidokey_devices, util, verifier,
};

fn main() {
    let mut cfg = Cfg::init();
    let device = FidoKeyHidFactory::create(&cfg).unwrap();
    println!("Setup Started");

    println!("Select pin");
    let mut pin = String::new();
    std::io::stdin().read_line(&mut pin).ok();
    pin = pin.trim().to_string();
    device.set_new_pin(&pin);

    let challenge = verifier::create_challenge();
    let ext = Mext::HmacSecret(Some(true));

    let make_credential_args = MakeCredentialArgsBuilder::new(constants::rpid, &challenge)
        .pin(&pin)
        .resident_key()
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
    let verify_result = verifier::verify_attestation(constants::rpid, &challenge, &attestation);
    if verify_result.is_success {
        println!("-- Verify Attestation Success");
    } else {
        println!("-- ! Verify Attestation Failed");
    }

    println!("- Authenticate");
    let challenge = verifier::create_challenge();

    // Create a HMCSecret2 with two specified salts.
    let ext =
        Gext::create_hmac_secret_2_from_string(constants::hmac_salt_1, constants::hmac_salt_2);

    let get_assertion_args = GetAssertionArgsBuilder::new(constants::rpid, &challenge)
        .pin(pin.as_str())
        .extensions(&[ext])
        .build();

    let assertions = device.get_assertion_with_args(&get_assertion_args).unwrap();
    println!("-- Authenticate Success");

    let find = assertions[0]
        .extensions
        .iter()
        .find(|it| matches!(it, Gext::HmacSecret2(_)));
    if let Some(Gext::HmacSecret2(hmac_secret)) = find {
        let (res1, res2) = hmac_secret.as_ref().unwrap();
        println!("--- HMAC Secret 1 = {}", util::to_hex_str(res1));
        println!("--- HMAC Secret 2 = {}", util::to_hex_str(res2));
    } else {
        println!("--- HMAC Secret 2 Not Found");
    }
    println!("Assertion");
    println!("{}", assertions[0]);

    println!("-- Verify Assertion");
    let is_success = verifier::verify_assertion(
        constants::rpid,
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
