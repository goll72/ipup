#include "common.h"

#include "dns.c"

Test(dns, valid_tsig_key_is_valid) {
    ldns_tsig_credentials cred = {0};

    expect(eq(dns_tsig_credentials_validate(cred), (ldns_status)LDNS_STATUS_NO_DATA));

    cred.algorithm = cred.keyname = "";
    cred.keydata = "naeaKJeq2Wum2TLUIYRBS7WTcpg0gCUs1hsJoGp3gS4ay9E/dfu6jQLYS9xMr9moeclYYfvOV9W461vIFbXzWQ==";

    expect(eq(dns_tsig_credentials_validate(cred), (ldns_status)LDNS_STATUS_OK));
}

Test(dns, invalid_tsig_key_is_invalid) {
    ldns_tsig_credentials cred = {0};
    cred.algorithm = cred.keyname = "";

    cr_expect(eq(dns_tsig_credentials_validate(cred), (ldns_status)LDNS_STATUS_CRYPTO_TSIG_BOGUS),
            "No key secret considered valid");

    cred.keydata = "iGXtbyFjER0R4XS3===";

    cr_expect(eq(dns_tsig_credentials_validate(cred), (ldns_status)LDNS_STATUS_INVALID_B64),
            "Key with excess padding considered valid");

    cred.keydata = "IAnfWadwM+DE8pwoIQPIAQ";

    cr_expect(eq(dns_tsig_credentials_validate(cred), (ldns_status)LDNS_STATUS_INVALID_B64),
            "Key with no padding considered valid");
}
