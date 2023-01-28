#include <ctype.h>
#include <sysexits.h>

#include "log.h"
#include "dns.h"

static ldns_resolver *sysresolv = NULL;

ldns_resolver *dns_sys_resolver(void)
{
    if (sysresolv)
        return sysresolv;

    // Reads from /etc/resolv.conf by default
    ldns_status ret = ldns_resolver_new_frm_file(&sysresolv, NULL);

    if (ret != LDNS_STATUS_OK)
        die(EX_OSFILE, "Failed to create stub resolver from /etc/resolv.conf: %s",
                ldns_get_errorstr_by_id(ret));

    return sysresolv;
}

void dns_free_sys_resolver(void)
{
    ldns_resolver_deep_free(sysresolv);
}

const char *dns_get_errorstr_by_rcode(ldns_pkt_rcode rcode)
{
    switch (rcode) {
        case LDNS_RCODE_NOERROR:
            return "Update successful";
        case LDNS_RCODE_FORMERR:
            return "Format error";
        case LDNS_RCODE_SERVFAIL:
            return "Internal server error";
        case LDNS_RCODE_NXDOMAIN:
            return "Domain does not exist";
        case LDNS_RCODE_NOTIMPL:
            return "DNS UPDATE not implemented by server";
        case LDNS_RCODE_REFUSED:
            return "Server refused request, check its security policy";
        case LDNS_RCODE_YXDOMAIN:
            return "Domain exists";
        case LDNS_RCODE_YXRRSET:
            return "RRset exists";
        case LDNS_RCODE_NXRRSET:
            return "RRset does not exist";
        case LDNS_RCODE_NOTAUTH:
            return "Server is not authoritative for zone";
        case LDNS_RCODE_NOTZONE:
            return "Record to be updated not in specified zone";
    }
}

ldns_resolver *dns_resolver_init_frm_dname(ldns_resolver *resolv, ldns_rdf *server)
{
    ldns_pkt *anspkt_aaaa = NULL, *anspkt_a = NULL;

    ldns_status ret_aaaa = ldns_resolver_query_status(&anspkt_aaaa, dns_sys_resolver(), server,
            LDNS_RR_TYPE_AAAA, LDNS_RR_CLASS_IN, LDNS_RD);

    ldns_status ret_a = ldns_resolver_query_status(&anspkt_a, dns_sys_resolver(), server,
            LDNS_RR_TYPE_A, LDNS_RR_CLASS_IN, LDNS_RD);

    if (ret_aaaa != LDNS_STATUS_OK && ret_a != LDNS_STATUS_OK) {
        log(LOG_WARNING, "Failed to query DNS server");
        goto fail;
    }

    if (ldns_pkt_ancount(anspkt_a) == 0 && ldns_pkt_ancount(anspkt_aaaa) == 0) {
        log(LOG_WARNING, "Got no answer from DNS server");
        goto fail;
    }

    ret_aaaa = ldns_resolver_push_nameserver_rr_list(resolv, ldns_pkt_answer(anspkt_aaaa));
    ret_a = ldns_resolver_push_nameserver_rr_list(resolv, ldns_pkt_answer(anspkt_a));

    if (ret_aaaa != LDNS_STATUS_OK && ret_a != LDNS_STATUS_OK) {
        log(LOG_WARNING, "Failed to store nameservers from query answer");
        goto fail;
    }

fail:
    ldns_pkt_free(anspkt_aaaa);
    ldns_pkt_free(anspkt_a);

    return resolv;
}

ldns_status dns_tsig_credentials_validate(ldns_tsig_credentials cred)
{
    if (cred.algorithm && cred.keyname && cred.keydata) {
        size_t b64enclen = strlen(cred.keydata);
        size_t b64pad = 0;

        if (b64enclen % 4 != 0)
            return LDNS_STATUS_INVALID_B64;

        if (cred.keydata[b64enclen - b64pad - 1] == '=')
            b64pad++;
        if (cred.keydata[b64enclen - b64pad - 1] == '=')
            b64pad++;

        for (size_t i = 0; i < b64enclen - b64pad; i++) {
            if (!isupper(cred.keydata[i]) &&
                    !islower(cred.keydata[i]) &&
                    !isdigit(cred.keydata[i]) &&
                     cred.keydata[i] != '+' && cred.keydata[i] != '/')
                return LDNS_STATUS_INVALID_B64;
        }

        return LDNS_STATUS_OK;
    } else if (cred.algorithm || cred.keyname || cred.keydata) {
        return LDNS_STATUS_CRYPTO_TSIG_BOGUS;
    } else {
        return LDNS_STATUS_NO_DATA;
    }
}

void dns_resolver_set_tsig_credentials(ldns_resolver *resolv, ldns_tsig_credentials cred)
{
    ldns_resolver_set_tsig_algorithm(resolv, cred.algorithm);
    ldns_resolver_set_tsig_keyname(resolv, cred.keyname);
    ldns_resolver_set_tsig_keydata(resolv, cred.keydata);
}

static ldns_rr *dns_prepare_update_rr(ldns_rdf *record,
        const struct sockaddr *addr, bool delete, uint32_t ttl)
{
    ldns_rdf *rd = ldns_sockaddr_storage2rdf((struct sockaddr_storage *)addr, NULL);
    ldns_rr *updrr = ldns_rr_new();

    // TTL = 0 means to delete the record
    if (delete)
        ldns_rr_set_ttl(updrr, 0);
    else if (ttl != 0)
        ldns_rr_set_ttl(updrr, ttl);

    ldns_rr_set_owner(updrr, ldns_rdf_clone(record));
    ldns_rr_set_class(updrr, delete ? LDNS_RR_CLASS_NONE : LDNS_RR_CLASS_IN);

    if (addr->sa_family == AF_INET)
        ldns_rr_set_type(updrr, LDNS_RR_TYPE_A);
    else if (addr->sa_family == AF_INET6)
        ldns_rr_set_type(updrr, LDNS_RR_TYPE_AAAA);

    if (!ldns_rr_push_rdf(updrr, rd))
        die(EX_SOFTWARE, "Failed to allocate memory");

    return updrr;
}

void dns_send_update(ldns_rdf *zone, ldns_rr_list *updrrlist, ldns_resolver *resolv)
{
    ldns_status ret;

    ldns_pkt *updanspkt = NULL;
    ldns_pkt *updpkt = ldns_update_pkt_new(ldns_rdf_clone(zone), LDNS_RR_CLASS_IN, NULL, updrrlist, NULL);

    ret = ldns_update_pkt_tsig_add(updpkt, resolv);

    if (ret != LDNS_STATUS_OK) {
        log(LOG_WARNING, "Failed to sign packet with TSIG key: %s", ldns_get_errorstr_by_id(ret));
        goto fail;
    }

    ret = ldns_resolver_send_pkt(&updanspkt, resolv, updpkt);

    ldns_pkt_rcode rcode = ldns_pkt_get_rcode(updanspkt);

    if (ret == LDNS_STATUS_OK && rcode != LDNS_RCODE_NOERROR) {
        log(LOG_WARNING, "Failed to query DNS server: %s", dns_get_errorstr_by_rcode(rcode));
    } else if (ret != LDNS_STATUS_OK) {
        log(LOG_WARNING, "Failed to query DNS server: %s", ldns_get_errorstr_by_id(ret));
    }

fail:
    ldns_pkt_free(updanspkt);
    ldns_pkt_free(updpkt);
}

void dns_do_update(ldns_resolver *resolv, ldns_rdf *zone, ldns_rdf *record,
        const struct sockaddr *addr, bool delete, uint32_t ttl)
{
    ldns_rr *updrr = dns_prepare_update_rr(record, addr, delete, ttl);
    ldns_rr_list *updrrlist = ldns_rr_list_new();

    if (!ldns_rr_list_push_rr(updrrlist, updrr))
        die(EX_SOFTWARE, "Failed to allocate memory");

    dns_send_update(zone, updrrlist, resolv);

    ldns_rr_list_deep_free(updrrlist);
}
