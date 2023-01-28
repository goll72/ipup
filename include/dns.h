#ifndef DNS_H
#define DNS_H

#include <ldns/ldns.h>

ldns_resolver *dns_sys_resolver(void);
void dns_free_sys_resolver(void);

const char *dns_get_errorstr_by_rcode(ldns_pkt_rcode rcode);

ldns_resolver *dns_resolver_init_frm_dname(ldns_resolver *resolv, ldns_rdf *server);

ldns_status dns_tsig_credentials_validate(ldns_tsig_credentials cred);
void dns_resolver_set_tsig_credentials(ldns_resolver *resolv, ldns_tsig_credentials cred);

void dns_send_update(ldns_rdf *zone, ldns_rr_list *uprrlist, ldns_resolver *resolv);
void dns_do_update(ldns_resolver *resolv, ldns_rdf *zone, ldns_rdf *record,
        const struct sockaddr *addr, bool delete, uint32_t ttl);

#endif /* DNS_H */
