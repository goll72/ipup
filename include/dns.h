#ifndef DNS_H
#define DNS_H

#include <ldns/ldns.h>

ldns_resolver *dns_sys_resolver(void);
void dns_free_sys_resolver(void);

ldns_resolver *dns_resolver_init_frm_dname(ldns_resolver *resolv, ldns_rdf *server);

ldns_status dns_tsig_credentials_validate(ldns_tsig_credentials cred);
void dns_resolver_set_tsig_credentials(ldns_resolver *resolv, ldns_tsig_credentials cred);

void dns_do_update(ldns_resolver *resolv, ldns_rdf *zone, ldns_rdf *record,
        int af, const void *addr, bool delete, uint32_t ttl);

#endif /* DNS_H */
