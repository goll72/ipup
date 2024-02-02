#include <signal.h>
#include <net/if.h>
#include <arpa/inet.h>

#include <netlink/cache.h>
#include <netlink/netlink.h>
#include <netlink/route/addr.h>

#include "log.h"
#include "dns.h"
#include "map.h"
#include "conf.h"

map_decl(conf_if, uint64_t, const char *, conf_if *);
map_decl(serv_rr, uintptr_t, conf_if *, ldns_rr_list *);

struct rtnl_addr_prop {
    struct nl_addr *nladdr;
    struct sockaddr_storage addr;
    socklen_t addrlen;
    int scope, ifidx, validlft;
};

static void rtnl_addr_get_prop(struct nl_object *obj, struct rtnl_addr_prop *prop)
{
    struct rtnl_addr *rtaddr = (struct rtnl_addr *)obj;
    prop->nladdr = rtnl_addr_get_local(rtaddr);

    prop->addrlen = sizeof prop->addr;
    nl_addr_fill_sockaddr(prop->nladdr, (struct sockaddr *)&prop->addr, &prop->addrlen);

    prop->scope = rtnl_addr_get_scope(rtaddr);
    prop->ifidx = rtnl_addr_get_ifindex(rtaddr);
    prop->validlft = rtnl_addr_get_valid_lifetime(rtaddr);
}

static void nl_dns_do_update(struct rtnl_addr_prop *prop, struct conf *conf, bool delete)
{
    // Get the interface name to index the config map
    char ifbuf[IF_NAMESIZE] = {0};
    if_indextoname(prop->ifidx, ifbuf);

    conf_if *ifconf;

    // Interface not listed
    if (!map_get_conf_if(conf->ifaces, ifbuf, &ifconf))
        return;

    const conf_serv *servconf = ifconf->server;
    struct sockaddr *addr = (struct sockaddr *)&prop->addr;

    uint32_t ttl = ifconf->opts & CONF_OPT_IFACE_RESPECT_TTL
            ? prop->validlft : ifconf->ttl;

    char addrbuf[INET6_ADDRSTRLEN] = {0};
    nl_addr2str(prop->nladdr, addrbuf, sizeof addrbuf);

    log(LOG_INFO, "%s address %s from %s", delete ? "Deleting" : "Updating", addrbuf, ifbuf);

    dns_do_update(servconf->resolv, ifconf->zone, ifconf->record, addr, delete, ttl);
}

static void cache_change_cb(struct nl_cache *cache,
        struct nl_object *obj, int action, void *arg)
{
    // Duplicate address, ignore
    if (action == NL_ACT_CHANGE)
        return;

    struct rtnl_addr_prop prop;
    rtnl_addr_get_prop(obj, &prop);

    struct conf *conf = arg;
    struct sockaddr *addr = (struct sockaddr *)&prop.addr;

    // We are only interested in global scope
    // addresses and we do not support IPv4
    if (prop.scope != 0 || addr->sa_family == AF_INET)
        return;

    nl_dns_do_update(&prop, conf, action == NL_ACT_DEL);
}

static ldns_rr_list *diff_addr_get_rr_list(map(serv_rr) *servrrlist, conf_if *ifconf)
{
    ldns_rr_list *ansrrlist = NULL;

    if (!map_get_serv_rr(servrrlist, ifconf, &ansrrlist)) {
        ldns_pkt *anspkt;
        ldns_status ret = ldns_resolver_query_status(&anspkt, ifconf->server->resolv,
                ifconf->record, LDNS_RR_TYPE_AAAA, LDNS_RR_CLASS_IN, 0);

        if (ret != LDNS_STATUS_OK) {
            log(LOG_WARNING, "Failed to query DNS server: %s", ldns_get_errorstr_by_id(ret));
            goto fail;
        }

        ldns_pkt_rcode rcode = ldns_pkt_get_rcode(anspkt);

        if (rcode != LDNS_RCODE_NOERROR) {
            log(LOG_WARNING, "Failed to query DNS server: %s", dns_get_errorstr_by_rcode(rcode));
            goto fail;
        }

        if (ldns_pkt_ancount(anspkt) == 0)
            goto fail;

        ansrrlist = ldns_rr_list_clone(ldns_pkt_answer(anspkt));
        map_set_serv_rr(servrrlist, ifconf, ansrrlist);

fail:
        ldns_pkt_free(anspkt);
    }

    return ansrrlist;
}

// Diff the host address table against the DNS records,
// mark the host addreses that are present in a DNS record
static bool diff_addr_ifconf(const char *key, conf_if *ifconf, void *arg)
{
    struct nl_cache *addrcache = nl_cache_mngt_require("route/addr");

    map(serv_rr) *servrrlist = arg;

    struct nl_object *obj = nl_cache_get_first(addrcache);
    struct nl_object *next;

    if (!obj)
        return false;

    int ifidx = if_nametoindex(key);

    // XXX: Inefficient?
    do {
        next = nl_cache_get_next(obj);

        struct rtnl_addr_prop prop;
        rtnl_addr_get_prop(obj, &prop);

        struct sockaddr *addr = (struct sockaddr *)&prop.addr;

        // Remove useless entries
        if (prop.scope != 0 || addr->sa_family == AF_INET) {
            nl_cache_remove(obj);
            continue;
        }

        if (ifidx != prop.ifidx)
            continue;

        // Memoize DNS query result in hashmap
        ldns_rr_list *ansrrlist = diff_addr_get_rr_list(servrrlist, ifconf);
        ldns_rdf *hostrdf = ldns_sockaddr_storage2rdf((struct sockaddr_storage *)addr, NULL);
        size_t ansrrcount = ldns_rr_list_rr_count(ansrrlist);

        // Remove from list if address is present in the host address table, and
        // mark it in the host address table
        for (size_t i = 0; i < ansrrcount; i++) {
            ldns_rr *rr = ldns_rr_list_rr(ansrrlist, i);
            ldns_rdf *tmp = ldns_rr_a_address(rr);

            if (ldns_rdf_compare(hostrdf, tmp) == 0) {
                ldns_rr_free(rr);

                nl_object_mark(obj);

                for (size_t j = i; j < ansrrcount - 1; j++) {
                    ldns_rr *tmprr = ldns_rr_list_rr(ansrrlist, j + 1);
                    ldns_rr_list_set_rr(ansrrlist, tmprr, j);
                }

                ansrrcount--;
                ldns_rr_list_set_rr_count(ansrrlist, ansrrcount);

                break;
            }
        }

        ldns_rdf_deep_free(hostrdf);
    } while ((obj = next));

    return true;
}

static bool sync_addr_del(conf_if *key, ldns_rr_list *delrrs, void *arg)
{
    if (!(key->opts & CONF_OPT_IFACE_DELETE_EXISTING))
        return true;

    size_t delrrcount = ldns_rr_list_rr_count(delrrs);

    if (delrrcount == 0)
        return true;

    for (size_t i = 0; i < delrrcount; i++) {
        ldns_rr *rr = ldns_rr_list_rr(delrrs, i);

        ldns_rr_set_class(rr, LDNS_RR_CLASS_NONE);
        ldns_rr_set_ttl(rr, 0);
    }

    dns_send_update(key->zone, delrrs, key->server->resolv);

    return true;
}

static void sync_addr_upd(struct nl_object *obj, void *arg)
{
    if (nl_object_is_marked(obj))
        return;

    struct rtnl_addr_prop prop;
    rtnl_addr_get_prop(obj, &prop);

    struct conf *conf = arg;

    nl_dns_do_update(&prop, conf, false);
}

static volatile bool signaled = false;

static void sig_handle(int signo)
{
    (void)signo;
    signaled = true;
}

static struct nl_cache_mngr *nl_setup(struct conf *conf)
{
    struct sigaction sa = {
        .sa_handler = sig_handle,
        .sa_flags = SA_RESETHAND
    };

    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    int ret;

    struct nl_cache_mngr *nlmngr;
    ret = nl_cache_mngr_alloc(NULL, NETLINK_ROUTE, NL_AUTO_PROVIDE, &nlmngr);

    if (ret < 0)
        die(EX_SOFTWARE, "Failed to set up Netlink cache manager: %s", nl_geterror(ret));

    struct nl_cache *cache;
    ret = rtnl_addr_alloc_cache(NULL, &cache);

    if (ret < 0)
        die(EX_SOFTWARE, "Failed to allocate Netlink address cache: %s", nl_geterror(ret));

    ret = nl_cache_mngr_add_cache(nlmngr, cache, cache_change_cb, conf);

    if (ret < 0)
        die(EX_SOFTWARE, "Failed to add cache to Netlink cache manager: %s", nl_geterror(ret));

    return nlmngr;
}

struct nl_cache_mngr *nl_sync(struct conf *conf)
{
    struct nl_cache_mngr *nlmngr = nl_setup(conf);

    map_ops(serv_rr) ops = {
        .val_free = ldns_rr_list_deep_free
    };

    map(serv_rr) *servrrlist = map_new_serv_rr(4, ops);

    // Store the addresses returned for each DNS record, then remove each record that is
    // present on the host address table from the list, for each interface. Additionally, mark
    // the host addresses that have corresponding DNS records. At the end, issue UPDATE queries to
    // delete all addresses that are still in the list (that is, that do not match any interfaces),
    // but only if the user has enabled `delete-existing`.
    map_foreach_conf_if(conf->ifaces, diff_addr_ifconf, servrrlist);
    map_foreach_serv_rr(servrrlist, sync_addr_del, NULL);

    // Send UPDATE queries for all entries in the address table that haven't been marked
    nl_cache_foreach(nl_cache_mngt_require("route/addr"), sync_addr_upd, conf);

    map_free_serv_rr(servrrlist);

    return nlmngr;
}

void nl_run(struct nl_cache_mngr *nlmngr)
{
    // Runs until an error occurs or the user requests termination
    while (1) {
        int ret = nl_cache_mngr_poll(nlmngr, -1);

        if (signaled)
            break;

        if (ret < 0)
            die(EX_OSERR, "Failed to poll on Netlink channel: %s", nl_geterror(ret));
    }
}

void nl_free(struct nl_cache_mngr *nlmngr)
{
    nl_cache_mngr_free(nlmngr);
}
