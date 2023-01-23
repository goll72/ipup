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

static void cache_change_cb(struct nl_cache *cache,
        struct nl_object *obj, int action, void *data)
{
    // Duplicate address, ignore
    if (action == NL_ACT_CHANGE)
        return;

    struct rtnl_addr *rtaddr = (struct rtnl_addr *)obj;

    struct nl_addr *nladdr = rtnl_addr_get_local(rtaddr);
    struct sockaddr *addr = (struct sockaddr *)&(struct sockaddr_storage){0};

    socklen_t len = sizeof(struct sockaddr_storage);
    nl_addr_fill_sockaddr(nladdr, addr, &len);

    int scope = rtnl_addr_get_scope(rtaddr);

    // We are only interested in global scope
    // addresses and we do not support IPv4
    if (scope != 0 || addr->sa_family == AF_INET)
        return;

    // Get the interface name to index the config map
    char ifbuf[IF_NAMESIZE] = {0};
    if_indextoname(rtnl_addr_get_ifindex(rtaddr), ifbuf);

    struct conf *confmap = data;
    ifconf_t *ifconf = map_get(confmap->ifaces, ifbuf, strlen(ifbuf));

    // Interface not listed
    if (!ifconf)
        return;

    const servconf_t *servconf = ifconf->server;

    bool delete = action == NL_ACT_DEL;
    bool verify = servconf->opts & CONF_OPT_SERVER_VERIFY_UPDATE;
    uint32_t ttl = ifconf->opts & CONF_OPT_IFACE_RESPECT_TTL
            ? rtnl_addr_get_valid_lifetime(rtaddr)
            : ifconf->ttl;

    char addrbuf[INET6_ADDRSTRLEN] = {0};
    nl_addr2str(nladdr, addrbuf, sizeof addrbuf);

    log(LOG_INFO, "%s address %s from %s", delete ? "Deleting" : "Updating", addrbuf, ifbuf);

    dns_do_update(servconf->resolv, ifconf->zone, ifconf->record,
            addr, delete, verify, ttl);
}

static volatile bool signaled = false;

static void sig_handle(int signo)
{
    (void)signo;
    signaled = true;
}

struct nl_cache_mngr *nl_run(struct conf *confmap) {
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

    ret = nl_cache_mngr_add_cache(nlmngr, cache, cache_change_cb, confmap);

    if (ret < 0)
        die(EX_SOFTWARE, "Failed to add cache to Netlink cache manager: %s", nl_geterror(ret));

    // Runs until an error occurs or the user requests termination
    while (1) {
        int ret = nl_cache_mngr_poll(nlmngr, -1);

        if (signaled)
            break;

        if (ret < 0)
            die(EX_OSERR, "Failed to poll on Netlink channel: %s", nl_geterror(ret));
    }

    return nlmngr;
}

void nl_free(struct nl_cache_mngr *nlmngr)
{
    nl_cache_mngr_free(nlmngr);
}
