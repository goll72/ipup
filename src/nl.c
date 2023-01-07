#include <err.h>

#include <netlink/cache.h>
#include <netlink/netlink.h>
#include <netlink/route/addr.h>

static void handler_nl_cache_change(struct nl_cache *cache,
        struct nl_object *obj, int action, void *data)
{
    struct rtnl_addr *addr = (struct rtnl_addr *)obj;

    nl_object_dump(obj, &(struct nl_dump_params) {
        .dp_type = NL_DUMP_LINE,
        .dp_fd = stdout
    });
}

struct nl_cache_mngr *nl_init(void) {
    int ret;

    struct nl_cache_mngr *nl_mngr;
    ret = nl_cache_mngr_alloc(NULL, NETLINK_ROUTE, NL_AUTO_PROVIDE, &nl_mngr);

    if (ret < 0)
        errx(2, "Failed to set up Netlink cache manager: %s", nl_geterror(ret));

    struct nl_cache *cache;
    ret = rtnl_addr_alloc_cache(NULL, &cache);

    if (ret < 0)
        errx(2, "Failed to allocate Netlink address cache: %s", nl_geterror(ret));

    ret = nl_cache_mngr_add_cache(nl_mngr, cache, handler_nl_cache_change, NULL);

    if (ret < 0)
        errx(2, "Failed to add cache to Netlink cache manager: %s", nl_geterror(ret));

    /* while (1) {
        ret = nl_cache_mngr_data_ready(nl_mngr);
        if (ret < 0)
            errx(2, "Failed to listen for events on Netlink channel: %s", nl_geterror(ret));
    } */

    return nl_mngr;
}
