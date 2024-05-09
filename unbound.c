/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2018 - 2024 Michael Ortmann */

#define MODULE_NAME "unbound"

#include <unbound.h>
#include "src/mod/module.h"

/* https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml */
#define RR_CLASS_IN  1  /* Internet (IN)         */
#define RR_TYPE_A    1  /* A host address        */
#define RR_TYPE_PTR  12 /* A domain name pointer */
#define RR_TYPE_AAAA 28 /* IP6 Address           */

static Function *global = NULL;

static struct ub_ctx* ctx;
static int idx, fd, count_hostbyip_successfully = 0,
           count_hostbyip_unsuccessfully = 0, count_ipbyhost_successfully = 0,
           count_ipbyhost_unsuccessfully = 0;

static void unbound_resolve(char *, int, void *);

static void unbound_callback(void *mydata, int err, struct ub_result* result)
{
  sockname_t sockname = {0};
  char name[128], *ip = (char *) mydata, *name2, *c;
  int l;

  putlog(LOG_MISC, "*", "Unbound: callback.");
  if(err) {
    putlog(LOG_MISC, "*", "Unbound error: %s", ub_strerror(err));
    ub_resolve_free(result);
    return;
  }
  if(result->havedata) {
    if (result->qtype == RR_TYPE_A) {
      putlog(LOG_MISC, "*", "Unbound: The ip4 of host %s is %s.",
             result->qname, inet_ntop(AF_INET, result->data[0], name, INET_ADDRSTRLEN));
      sockname.family = AF_INET;
      sockname.addrlen = sizeof(struct sockaddr_in);
      memcpy(&sockname.addr.s4.sin_addr, result->data[0], 4);
      sockname.addr.sa.sa_family = sockname.family;
      call_ipbyhost(result->qname, &sockname, 1);
      count_ipbyhost_successfully++;
    }
#ifdef IPV6
    else if (result->qtype == RR_TYPE_AAAA) {
      putlog(LOG_MISC, "*", "Unbound: The ip6 of host %s is %s.",
             result->qname, inet_ntop(AF_INET6, result->data[0], name, INET6_ADDRSTRLEN));
      sockname.family = AF_INET6;
      sockname.addrlen = sizeof(struct sockaddr_in6);
      memcpy(&sockname.addr.s6.sin6_addr, result->data[0], 16);
      sockname.addr.sa.sa_family = sockname.family;
      call_ipbyhost(result->qname, &sockname, 1);
      count_ipbyhost_successfully++;
    } 
#endif
    else if (result->qtype == RR_TYPE_PTR) {
      name2 = result->data[0];

      /* decode "<len 1><data 1>...<len n><data n>" to "<data1>...<.><data n>"
       * example: "\006edward\008eggheads\003org" -> "edward.eggheads.org"
       */
      if (*name2) {
        c = name2 + *name2 + 1;
        name2++;
        while (*c) {
          l = *c;
          *c = '.';
          c += l + 1;
        }
      }

      putlog(LOG_MISC, "*", "Unbound: The host of ip %s is %s.", ip, name2);
      sockname.family = AF_INET;
      sockname.addrlen = sizeof(struct sockaddr_in);
      inet_pton(sockname.family, ip, &sockname.addr.s4.sin_addr);
      sockname.addr.sa.sa_family = sockname.family;
      call_hostbyip(&sockname, name2, 1);
      count_hostbyip_successfully++;
      nfree(ip);
    }
  } else {
    if (result->qtype == RR_TYPE_A) {
      putlog(LOG_MISC, "*", "Unbound: No ip4 of host %s.", result->qname);
#ifdef IPV6
      if (!pref_af)
        unbound_resolve(result->qname, RR_TYPE_AAAA, NULL);
      else {
#endif
      call_ipbyhost(result->qname, &sockname, 0);
      count_ipbyhost_unsuccessfully++;
#ifdef IPV6
      }
#endif
    }
#ifdef IPV6
    else if (result->qtype == RR_TYPE_AAAA) {
      putlog(LOG_MISC, "*", "Unbound: No ip6 of host %s.", result->qname);
      if (pref_af)
        unbound_resolve(result->qname, RR_TYPE_A, NULL);
      else {
        call_ipbyhost(result->qname, &sockname, 0);
        count_ipbyhost_unsuccessfully++;
      }
    }
#endif
    else if (result->qtype == RR_TYPE_PTR) {
      putlog(LOG_MISC, "*", "Unbound: No host of ip %s.", ip);
      sockname.family = AF_INET;
      sockname.addrlen = sizeof(struct sockaddr_in);
      inet_pton(sockname.family, ip, &sockname.addr.s4.sin_addr);
      sockname.addr.sa.sa_family = sockname.family;
      call_hostbyip(&sockname, ip, 0);
      count_hostbyip_unsuccessfully++;
    }
  }
  ub_resolve_free(result);
}

/* Put ip4 into reverse lookup format */
static void ip4(char *name, const struct in_addr *addr, size_t namesize)
{
  snprintf(name, namesize, "%u.%u.%u.%u.in-addr.arpa",
           ((uint8_t *) addr)[3],
           ((uint8_t *) addr)[2],
           ((uint8_t *) addr)[1],
           ((uint8_t *) addr)[0]);
}

/* Put ip6 into reverse lookup format */
#ifdef IPV6
static void ip6(char *name, const struct in6_addr *addr, size_t namesize)
{
  const char* hex = "0123456789abcdef";
  char *p;
  int i;

  p = name;
  for (i = 15; i >= 0; i--) {
    uint8_t b = ((uint8_t *) addr)[i];
    *p++ = hex[(b & 0x0f)];
    *p++ = '.';
    *p++ = hex[(b & 0xf0) >> 4];
    *p++ = '.';
  }
  snprintf(name + 16 * 4, namesize - 16 * 4, "ip6.arpa");
}
#endif

static void unbound_resolve(char *name, int rrtype, void *mydata)
{
  int retval;

  putlog(LOG_MISC, "*", "Unbound: resolve name %s rrtype %i.", name, rrtype);
  retval = ub_resolve_async(ctx, name, rrtype, RR_CLASS_IN, mydata, unbound_callback, NULL);
  if (retval)
    putlog(LOG_MISC, "*", "Unbound error: %s", ub_strerror(retval));
}

static void unbound_hostbyip(sockname_t *addr)
{
  char name[16 * 4 + sizeof "ip6.arpa"];
  char *ip = iptostr(&addr->addr.sa), *ipx;
  size_t len;

#ifdef IPV6
  if (addr->family == AF_INET6)
    ip6(name, &addr->addr.s6.sin6_addr, sizeof name);
  else
#endif
    ip4(name, &addr->addr.s4.sin_addr, sizeof name);
  len = strlen(ip) + 1;
  ipx = nmalloc(len);
  memcpy(ipx, ip, len);
  unbound_resolve(name, RR_TYPE_PTR, ipx);
}

static void unbound_ipbyhost(char *name)
{
  sockname_t sockname;

  /* if name is ip instead of host */
  if (setsockname(&sockname, name, 0, 0) != AF_UNSPEC) {
    call_ipbyhost(name, &sockname, 1);
    return;
  }

#ifdef IPV6
  if (pref_af)
    unbound_resolve(name, RR_TYPE_AAAA, NULL);
  else
#endif
  unbound_resolve(name, RR_TYPE_A, NULL);
}

static void unbound_report(int idx, int details)
{
  if (details) {
    dprintf(idx, "    unbound version: %s (header version %i.%i.%i)\n", ub_version(),
            UNBOUND_VERSION_MAJOR, UNBOUND_VERSION_MINOR, UNBOUND_VERSION_MICRO);
    dprintf(idx, "    %i hostbyip resolved successfully\n", count_hostbyip_successfully);
    dprintf(idx, "    %i hostbyip resolved unsuccessfully\n", count_hostbyip_unsuccessfully);
    dprintf(idx, "    %i ipbyhost resolved successfully\n", count_ipbyhost_successfully);
    dprintf(idx, "    %i ipbyhost resolved unsuccessfully\n", count_ipbyhost_unsuccessfully);
  }
}

static char *unbound_close()
{
  del_hook(HOOK_DNS_HOSTBYIP, (Function) unbound_hostbyip);
  del_hook(HOOK_DNS_IPBYHOST, (Function) unbound_ipbyhost);
  killsock(fd);
  lostdcc(idx);
  module_undepend(MODULE_NAME);
  return NULL;
}

EXPORT_SCOPE char *unbound_start();

static Function unbound_table[] = {
  (Function) unbound_start,
  (Function) unbound_close,
  NULL,
  (Function) unbound_report,
};

static void unbound_activity(int idx, char *buf, int len)
{
  int retval = ub_process(ctx);

  if (retval)
    putlog(LOG_MISC, "*", "Unbound error: %s", ub_strerror(retval));
}

static void unbound_display(int idx, char *buf)
{
  strcpy(buf, "unbo  (ready)");
}

static struct dcc_table DCC_UNBOUND = {
  "UNBOUND",
  DCT_LISTEN,
  NULL,
  unbound_activity,
  NULL,
  NULL,
  unbound_display,
  NULL,
  NULL,
  NULL
};

char *unbound_start(Function *global_funcs)
{
  int retval;

  global = global_funcs;

  module_register(MODULE_NAME, unbound_table, 1, 1);

  if (!module_depend(MODULE_NAME, "eggdrop", 108, 0)) {
    module_undepend(MODULE_NAME);
    return "This module requires Eggdrop 1.8.0 or later.";
  }

  ctx = ub_ctx_create();
  if(!ctx)
    return "Unbound error: could not create unbound context.";
  retval = ub_ctx_resolvconf(ctx, "/etc/resolv.conf");
  if(retval)
    putlog(LOG_MISC, "*", "Unbound warning: %s", ub_strerror(retval));
  retval = ub_ctx_hosts(ctx, "/etc/hosts");
  if(retval)
    putlog(LOG_MISC, "*", "Unbound warning: %s", ub_strerror(retval));

  idx = new_dcc(&DCC_UNBOUND, 0);
  if (idx < 0)
    return "Unbound error: could not get new dcc.";
  fd = ub_fd(ctx);
  if (fd == -1) {
    lostdcc(idx);
    return "Unbound error: could not get file descriptor.";
  }
  if (allocsock(fd, SOCK_PASS) == -1) {
    killsock(fd);
    lostdcc(idx);
    return "Unbound error: could not allocate socket in socklist.";
  }
  dcc[idx].sock = fd;
  dcc[idx].timeval = now;
  strcpy(dcc[idx].nick, "(unbound)");

  add_hook(HOOK_DNS_HOSTBYIP, (Function) unbound_hostbyip);
  add_hook(HOOK_DNS_IPBYHOST, (Function) unbound_ipbyhost);

  return NULL;
}
