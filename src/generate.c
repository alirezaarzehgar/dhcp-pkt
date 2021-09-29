/**
 * @file generate.c
 * @author alireza arzehgar (alirezaarzehgar82@gmail.com)
 * @brief
 * @version 0.1
 * @date 2021-09-19
 *
 * @copyright Copyright (c) 2021
 *
 */

#include "pkt/generate.h"

pktBlockManagerRetVal_t
pktBlockManager()
{
  static int block;

  void __pkt_close()
  {
    block = -1;
  }

  void __pkt_clear()
  {
    block = 0;
  }

  void __pkt_increase (int size)
  {
    block += size;
  }

  pktBlockManagerRetVal_t ret = { __pkt_clear, __pkt_close, __pkt_increase, block };

  return ret;
}

int
pktGenOffer (pktDhcpPacket_t *discovery, pktDhcpPacket_t *offer,
             pktGenCallback_t *blocks, pktGenCallback_t *options)
{
  char *discoveryCookie;

  if (!pktIsDiscoveryPktValidForOffer (discovery))
    return PKT_RET_FAILURE;

  /* Apply default offer fields */
  pktGenFieldHardwareLen (offer, PKT_HLEN);

  pktGenFieldHardwareType (offer, PKT_HTYPE_ETHERNET);

  if (blocks)
    {
      for (size_t i = 0; blocks[i].func != NULL && blocks[i].param != NULL; i++)
        blocks[i].func (offer, blocks[i].param);
    }

  /* Apply necessary offer fileds */
  pktGenFieldOperationCode (offer, PKT_MESSAGE_TYPE_BOOT_REPLY);

  pktGenFieldClientMacAddress (offer, pktMacHex2str (discovery->chaddr));

  pktGenFieldTransactionId (offer, discovery->xid);

  /* Apply default offer options */
  pktDhcpOptions_t *opt = (pktDhcpOptions_t *)&offer->options;

  pktGenOptInit (opt);

  discoveryCookie = pktGetMagicCookie (discovery);

  pktGenOptMagicCookie (opt, discoveryCookie);

  pktGenOptDhcpMsgType (opt, DHCPOFFER);

  /* Iterate and run all option functions */
  if (options)
    {
      for (size_t i = 0; options[i].func != NULL && options[i].param != NULL; i++)
        options[i].func (opt, options[i].param);
    }

  pktGenOptEnd (opt);

  return PKT_RET_SUCCESS;
}

int
pktGenAck (pktDhcpPacket_t *request, pktDhcpPacket_t *ack,
           pktGenCallback_t *blocks, pktGenCallback_t *options)
{
  char *requestCookie;

  if (!pktIsRequestPktValidForAck (request))
    return PKT_RET_FAILURE;

  /* Apply default offer fields */
  pktGenFieldHardwareLen (ack, PKT_HLEN);

  pktGenFieldHardwareType (ack, PKT_HTYPE_ETHERNET);

  if (blocks)
    {
      for (size_t i = 0; blocks[i].func != NULL && blocks[i].param != NULL; i++)
        blocks[i].func (ack, blocks[i].param);
    }

  /* Apply necessary offer fileds */
  pktGenFieldOperationCode (ack, PKT_MESSAGE_TYPE_BOOT_REPLY);

  pktGenFieldClientMacAddress (ack, pktMacHex2str (request->chaddr));

  pktGenFieldTransactionId (ack, request->xid);

  /* Apply default offer options */
  pktDhcpOptions_t *opt = (pktDhcpOptions_t *)&ack->options;

  pktGenOptInit (opt);

  requestCookie = pktGetMagicCookie (request);

  pktGenOptMagicCookie (opt, requestCookie);

  pktGenOptDhcpMsgType (opt, DHCPACK);

  /* Iterate and run all option functions */
  if (options)
    {
      for (size_t i = 0; options[i].func != NULL && options[i].param != NULL; i++)
        options[i].func (opt, options[i].param);
    }

  pktGenOptEnd (opt);

  return PKT_RET_SUCCESS;
}

int
pktGenNak (void *unused /* TODO any parameter sets on future */,
           pktDhcpPacket_t *nak)
{
  /* get error message */

  /* TODO - get error message */

  /* get extra option */

  /* TODO - get extra option */

  return PKT_RET_SUCCESS;
}

void
pktGenOptInit (pktDhcpOptions_t *opt)
{
  bzero (opt, DHCP_MAX_OPTION_LEN);

  pktBlockManager().clear();
}

void
pktGenOptMagicCookie (pktDhcpOptions_t *opt, char *cookie)
{
  int cookieLen = strlen (cookie);

  memcpy (&opt->opts[pktBlockManager().block], cookie, cookieLen);

  pktBlockManager().increase (cookieLen);
}

void
pktGenOptDhcpMsgType (pktDhcpOptions_t *opt, int type)
{
  pktMessageType_t msgType = {.len = 1, .option = OPTION_DHCP_MSG_TYPE & 0xff, .type = type};

  int size = sizeof (pktMessageType_t);

  memcpy (&opt->opts[pktBlockManager().block], &msgType, size);

  pktBlockManager().increase (size);
}

void
pktGenOptAddr (pktDhcpOptions_t *opt, char *addr, int option, size_t len)
{
  pktAddress_t *address = (pktAddress_t *)malloc (sizeof (pktAddress_t));

  address->option = option & 0xff;

  address->len = len;

  size_t size = sizeof (pktAddress_t) + address->len;

  char *hexAddr = pktIpStr2hex (addr);

  memcpy (address->addr, hexAddr, 4);

  memcpy (&opt->opts[pktBlockManager().block], address, size);

  pktBlockManager().increase (size);

  free (address);
}

void
pktGenOptDhcpServerIdentofier (pktDhcpOptions_t *opt, char *server)
{
  pktGenOptAddr (opt, server, OPTION_SERVER_IDENTIFIER, PKT_DEFAULT_ADDRESS_LEN);
}

void
pktGenOptIpAddrLeaseTime (pktDhcpOptions_t *opt, uint32_t time)
{
  char *hexTime;

  int size = sizeof (pktIpAddressLeaseTime_t);

  pktIpAddressLeaseTime_t ipAddrLT = {.option = OPTION_IP_ADDR_LEASE_TIME & 0xff, .len = PKT_IP_ADDR_LEASE_TIME_LEN};

  hexTime = pktLeaseTimeLong2hex (time);

  if (time)
    memcpy (ipAddrLT.time, hexTime, ipAddrLT.len);

  memcpy (&opt->opts[pktBlockManager().block], &ipAddrLT, size);

  pktBlockManager().increase (size);
}

void
pktGenOptSubnetMask (pktDhcpOptions_t *opt, char *netmask)
{
  pktGenOptAddr (opt, netmask, OPTION_SUBNET_MASK, PKT_DEFAULT_ADDRESS_LEN);
}

void
pktGenOptRouter (pktDhcpOptions_t *opt, char *router)
{
  pktGenOptAddr (opt, router, OPTION_ROUTER, PKT_DEFAULT_ADDRESS_LEN);
}

void
pktGenOptString (pktDhcpOptions_t *opt, char *string, int option)
{
  pktString_t *str = (pktString_t *)malloc (sizeof (pktString_t));

  str->option = option & 0xff;

  str->len = strlen (string);

  char *name = string;

  int size = sizeof (pktString_t) + str->len;

  if (name)
    memcpy (str->name, name, str->len);

  memcpy (&opt->opts[pktBlockManager().block], str, size);

  pktBlockManager().increase (size);
}

void
pktGenOptDomainName (pktDhcpOptions_t *opt, char *domainName)
{
  pktGenOptString (opt, domainName, OPTION_DOMAIN_NAME);
}

void
pktGenOptEnd (pktDhcpOptions_t *opt)
{
  pktEnd_t end = {.option = OPTION_END};

  memcpy (&opt->opts[pktBlockManager().block], &end, sizeof (pktEnd_t));

  pktBlockManager().close();
}

void
pktGenFieldClientMacAddress (pktDhcpPacket_t *pkt, char *chaddr)
{
  if (pkt->hlen == 0)
    pkt->hlen = PKT_HLEN;

  char *hexMac = pktMacStr2hex (chaddr);

  memcpy (pkt->chaddr, hexMac, pkt->hlen);
}

void
pktGenFieldOperationCode (pktDhcpPacket_t *pkt, int op)
{
  pkt->op = op;
}

void
pktGenFieldHardwareType (pktDhcpPacket_t *pkt, int htype)
{
  pkt->htype = htype;
}

void
pktGenFieldTransactionId (pktDhcpPacket_t *pkt, int xid)
{
  pkt->xid = xid;
}

void
pktGenFieldYourIpAddress (pktDhcpPacket_t *pkt, char *yip)
{
  pkt->yiaddr.s_addr = inet_addr (yip);
}

void
pktGenFieldHardwareLen (pktDhcpPacket_t *pkt, int len)
{
  pkt->hlen = len;
}