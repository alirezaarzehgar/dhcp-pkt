/**
 * @file generation_test.c
 * @author alirezaarzehgar (alirezaarzehgar82@gmail.com)
 * @brief
 * @version 0.1
 * @date 2021-09-25
 *
 * @copyright Copyright (c) 2021
 *
 */

#include "pkt/generation_test.h"

#include "pkt/analyze_test.h"

extern char bufAll[DHCP_PACKET_MAX_LEN];

extern char bufDiscovery[DHCP_PACKET_MAX_LEN];

extern char bufOffer[DHCP_PACKET_MAX_LEN];

extern char bufRequest[DHCP_PACKET_MAX_LEN];

extern char bufNak[DHCP_PACKET_MAX_LEN];

void
pktBlockManagerTest()
{
  pktBlockManager().clear();

  int count = -50;

  for (size_t i = -50; i < 50; i += rand() % 10)
    {
      count += i;

      pktBlockManager().increase (i);

      CU_ASSERT_EQUAL (count, pktBlockManager().block);
    }
}

void
packetGenMainTest()
{
  /* Test endpoint for many test regardless specific function */

  pktDhcpPacket_t *discovery = (pktDhcpPacket_t *)bufDiscovery;

  pktDhcpPacket_t *offer = (pktDhcpPacket_t *)calloc (sizeof (pktDhcpPacket_t),
                           sizeof (pktDhcpPacket_t));

  pktDhcpOptions_t *offerOpt = (pktDhcpOptions_t *)calloc (sizeof (
                                 pktDhcpOptions_t), sizeof (pktDhcpOptions_t));

  offerOpt = (pktDhcpOptions_t *)offer->options;

  /* commons */

  char *chaddr = pktMacStr2hex ("08:00:27:84:3e:d0");

  char *cookie = pktGetMagicCookie (discovery);

  char *domain;

  CU_ASSERT_FATAL (strlen (cookie) == DHCP_MAGIC_COOKIE_SIZE);

  CU_ASSERT_FATAL (pktIsDiscoveryPktValidForOffer (discovery));

  pktGenFieldOperationCode (offer, PKT_MESSAGE_TYPE_BOOT_REPLAY);

  pktGenFieldHardwareType (offer, PKT_HTYPE_ETHERNET);

  pktGenFieldTransactionId (offer, discovery->xid);

  pktGenFieldYourIpAddress (offer, "192.168.133.144");

  pktGenFieldHardwareLen (offer, 6);

  pktGenFieldClientMacAddress (offer, "08:00:27:84:3e:d0");

  /* opts */

  pktGenOptInit (offerOpt);

  pktGenOptMagicCookie (offerOpt, cookie);

  pktGenOptDhcpMsgType (offerOpt, DHCPOFFER);

  pktGenOptDhcpServerIdentifier (offerOpt, "192.168.133.30");

  pktGenOptIpAddrLeaseTime (offerOpt, 600);

  pktGenOptSubnetMask (offerOpt, "255.255.255.0");

  pktGenOptRouter (offerOpt, "192.168.100.1");

  pktGenOptDomainName (offerOpt, "example.org");

  pktGenOptEnd (offerOpt);

  CU_ASSERT_EQUAL (offer->op, PKT_MESSAGE_TYPE_BOOT_REPLAY);

  CU_ASSERT_EQUAL (offer->htype, PKT_HTYPE_ETHERNET);

  CU_ASSERT_STRING_EQUAL (pktMacHex2str (offer->chaddr), pktMacHex2str (chaddr));

  CU_ASSERT_EQUAL (offer->hlen, 6);

  CU_ASSERT_EQUAL (offer->xid, discovery->xid);

  CU_ASSERT_EQUAL (offer->yiaddr.s_addr, inet_addr ("192.168.133.144"));

  CU_ASSERT_EQUAL (pktGetDhcpMessageType (offer), DHCPOFFER);

  CU_ASSERT_STRING_EQUAL (inet_ntoa (*pktGetServerIdentifier (offer)),
                          "192.168.133.30");

  CU_ASSERT_EQUAL (pktLeaseTimeHex2long (pktGetIpAddressLeaseTime (offer)), 600);

  CU_ASSERT_STRING_EQUAL (inet_ntoa (*pktGetSubnetMask (offer)),
                          "255.255.255.0");

  CU_ASSERT_STRING_EQUAL (inet_ntoa (*pktGetRouter (offer)), "192.168.100.1");

  domain = pktGetDomainName (offer);

  CU_ASSERT_FATAL (domain != NULL);

  CU_ASSERT_STRING_EQUAL (domain, "example.org");
}

void
pktGenOfferTest()
{
  pktDhcpPacket_t *discovery = (pktDhcpPacket_t *)bufDiscovery;

  pktDhcpPacket_t *offer = (pktDhcpPacket_t *)calloc (sizeof (pktDhcpPacket_t),
                           sizeof (pktDhcpPacket_t));

  char *chaddr = pktMacStr2hex ("08:00:27:84:3e:d0");

  pktGenCallback_t blocks[] =
  {
    {.func = (pktGenCallbackFunc_t)pktGenFieldYourIpAddress, .param = "192.168.133.144"},
    PKT_GEN_CALLBACK_NULL,
  };

  pktGenCallback_t options[] =
  {
    {.func = (pktGenCallbackFunc_t)pktGenOptRouter, .param = "192.168.1.1"},
    {.func = (pktGenCallbackFunc_t)pktGenOptDhcpServerIdentifier, .param = "192.168.133.30"},
    {.func = (pktGenCallbackFunc_t)pktGenOptDomainName, .param = "example.org"},
    {.func = (pktGenCallbackFunc_t)pktGenOptSubnetMask, .param = "255.255.255.0"},
    {.func = (pktGenCallbackFunc_t)pktGenOptIpAddrLeaseTime, .param = (void *)600},
    PKT_GEN_CALLBACK_NULL,
  };

  pktGenOffer (discovery, offer, blocks, options);

  /* Tests Fields */
  struct in_addr *serverIdentifier;

  struct in_addr *mask;

  struct in_addr *router;

  char *domain;

  char *cookie;

  CU_ASSERT_EQUAL (offer->op, PKT_MESSAGE_TYPE_BOOT_REPLAY);

  CU_ASSERT_EQUAL (offer->htype, PKT_HTYPE_ETHERNET);

  CU_ASSERT_STRING_EQUAL (pktMacHex2str (offer->chaddr), pktMacHex2str (chaddr));

  CU_ASSERT_EQUAL (offer->hlen, 6);

  CU_ASSERT_EQUAL (offer->xid, discovery->xid);

  CU_ASSERT_EQUAL (offer->yiaddr.s_addr, inet_addr ("192.168.133.144"));

  /* Test Options */
  CU_ASSERT_EQUAL (pktGetDhcpMessageType (offer), DHCPOFFER);

  cookie = pktGetMagicCookie (offer);

  CU_ASSERT_TRUE (cookie != NULL);

  CU_ASSERT_STRING_EQUAL (cookie, pktGetMagicCookie (discovery));

  serverIdentifier = pktGetServerIdentifier (offer);

  CU_ASSERT_FATAL (serverIdentifier != NULL);

  CU_ASSERT_STRING_EQUAL (inet_ntoa (*serverIdentifier),
                          "192.168.133.30");

  CU_ASSERT_EQUAL (pktLeaseTimeHex2long (pktGetIpAddressLeaseTime (offer)), 600);

  mask = pktGetSubnetMask (offer);

  CU_ASSERT_FATAL (mask != NULL);

  CU_ASSERT_STRING_EQUAL (inet_ntoa (*mask),
                          "255.255.255.0");

  router = pktGetRouter (offer);

  CU_ASSERT_FATAL (router != NULL);

  CU_ASSERT_STRING_EQUAL (inet_ntoa (*router), "192.168.1.1");

  domain = pktGetDomainName (offer);

  CU_ASSERT_FATAL (domain != NULL);

  CU_ASSERT_STRING_EQUAL (domain, "example.org");
}

void
pktGenAckTest()
{
  pktDhcpPacket_t *request = (pktDhcpPacket_t *)bufRequest;

  pktDhcpPacket_t *ack = (pktDhcpPacket_t *)calloc (sizeof (pktDhcpPacket_t),
                         sizeof (pktDhcpPacket_t));

  char *chaddr = pktMacStr2hex ("08:00:27:84:3e:d0");

  pktGenCallback_t blocks[] =
  {
    {.func = (pktGenCallbackFunc_t)pktGenFieldYourIpAddress, .param = "192.168.133.144"},
    PKT_GEN_CALLBACK_NULL,
  };

  pktGenCallback_t options[] =
  {
    {.func = (pktGenCallbackFunc_t)pktGenOptSubnetMask, .param = "255.255.255.0"},
    {.func = (pktGenCallbackFunc_t)pktGenOptRouter, .param = "192.168.1.1"},
    {.func = (pktGenCallbackFunc_t)pktGenOptIpAddrLeaseTime, .param = (void *)600},
    {.func = (pktGenCallbackFunc_t)pktGenOptDhcpServerIdentifier, .param = "192.168.133.30"},
    {.func = (pktGenCallbackFunc_t)pktGenOptDomainName, .param = "example.org"},
    PKT_GEN_CALLBACK_NULL,
  };

  pktGenAck (request, ack, blocks, options);

  /* Tests Fields */
  struct in_addr *serverIdentifier;

  struct in_addr *mask;

  struct in_addr *router;

  char *domain;

  char *cookie;

  CU_ASSERT_EQUAL (ack->op, PKT_MESSAGE_TYPE_BOOT_REPLAY);

  CU_ASSERT_EQUAL (ack->htype, PKT_HTYPE_ETHERNET);

  CU_ASSERT_STRING_EQUAL (pktMacHex2str (ack->chaddr), pktMacHex2str (chaddr));

  CU_ASSERT_EQUAL (ack->hlen, 6);

  CU_ASSERT_EQUAL (ack->xid, request->xid);

  CU_ASSERT_EQUAL (ack->yiaddr.s_addr, inet_addr ("192.168.133.144"));

  /* Test Options */
  CU_ASSERT_EQUAL (pktGetDhcpMessageType (ack), DHCPACK);

  cookie = pktGetMagicCookie (ack);

  CU_ASSERT_TRUE (cookie != NULL);

  CU_ASSERT_STRING_EQUAL (cookie, pktGetMagicCookie (request));

  serverIdentifier = pktGetServerIdentifier (ack);

  CU_ASSERT_FATAL (serverIdentifier != NULL);

  CU_ASSERT_STRING_EQUAL (inet_ntoa (*serverIdentifier),
                          "192.168.133.30");

  CU_ASSERT_EQUAL (pktLeaseTimeHex2long (pktGetIpAddressLeaseTime (ack)), 600);

  mask = pktGetSubnetMask (ack);

  CU_ASSERT_FATAL (mask != NULL);

  CU_ASSERT_STRING_EQUAL (inet_ntoa (*mask),
                          "255.255.255.0");

  router = pktGetRouter (ack);

  CU_ASSERT_FATAL (router != NULL);

  CU_ASSERT_STRING_EQUAL (inet_ntoa (*router), "192.168.1.1");

  domain = pktGetDomainName (ack);

  CU_ASSERT_FATAL (domain != NULL);

  CU_ASSERT_STRING_EQUAL (domain, "example.org");
}

void
pktGenNakTest()
{
  char *chaddr = pktMacStr2hex ("08:00:27:84:3e:d0");

  struct in_addr *serverIdentifier;

  char *cookie;

  pktDhcpPacket_t *discovery = (pktDhcpPacket_t *)bufDiscovery;

  pktDhcpPacket_t *nak = (pktDhcpPacket_t *)malloc (sizeof (pktDhcpPacket_t));

  pktGenCallback_t options[] =
  {
    { .func = (pktGenCallbackFunc_t)pktGenOptDhcpServerIdentifier, .param = "192.168.100.1" },
    { .func = (pktGenCallbackFunc_t)pktGenOptMessage, .param = "Wrong server-ID" },
    PKT_GEN_CALLBACK_NULL,
  };

  pktGenNak (discovery, nak, NULL, options);

  CU_ASSERT_EQUAL (nak->op, PKT_MESSAGE_TYPE_BOOT_REPLAY);

  CU_ASSERT_EQUAL (nak->htype, PKT_HTYPE_ETHERNET);

  CU_ASSERT_STRING_EQUAL (pktMacHex2str (nak->chaddr), pktMacHex2str (chaddr));

  CU_ASSERT_EQUAL (nak->hlen, 6);

  CU_ASSERT_EQUAL (nak->xid, discovery->xid);

  CU_ASSERT_EQUAL (pktGetDhcpMessageType (nak), DHCPNAK);

  cookie = pktGetMagicCookie (nak);

  CU_ASSERT_TRUE (cookie != NULL);

  CU_ASSERT_STRING_EQUAL (cookie, pktGetMagicCookie (discovery));

  serverIdentifier = pktGetServerIdentifier (nak);

  CU_ASSERT_FATAL (serverIdentifier != NULL);

  CU_ASSERT_STRING_EQUAL (inet_ntoa (*serverIdentifier),
                          "192.168.100.1");
  free (nak);
}