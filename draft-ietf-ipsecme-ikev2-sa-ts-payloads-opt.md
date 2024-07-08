---
title: IKEv2 Optional SA&TS Payloads in Child Exchange
abbrev: IKEv2 Optional Child SA&TS Payloads
docname: draft-ietf-ipsecme-ikev2-sa-ts-payloads-opt-02
category: std

ipr: trust200902
area: Security
workgroup: IPSECME Working Group
keyword: Internet-Draft
stream: IETF

stand_alone: true
pi:
  toc: yes
  sortrefs: yes
  symrefs: yes

author:
- ins: S. Kampati
  name: Sandeep Kampati
  org: Microsoft
  abbrev: Microsoft
  email: skampati@microsoft.com
  country: India
- ins: W. Pan
  name: Wei Pan
  org: Huawei Technologies
  abbrev: Huawei
  email: william.panwei@huawei.com
  street: 101 Software Avenue, Yuhuatai District
  code: ""
  city: Nanjing
  region: Jiangsu
  country: China
- ins: P. Wouters
  name: Paul Wouters
  org: Aiven
  abbrev: Aiven
  email: paul.wouters@aiven.io
- ins: M. Bharath
  name: Meduri S S Bharath
  org: Mavenir Systems Pvt Ltd
  abbrev: Mavenir
  email: bharath.meduri@mavenir.com
  street: Manyata Tech Park
  code: ""
  city: Bangalore
  region: Karnataka
  country: India
- ins: M. Chen
  name: Meiling Chen
  org: China Mobile
  abbrev: CMCC
  email: chenmeiling@chinamobile.com
  street: 32 Xuanwumen West Street, West District
  code: "100053"
  city: Beijing
  country: China

normative:
  RFC2119:
  RFC8174:
  RFC7296:

informative:

venue:
  mail: ipsec@ietf.org

--- abstract

This document describes a method for reducing the size of the Internet Key Exchange version 2 (IKEv2) CREATE\_CHILD\_SA exchanges used for rekeying of the IKE or Child SA by replacing the SA and TS payloads with a Notify Message payload.
Reducing size and complexity of IKEv2 exchanges is especially useful for low power consumption battery powered devices.

--- middle

# Introduction

The Internet Key Exchange protocol version 2 (IKEv2) [RFC7296] is used to negotiate Security Association (SA) parameters for the IKE SA and the Child SAs. Cryptographic key material for these SAs have a limited lifetime before it needs to be refreshed, a process referred to as "rekeying". IKEv2 uses the CREATE_CHILD_SA exchange to rekey either the IKE SA or the Child SAs.

When rekeying, a full set of negotiation parameters are exchanged. However, most of these parameters will be the same as before, and some of these parameters MUST NOT change.

For example, the Traffic Selector (TS) negotiated for the new Child SA MUST cover the Traffic Selectors negotiated for the old Child SA. And in practically all cases, a new Child SA does not need to cover a wider set of Traffic. In the rare case where this would be needed, either a standard rekey could be used or a new Child SA could be negotiated followed by a deletion of the replaced Child SA.

Similarly, IKEv2 states that the cryptographic parameters negotiated for rekeying SHOULD NOT be different. This means that the security properties of the IKE or Child SA in practise do not change during a typical rekey.

This document specifies a method to omit these parameters and replace them with a single Notify Message declaring that all these parameters are identical to the originally negotiated parameters.

Large scale IKEv2 gateways such as Evolved Packet Data Gateway (ePDG) in 4G networks or Centralized Radio Access Network (cRAN/Cloud) gateways in 5G networks typically support more than 100,000 IKE/IPsec connections. At any point in time, there will be hundreds or thousands of IKE SAs and Child SAs that are being rekeyed. This takes a large amount of bandwidth and CPU power and any protocol simplification or bandwidth reducing would result in a significant resource saving.

For Internet of Things (IoT) devices which utilize low power consumption technology, reducing the size of the CREATE_CHILD_SA exchange for rekeying reduces its power consumption, as sending bytes over the air is usually the most power consuming operation of such a device. Reducing the CPU operations required to verify the rekey exchanges parameters will also save power and extend the lifetime for these devices.

When using identical parameters for the IKE SA or Child SA rekey, the SA and TS payloads can be omitted thanks to the optimization defined in this document. For an IKE SA rekey, instead of the (large) SA payload, only a Key Exchange (KE) payload and a new Notify Type payload with the new SPI are required. For a Child SA payload, instead of the SA or TS payloads, only an optional KE payload (when using PFS) and a new Notify Type payload with the new SPI are needed. This makes the rekey exchange packets much smaller and the peers do not need to verify that the SA or TS parameters are compatible with the old SA parameters.



# Conventions Used in This Document

## Requirements Language

{::boilerplate bcp14-tagged}

# Negotiation of Support for OPTIMIZED REKEY

To indicate support for the optimized rekey negotiation, the initiator includes the OPTIMIZED_REKEY_SUPPORTED notify payload in the IKE_AUTH exchange request. If multiple IKE_AUTH exchanges are sent, the OPTIMIZED_REKEY_SUPPORTED notify payload should be in the last IKE_AUTH exchange. During this initial key request, the entire SA and TS payloads are included as normal. Note that the notify indicates support for optimized rekey for both IKE and Child SAs.

A responder that does not support the optimized rekey exchange processes the SA and TS payloads as normal, and does not include the new Notify. As per regular IKEv2 processing, a responder that does not recognize this new Notify, MUST ignore the notify. Responders may have been administratively configured with the optimization turned off for local reasons. The absense of the Notify indicates to the initiator that the optimization is not available, and normal, full rekey should be done.

When a peer wishes to rekey an IKE SA or Child SA, it MAY use the optimized rekey method during the CREATE_CHILD_SA exchange. If both peers have exchanged OPTIMIZED_REKEY_SUPPORTED notifies, peers SHOULD use the optimized rekey method for rekeys. Non-optimized, regular rekey requests MUST always be accepted.

The IKE_AUTH message exchange in this case is shown below:

~~~~
Initiator                       Responder
--------------------------------------------------------------------
HDR, SK {IDi, [CERT,] [CERTREQ,]
    [IDr,] AUTH, SAi2, TSi, TSr,
    N(OPTIMIZED_REKEY_SUPPORTED)} -->
                            <-- HDR, SK {IDr, [CERT,] AUTH,
                                    SAr2, TSi, TSr,
                                    N(OPTIMIZED_REKEY_SUPPORTED)}
~~~~

# Optimized Rekey of the IKE SA

The initiator of an optimized rekey request sends a CREATE_CHILD_SA request with the OPTIMIZED_REKEY notify payload containing the new Security Parameter Index (SPI) for the new IKE SA. It omits the SA payload.

The responder of an optimized rekey request replies with an included OPTIMIZED_REKEY notify with its new IKE SPI and also omits the SA payload.

Both parties send their nonce and KE payloads just as they would do for a regular IKE SA rekey.

Using the old SPI from the IKE header and the two new SPIs respectively from the initiator and responder's OPTIMIZED_REKEY payloads, both parties can perform the IKE SA rekey operation.

The CREATE_CHILD_SA message exchange in this case is shown below:

~~~~
Initiator                       Responder
--------------------------------------------------------------------
HDR, SK {N(OPTIMIZED_REKEY,newSPIi),
         Ni, KEi} -->
                            <-- HDR, SK {N(OPTIMIZED_REKEY,newSPIr),
                                         Nr, KEr}
~~~~

# Optimized Rekey of Child SAs

The initiator of an optimized rekey request sends a CREATE_CHILD_SA request with the OPTIMIZED_REKEY notify payload containing the new Security Parameter Index (SPI) for the new Child SA. It omits the SA and TS payloads. If the current Child SA was negotiated with Perfect Forward Secrecy (PFS), a KEi payload is included as well. If no PFS was negotiated for the current Child SA, a KEi payload is not included.

The responder of an optimized rekey request performs the same process. It includes the OPTIMIZED_REKEY notify with its new SPI for the new Child SA and omits the SA and TS payloads. Depending on the PFS negotiation of the current Child SA, the responder includes a KEr payload.

Both parties send their nonce payloads just as they would do for a regular Child SA rekey.

Using the old SPI from the REKEY_SA payload and the two new SPIs respectively from the initiator and responder's OPTIMIZED_REKEY payloads, both parties can perform the Child SA rekey operation.

Notify payloads that can affect the Child SA properties, such as USE_TRANSPORT_MODE or ESP_TFC_PADDING_NOT_SUPPORTED MAY be sent but MUST be ignored and MUST NOT cause the Child SA properties to change. IPCOMP_SUPPORTED MUST be sent as it contains the required updated CPI parameter.

For the Child SA that was negotiated as part of an initial IKE exchange (eg IKE_AUTH), its rekey parameters for the KE payload SHOULD be the same KE group(s) for Child SA PFS as the negotiated IKE SA. If rekeying without PFS is required, the peer first initiates a regular Child SA rekey without KE payload, and subsequently it can use the optimized rekey method. If a peer responding to an optimized rekey receives a request with a non-allowed PFS proposal, it MUST return an INVALID_KE_PAYLOAD response.

The CREATE_CHILD_SA message exchange in this case is shown below:

~~~~
Initiator                       Responder
--------------------------------------------------------------------
HDR, SK {N(REKEY_SA,oldSPI), N(OPTIMIZED_REKEY,newSPIi),
         Ni, [KEi,]} -->
                            <-- HDR, SK {N(OPTIMIZED_REKEY,newSPIr),
                                         Nr, [KEr,]}
~~~~

# Payload Formats

## OPTIMIZED\_REKEY\_SUPPORTED Notify

The OPTIMIZED_REKEY_SUPPORTED Notify Message type notification is used by the initiator and responder to indicate their support for the optimized rekey negotiation.

~~~~
                     1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+---------------+-+-------------+-------------------------------+
| Next Payload  |C|  RESERVED   |         Payload Length        |
+---------------+-+-------------+-------------------------------+
|Protocol ID(=0)| SPI Size (=0) |      Notify Message Type      |
+---------------+---------------+-------------------------------+
~~~~

* Protocol ID (1 octet) - MUST be 0.
* SPI Size (1 octet) - MUST be 0, meaning no SPI is present.
* Notify Message Type (2 octets) - MUST be set to the value `TBD1`.

This Notify Message type contains no data.

## OPTIMIZED\_REKEY Notify

The OPTIMIZED_REKEY Notify Message type is used to perform an optimized IKE SA or Child SA rekey.

~~~~
 0                 1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+---------------+-+-------------+-------------------------------+
| Next Payload  |C|  RESERVED   |         Payload Length        |
+---------------+-+-------------+-------------------------------+
|Protocol ID(=0)| SPI Size (=0) |      Notify Message Type      |
+---------------+---------------+-------------------------------+
|                                                               |
~                            New SPI                            ~
|                                                               |
+---------------------------------------------------------------+
~~~~

* Protocol ID (1 octet) - MUST be 0.

* SPI Size (1 octet) - MUST be 0. The "Security Parameter Index (SPI)" field is not used in this Notify, and the new SPI is placed in the "Notification Data" field.

* Notify Message Type (2 octets) - MUST be set to the value `TBD2`.

The 'New SPI' field is the data associated with this Notify, and it's either a four-octet SPI when rekeying an IKE SA or an eight-octet SPI when rekeying a Child SA.

# IANA Considerations

This document defines two new Notify Message Types in the "IKEv2 Notify Message Types - Status Types" registry. IANA is requested to assign codepoints in this registry.

~~~~
NOTIFY messages: status types            Value
----------------------------------------------------------
OPTIMIZED_REKEY_SUPPORTED                TBD1
OPTIMIZED_REKEY                          TBD2
~~~~

# Operational Considerations

Some implementations allow sending rekey messages with a different set of Traffic Selectors or cryptographic parameters in response to a configuration update. IKEv2 [RFC7296] states this SHOULD NOT be done. Whether or not optimized rekeying is used, a configuration change that changes the Traffic Selectors or cryptographic parameters MUST NOT use the optimized rekey method. It SHOULD also not use a regular rekey method but instead start an entire new IKE and Child SA negotiation with the new parameters.

# Security Considerations

The optimized rekey removes sending unnecessary new parameters that originally would have to be validated against the original parameters. In that sense, this optimization enhances the security of the rekey process by reducing the complexity and code required.

# Acknowledgments

Special thanks go to Valery Smyslov and Antony Antony.

--- back

