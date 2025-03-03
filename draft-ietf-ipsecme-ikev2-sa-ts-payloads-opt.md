---
title: Optimized Rekeys in the Internet Key Exchange Protocol Version 2 (IKEv2)
abbrev: Optimized Rekey of IKE & Child SAs
docname: draft-ietf-ipsecme-ikev2-sa-ts-payloads-opt-04
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
- ins: V. Smyslov
  name: Valery Smyslov
  org: ELVIS-PLUS
  abbrev: ELVIS-PLUS
  phone: "+7 495 276 0211"
  email: svan@elvis.ru
  street: PO Box 81
  code: "124460"
  city: Moscow (Zelenograd)
  country: Russian Federation

normative:
  RFC2119:
  RFC8174:
  RFC7296:
  RFC5723:
  RFC9370:

informative:
  RFC5857:
  RFC9347:
  I-D.pwouters-ipsecme-child-pfs-info: child-pfs

venue:
  mail: ipsec@ietf.org

--- abstract

This document describes a method for reducing the size of the Internet Key Exchange version 2 (IKEv2) CREATE\_CHILD\_SA exchanges used for rekeying of the IKE or Child SA by replacing the SA and TS payloads with a Notify Message payload.
Reducing size and complexity of IKEv2 exchanges is especially useful for low power consumption battery powered devices.

--- middle

# Introduction

The Internet Key Exchange protocol version 2 (IKEv2) [RFC7296] is used to negotiate Security Association (SA) parameters for the IKE SA and the Child SAs. Cryptographic key material for these SAs have a limited lifetime before it needs to be refreshed, a process referred to as "rekeying". IKEv2 uses the CREATE_CHILD_SA exchange to rekey either the IKE SA or the Child SAs.

When rekeying, a full set of negotiation parameters are exchanged. However, most of these parameters will be the same as before. This means that the security properties of the IKE or Child SA in practice do not change during a typical rekey.

For example, the Traffic Selectors (TS) negotiated for the new Child SA must cover the Traffic Selectors negotiated for the old Child SA. And in practically all cases, a new Child SA does not need to cover a wider set of traffic. In the rare case where this would be needed, either a standard rekey could be used or a new Child SA could be negotiated followed by a deletion of the replaced Child SA. Further, per RFC 7296, the Traffic Selectors and algorithms should not change when rekeying the Child SA.

This document specifies a method to omit these parameters and replace them with a single Notify Message declaring that all these parameters are identical to the originally negotiated parameters.

Large scale IKEv2 gateways such as Evolved Packet Data Gateway (ePDG) in 4G networks or Centralized Radio Access Network (cRAN/Cloud) gateways in 5G networks typically support more than 100,000 IKE/IPsec connections. At any point in time, there will be hundreds or thousands of IKE SAs and Child SAs that are being rekeyed. This takes a large amount of bandwidth and CPU power and any protocol simplification or bandwidth reducing would result in a significant resource saving.

For Internet of Things (IoT) devices which utilize low power consumption technology, reducing the size of the CREATE_CHILD_SA exchange for rekeying reduces its power consumption, as sending bytes over the air is usually the most power consuming operation of such a device. Reducing the CPU operations required to verify the rekey exchanges parameters will also save power and extend the lifetime for these devices.

When using identical parameters for the IKE SA or Child SA rekey, the SA and TS payloads can be omitted thanks to the optimization defined in this document. For an IKE SA rekey, instead of the (large) SA payload, only a Key Exchange (KE) payload, a Nonce payload, and a new Notify Type payload with the new Security Parameter Index (SPI) are required. For a Child SA rekey, instead of the SA or TS payloads, only an optional KE payload (when using PFS), a Nonce payload, and a new Notify Type payload with the new SPI are needed. This makes the rekey exchange packets much smaller and the peers do not need to verify that the SA or TS parameters are compatible with the old SA parameters.

# Conventions Used in This Document

## Requirements Language

{::boilerplate bcp14-tagged}

# Negotiation of Support for Optimized Rekey

To indicate support for the optimized rekey negotiation, the initiator includes the OPTIMIZED_REKEY_SUPPORTED notify payload in the IKE_AUTH exchange request.
If the responder supports this optimized rekey and is configured to use it, then it includes the OPTIMIZED_REKEY_SUPPORTED in the IKE_AUTH response message.
If multiple IKE_AUTH exchanges are sent, the OPTIMIZED_REKEY_SUPPORTED notify payload should be in the first IKE_AUTH request and the last IKE_AUTH response.
During the IKE_AUTH exchanges, the entire SA and TS payloads are included as normal. Note that the notify indicates support for optimized rekey for both IKE and Child SAs.

A responder that does not support the optimized rekey exchange processes the SA and TS payloads as normal, and does not include the new Notify. As per regular IKEv2 processing, a responder that does not recognize this new Notify, will ignore it. Responders may have been administratively configured with the optimization turned off for local reasons. The absence of the Notify indicates to the initiator that the optimization is not available, and regular rekey should be used.

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

If both peers have exchanged OPTIMIZED_REKEY_SUPPORTED notifies, peers SHOULD use the optimized rekey method for rekeys.
Non-optimized, regular rekey requests MUST always be accepted.
The regular rekey can be retried when the optimized rekey fails.

Note that, except for the key and identification information such as the SPI, the optimized rekey MUST inherit all other properties of the SA being rekeyed.
This means the configurations related to the SA being rekeyed are supposed to have no changes.
If there is a change to the configurations, the regular rekey MUST be used instead.
After the regular rekey, the next rekey can use the optimized way if there is no change to the configuration.

# Optimized Rekey of IKE SA

The initiator of an optimized rekey request sends a CREATE_CHILD_SA request with the OPTIMIZED_REKEY notify payload containing the new SPI for the new IKE SA. It omits the SA payload.

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

The initiator of an optimized rekey request sends a CREATE_CHILD_SA request with the OPTIMIZED_REKEY notify payload containing the new SPI for the new Child SA.
It omits the SA and TS payloads.
If the Child SA being rekeyed was negotiated with Perfect Forward Secrecy (PFS), a KEi payload is included as well.
If no PFS was negotiated for the Child SA being rekeyed, a KEi payload is not included.
If the Child SA being rekeyed was created with IP compression, then IPCOMP_SUPPORTED notifications MUST be sent as they contain the required updated Compression Parameter Indexes (CPIs).

The responder of an optimized rekey request performs the same process. It includes the OPTIMIZED_REKEY notify with its new SPI for the new Child SA and omits the SA and TS payloads. Depending on the PFS and IP compression negotiation of the Child SA being rekeyed, the responder correspondingly includes a KEr payload and/or the IPCOMP_SUPPORTED Notify payload. 

Both parties send their nonce payloads just as they would do for a regular Child SA rekey.

Using the old SPI from the REKEY_SA payload and the two new SPIs respectively from the initiator and responder's OPTIMIZED_REKEY payloads, both parties can perform the Child SA rekey operation.

Except for the key and identification information such as the SPI and CPI, all other properties of the Child SA being rekeyed MUST be inherited to the one newly created by the optimized rekey. Notify payloads that can affect these properties, such as USE_TRANSPORT_MODE, ESP_TFC_PADDING_NOT_SUPPORTED, ROHC_SUPPORTED [RFC5857] or USE_AGGFRAG [RFC9347] MUST NOT be sent.

The CREATE_CHILD_SA message exchange in this case is shown below:

~~~~
Initiator                       Responder
--------------------------------------------------------------------
HDR, SK {N(REKEY_SA,oldSPI), N(OPTIMIZED_REKEY,newSPIi),
         Ni, [KEi,]} -->
                            <-- HDR, SK {N(OPTIMIZED_REKEY,newSPIr),
                                         Nr, [KEr,]}
~~~~

For the initial Child SA that was negotiated as part of an initial IKE exchange (e.g., IKE_AUTH), at the time of its creation the parameters of PFS and KE method for Child SAs are not negotiated. Therefore, the KE method for the initial IKE SA should also be recognized as the one for this initial Child SA.

Two peers must have the same configurations for the parameters of PFS and KE method for Child SAs.

If rekeying without PFS is required, the peer initiates the optimized rekey request without a KEi payload.
If rekeying with PFS is required and the configured KE method for Child SAs is the same as the one used by the Child SA being rekeyed, the peer initiates the optimized rekey request with a KEi payload. The responder correspondingly includes a KEr payload or not in its optimized rekey response.

If the configured KE method for Child SAs is different from the one used by the Child SA being rekeyed, this situation can be seen as there is a configuration change, thus the regular rekey should be used instead of the optimized rekey.

If the responder fails to process the optimized rekey request, e.g., receiving a request with a non-allowed PFS proposal, it MUST return an error as the notification of type NO_PROPOSAL_CHOSEN. After receiving the error response of the optimized rekey, the initiator can retry a regular rekey.

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

The Notification Data for this notify contains new SPI. Its size depends on the type of SA being rekeyed. In case of IKE SA it MUST be 8 octets. In case of Child SA it MUST be equal to the SPI Size field in the REKEY_SA notification that identifies the SA being rekeyed.

# Interaction with IKEv2 Extensions

## Multiple Key Exchanges

[RFC9370] defines the use of multiple key exchange methods for the purpose of IKE SA and Child SA establishment in IKEv2. If multiple key exchange methods are used for an SA, then optimized rekey of this SA MUST use the same key exchange methods. It means that the CREATE_CHILD_SA will be followed by some IKE_FOLLOWUP_KE exchanges and the number of these exchanges will be determined by the number of additional key exchange methods used for the SA being rekeyed.


## IKE Session Resumption

IKE Session Resumption [RFC5723] defines an IKEv2 extension, that allows peers to quickly restore IKE SA when it is for some reason deleted. When used with optimized rekey, the following rules apply.


* Support for optimized rekeys MUST be re-negotiated during the resumption (in the IKE_AUTH exchange).

* If support for optimized rekey is negotiated during resumption, then all IKE SA algorithms, including key exchange methods, are taken from the resumption ticket (i.e., from the SA being resumed), since they are not negotiated in the IKE_SA_RESUME exchange.

* The initial Child SA created during the resumption is considered as been created with key exchange methods for the IKE SA, that were stored in the resumption ticket. This is despite the fact, that during the resumption no key exhanges (e.g., Diffie-Hellman) take place, the session keys are derived from the keys stored in the resumption ticket.

# IANA Considerations

This document defines two new Notify Message Types in the "IKEv2 Notify Message Types - Status Types" registry. IANA is requested to assign codepoints in this registry.

~~~~
NOTIFY messages: status types            Value
----------------------------------------------------------
OPTIMIZED_REKEY_SUPPORTED                TBD1
OPTIMIZED_REKEY                          TBD2
~~~~

# Operational Considerations

Some implementations allow sending rekey messages with a different set of Traffic Selectors or cryptographic parameters in response to a configuration update. IKEv2 [RFC7296] states this "SHOULD NOT" be done. But if there is a configuration change that changes the Traffic Selectors, cryptographic parameters, or other properties of the SA, the regular rekey should be used to make the configuration change active, since the optimized rekey can't express such changes.

Two peers' PFS policy and KE method configurations MUST be the same, otherwise, the rekey of the Child SA created in the IKE_AUTH exchange would fail. This issue is also discussed in detail in {{-child-pfs}}. If the KE method for Child SAs is negotiated during the creation of the initial Child SA via the mechanism like {{-child-pfs}}, this KE method MUST be inherited when using the optimized method to rekey the initial Child SA.

# Security Considerations

The optimized rekey removes sending unnecessary new parameters that originally would have to be validated against the original parameters. In that sense, this optimization enhances the security of the rekey process by reducing the complexity and code required.

# Acknowledgments

Special thanks go to Antony Antony and Tobias Brunner.

--- back
