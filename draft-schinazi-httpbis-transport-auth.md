---
title: HTTP Transport Authentication
abbrev: HTTP Transport Authentication
docname: draft-schinazi-httpbis-transport-auth-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
category: exp
wg: HTTPBIS
area: "Applications and Real-Time"
venue:
  group: "HTTP"
  type: "Working Group"
  mail: "ietf-http-wg@w3.org"
  arch: "https://lists.w3.org/Archives/Public/ietf-http-wg/"
  github: "DavidSchinazi/draft-schinazi-httpbis-transport-auth"
  latest: "https://DavidSchinazi.github.io/draft-schinazi-httpbis-transport-auth/draft-schinazi-httpbis-transport-auth.html"
keyword:
  - secure
  - tunnels
  - masque
  - http-ng
author:
  -
    ins: D. Schinazi
    name: David Schinazi
    org: Google LLC
    street: 1600 Amphitheatre Parkway
    city: Mountain View
    region: CA
    code: 94043
    country: United States of America
    email: dschinazi.ietf@gmail.com
  -
    ins: D. Oliver
    name: David M. Oliver
    org: Guardian Project
    email: david@guardianproject.info
    uri: https://guardianproject.info
normative:
  HTTP: RFC9110

--- abstract

Existing HTTP authentication mechanisms are probeable in the sense that it is
possible for an unauthenticated client to probe whether an origin serves
resources that require authentication. It is possible for an origin to hide the
fact that it requires authentication by not generating Unauthorized status
codes, however that only works with non-cryptographic authentication schemes:
cryptographic schemes (such as signatures or message authentication codes)
require a fresh nonce to be signed, and there is no existing way for the origin
to share such a nonce without exposing the fact that it serves resources that
require authentication. This document proposes a new non-probeable cryptographic
authentication scheme.

--- middle

# Introduction {#introduction}

Existing HTTP authentication mechanisms are probeable in the sense that it is
possible for an unauthenticated client to probe whether an origin serves
resources that require authentication. It is possible for an origin to hide the
fact that it requires authentication by not generating Unauthorized status
codes, however that only works with non-cryptographic authentication schemes:
cryptographic schemes (such as signatures or message authentication codes)
require a fresh nonce to be signed, and there is no existing way for the origin
to share such a nonce without exposing the fact that it serves resources that
require authentication. This document proposes a new non-probeable cryptographic
authentication scheme.

There are scenarios where servers may want to expose the fact that
authentication is required for access to specific resources. This is left for
future work.

## Conventions and Definitions {#conventions}

{::boilerplate bcp14-tagged}

This document uses the Augmented BNF defined in {{!ABNF=RFC5234}} and updated by
{{!ABNF2=RFC7405}} along with the "#rule" extension defined in {{Section 5.6.1
of HTTP}}. The rules below are defined in {{HTTP}} and {{!OID=RFC3061}}.

~~~
  OWS           = <OWS, see {{Section 5.6.3 of HTTP}}>
  quoted-string = <quoted-string, see {{Section 5.6.4 of HTTP}}>
  token         = <token, see {{Section 5.6.2 of HTTP}}>
  token68       = <token68, see {{Section 5.6.3 of HTTP}}>
  oid           = <oid, see {{Section 2 of OID}}>
~~~


# Computing the Authentication Proof {#compute-proof}

This document only defines Transport Authentication for uses of HTTP with TLS.
This includes any use of HTTP over TLS as typically used for HTTP/2, or
HTTP/3 where the transport protocol uses TLS as its authentication and key
exchange mechanism {{?QUIC-TLS=RFC9001}}.

The user agent leverages a TLS keying material exporter {{!KEY-EXPORT=RFC5705}}
to generate a nonce which can be signed using the user-id's key. The keying
material exporter uses a label that starts with the characters
"EXPORTER-HTTP-Transport-Authentication-" (see {{schemes}} for the labels and
contexts used by each scheme). The TLS keying material exporter is used to
generate a 32-byte key which is then used as a nonce.


# Header Field Definition {#header-definition}

The "Transport-Authentication" header allows a user agent to authenticate
its transport connection with an origin server.

~~~
  Transport-Authentication = tpauth-scheme *( OWS ";" OWS param )
  tpauth-scheme            = token
  param                    = token "=" ( token / quoted-string )
~~~


## The u Directive {#directive-u}

The OPTIONAL "u" (user-id) directive specifies the user-id that the user
agent wishes to authenticate. It is encoded using
Base64 ({{Section 4 of !BASE64=RFC4648}}).

~~~
    u = token68
~~~


## The p Directive {#directive-p}

The OPTIONAL "p" (proof) directive specifies the proof that the user agent
provides to attest to possessing the credential that matches its user-id.
It is encoded using Base64 ({{Section 4 of BASE64}}).

~~~
    p = token68
~~~


## The a Directive {#directive-a}

The OPTIONAL "a" (algorithm) directive specifies the algorithm used to compute
the proof transmitted in the "p" directive.

~~~
    a = oid
~~~


# Transport Authentication Schemes {#schemes}

The Transport Authentication Framework allows defining Transport
Authentication Schemes, which specify how to authenticate user-ids. This
documents defined the "Signature" and "HMAC" schemes.


## Signature {#signature}

The "Signature" Transport Authentication Scheme uses asymmetric cyptography.
User agents possess a user-id and a public/private key pair, and origin
servers maintain a mapping of authorized user-ids to their associated public
keys. When using this scheme, the "u", "p", and "a" directives are REQUIRED.
The TLS keying material export label for this scheme is
"EXPORTER-HTTP-Transport-Authentication-Signature" and the associated
context is empty. The nonce is then signed using the selected asymmetric
signature algorithm and transmitted as the proof directive.

For example, the user-id "john.doe" authenticating using Ed25519
{{?ED25519=RFC8410}} could produce the following header (lines are folded to
fit):

~~~
Transport-Authentication: Signature u="am9obi5kb2U=";
a=1.3.101.112;
p="SW5zZXJ0IHNpZ25hdHVyZSBvZiBub25jZSBoZXJlIHdo
aWNoIHRha2VzIDUxMiBiaXRzIGZvciBFZDI1NTE5IQ=="
~~~


## HMAC {#hmac}

The "HMAC" Transport Authentication Scheme uses symmetric cyptography.
User agents possess a user-id and a secret key, and origin servers maintain a
mapping of authorized user-ids to their associated secret key. When using this
scheme, the "u", "p", and "a" directives are REQUIRED.
The TLS keying material export label for this scheme is
"EXPORTER-HTTP-Transport-Authentication-HMAC" and the associated
context is empty. The nonce is then HMACed using the selected HMAC algorithm
and transmitted as the proof directive.

For example, the user-id "john.doe" authenticating using
HMAC-SHA-512 {{?SHA=RFC6234}} could produce the following
header (lines are folded to fit):

~~~
Transport-Authentication: HMAC u="am9obi5kb2U=";
a=2.16.840.1.101.3.4.2.3;
p="SW5zZXJ0IEhNQUMgb2Ygbm9uY2UgaGVyZSB3aGljaCB0YWtl
cyA1MTIgYml0cyBmb3IgU0hBLTUxMiEhISEhIQ=="
~~~


# Intermediary Considerations {#intermediary}

Since Transport Authentication authenticates the underlying transport by
leveraging TLS keying material exporters, it cannot be transparently forwarded
by HTTP intermediaries. HTTP intermediaries that support this specification will
validate the authentication received from the client themselves, then inform the
upstream HTTP server of the presence of valid authentication using some other
mechanism.


# Security Considerations {#security}

Transport Authentication allows a user-agent to authenticate to an origin
server while guaranteeing freshness and without the need for the server
to transmit a nonce to the user agent. This allows the server to accept
authenticated clients without revealing that it supports or expects
authentication for some resources. It also allows authentication without
the user agent leaking the presence of authentication to observers due to
clear-text TLS Client Hello extensions.


# IANA Considerations {#iana}

## Transport-Authentication Header Field {#iana-header}

This document will request IANA to register the following entry in the "HTTP
Field Name" registry maintained at
<[](https://www.iana.org/assignments/http-fields)>:

Field Name:
: Transport-Authentication

Template:
: None

Status:
: provisional (permanent if this document is approved)

Reference:
: This document

Comments:

: None
{: spacing="compact"}


## Transport Authentication Schemes Registry {#iana-schemes}

This document, if approved, requests IANA to create a new "HTTP Transport
Authentication Schemes" Registry. This new registry contains strings and is
covered by the First Come First Served policy from {{Section 4.4 of
!IANA-POLICY=RFC8126}}. Each entry contains an optional "Reference" field.

It initially contains the following entries:

* Signature

* HMAC

The reference for both is this document.

## TLS Keying Material Exporter Labels {#iana-exporter-label}

This document, if approved, requests IANA to register the following entries in
the "TLS Exporter Labels" registry maintained at
<https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#exporter-labels>

* EXPORTER-HTTP-Transport-Authentication-Signature

* EXPORTER-HTTP-Transport-Authentication-HMAC

Both of these entries are listed with the following qualifiers:

DTLS-OK:

: N

Recommended:

: Y

Reference:

: This document
{: spacing="compact"}

--- back

# Acknowledgments {#acknowledgments}
{:numbered="false"}

The authors would like to thank many members of the IETF community, as this
document is the fruit of many hallway conversations. Using the OID for the
signature and HMAC algorithms was inspired by Signature Authentication in
IKEv2.


