# Example of Encrypted Content Encoding over HTTP

## Introduction ##
The following example was inspired by [RFC8188][rfc8188] which was published as
a propsed standard June 2017 by M. Thomson and the Mozilla organization. It
uses a slightly modified version of the [.NET implementation][lib-ece] by
Tomasz Pęczek.

The example is currently just a proof of concept that it is possible to
communicate with REST endpoint using end-to-end encryption.

## Getting Started ##
To run the example first start the Server application, then run the Client
application. The Client application will issue a GET and a POST request
respectively and output the encrypted and decrypted content to the console
window.

[rfc8188]: https://tools.ietf.org/html/rfc8188
[lib-ece]: https://github.com/tpeczek/Lib.Net.Http.EncryptedContentEncoding
