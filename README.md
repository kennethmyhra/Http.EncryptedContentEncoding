# Example of Encrypted Content Encoding over HTTP and RESTful services

## Introduction
The following example was inspired by [RFC8188][rfc8188] which was published as
a proposed standard June 2017 by M. Thomson and the Mozilla organization. It
uses a slightly modified version of the [.NET implementation][lib-ece] by
Tomasz Pęczek.

The example is a proof of concept of end-to-end encryption communication with
with a REST endpoint.

## Getting Started
To run the example first start the Server application, then run the Client
application. The Client application will issue a GET and a POST request
respectively and output the encrypted and decrypted content to the console
window.

## Contributing
We are welcoming contributors!

[rfc8188]: https://tools.ietf.org/html/rfc8188
[lib-ece]: https://github.com/tpeczek/Lib.Net.Http.EncryptedContentEncoding
