# Legal notice

This project is independent research into Apple Watch interoperability on Linux.
Use it only with devices you own or are authorised to test.
It does not bypass Activation Lock or provide Apple Account sign-in.
The maintainers will not accept contributions that add these functions.

This notice is not legal advice. Applicable laws and contracts depend on your
country and circumstances. Apple services remain subject to Apple's terms.
The policies below do not change the [MIT licence](LICENSE).

## Legal basis in the European Union

The authors rely on national laws that implement
[Directive 2009/24/EC](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX%3A32009L0024),
Articles 5(3), 6 and 8(2). These provisions permit certain study and
interoperability work by people entitled to use the software.

Article 6 permits decompilation only when essential information is not readily
available. Work must be limited to the parts needed for interoperability.
Use the information only for interoperability. Share it only where necessary
for that purpose. Do not use it to create software substantially similar in its
expression or otherwise infringe copyright. Article 6(3) sets further limits
that protect the copyright holder's legitimate interests and normal exploitation
of the program.

[Directive (EU) 2016/943](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX%3A32016L0943),
Article 3(1)(b), permits certain study of public or lawfully held products.
A legally valid duty to limit acquisition of trade secrets can restrict this
exception. It does not give general permission to disclose trade secrets.

These provisions do not give general permission to bypass protection measures
or access protected services. Their conditions and national implementations
apply. Other countries have different rules.

## Contributions and private data

Submit only material you have the right to share. Independent code, protocol
facts, synthetic test values and sanitised documentation are welcome.
Do not submit Apple software, disassembly, memory dumps, real credentials,
account data, device identifiers or private captures.

Pairing files contain private keys. Logs, captures and saved activation responses
can contain device or account data. Keep these files private, including files
saved outside the default `runs/` directory.

## Activation traffic

The companion forwards the Watch's activation request through verified TLS.
Destinations and redirects must use HTTPS on port 443 at `apple.com` or its
subdomains. The HTTP client manages headers and cookies; the companion sets
`X-iOS-Activation-Medium` to `WiFi`.
It does not create or alter Apple's signed activation record.
Responses are also saved in the private state directory for debugging.

## Risk, warranty and affiliation

The software is experimental. It was demonstrated on Apple Watch SE 3 with
watchOS 26.4. Updates or other devices can cause failures.
You may need to erase or restore the Watch. The software and cryptographic code
have not had a security audit. The MIT licence provides no warranty.

This project is not affiliated with, endorsed by or sponsored by Apple Inc.
Apple and its product names are Apple's trademarks. These names identify the
products involved.

## Reports

Report security problems privately to the maintainers or through a private
repository security advisory. Report Apple product vulnerabilities through
[Apple Product Security](https://support.apple.com/en-us/102549).
Contact the maintainers if material in this repository should not be public.
