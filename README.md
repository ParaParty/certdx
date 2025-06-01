# Introduction
Certdx is A centralized SSL certificate daemon including server and client.
One centralized server manage all certificates and multiple clients use the certificates.

# Caddy Plugin
It has caddy plugin can be used as [certifacate manager](https://caddyserver.com/docs/caddyfile/directives/tls#certificate-managers) in caddy.

Usage example
```
{
    auto_https off
    certdx {
        http {
            main_server {
                url https://certdxserver.example.com:19198/1145141919810
                token KFCCrazyThursdayVMe50
            }
        }

        certificate cert-name {
            your.domain
            *.your.domain
        }
    }
}


https://your.domain:114514 {
        tls {
                get_certificate certdx cert-name
        }
        reverse_proxy 127.0.0.1:19198
}
```
[Full Example](exec/caddytls/readme.md)

You can refer [get_certificate](https://caddyserver.com/docs/caddyfile/directives/tls#get_certificate) for more information
