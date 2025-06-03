# certdx caddy

## Caddyfile example
```caddyfile
{
    auto_https off
    certdx {
        retry_count 5

        # http or grpc
        mode http

        # only take effect in gRPC mode. If client lost connection from
        # main server or standby server, will reconnect to server every
        # reconnectInterval. Also, if client fallback to standby server,
        # will retry connect to main server every reconnectInterval.
        reconnect_interval 10m

        http {
            main_server {
                url https://certdxserver.example.com:19198/1145141919810
                authMode token
                token KFCCrazyThursdayVMe50

                # authMode mtls
                # ca /path/to/grpc/mtls/ca.pem
                # certificate /path/to/grpc/mtls/client/cert.pem
                # key /path/to/grpc/mtls/client/private.key
            }

            # optional
            standby_server {
                url http://mybackupserver.local:11451/1919810
            }
        }

        GRPC {
            main_server {
                server grpc.example.com:9999
                ca /path/to/grpc/mtls/ca.pem
                certificate /path/to/grpc/mtls/client/cert.pem
                key /path/to/grpc/mtls/client/private.key
            }

            # optional
            standby_server {
                server 192.168.1.2:9090
                ca /path/to/grpc/mtls/ca.pem
                certificate /path/to/grpc/mtls/client/cert.pem
                key /path/to/grpc/mtls/client/private.key
            }
        }

        # define a certificate with following domains
        certificate cert-id {
            example.com
            6.example.com
        }
    }
}

https://example.com {
    tls {
        # use previously defined cert
        get_certificate certdx cert-id
     }
}
```
