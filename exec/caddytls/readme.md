# certdx caddy

## Caddyfile example
```caddyfile
{
	auto_https off
    certdx {
        config_path /path/to/certdx_client_config.toml
    }
}

https://example.com {
    tls {
         get_certificate certdx
     }
}
```
