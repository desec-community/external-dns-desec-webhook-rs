{
  lib,
  dockerTools,
  cacert,
  runCommand,
  external-dns-desec-webhook,
}:
dockerTools.streamLayeredImage {
  name = "ghcr.io/desec-community/external-dns-desec-webhook-rs";
  tag = "latest";

  created = "1970-01-01T00:00:00Z";

  contents = [
    cacert
    (runCommand "image-etc" { } ''
      mkdir -p $out/etc
      echo 'webhook:x:1000:1000:webhook:/nonexistent:/sbin/nologin' > $out/etc/passwd
      echo 'webhook:x:1000:' > $out/etc/group
      echo 'nogroup:x:65534:' >> $out/etc/group
    '')
  ];

  config = {
    Entrypoint = [ (lib.getExe external-dns-desec-webhook) ];
    User = "1000:1000";

    ExposedPorts = {
      "8888/tcp" = { };
      "8080/tcp" = { };
    };

    Env = [
      "SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt"
    ];

    Labels = {
      "org.opencontainers.image.source" =
        "https://github.com/desec-community/external-dns-desec-webhook-rs";
      "org.opencontainers.image.licenses" = "MIT OR Apache-2.0";
      "org.opencontainers.image.description" = "external-dns webhook provider for deSEC DNS";
    };
  };
}
