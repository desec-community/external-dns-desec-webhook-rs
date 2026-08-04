# The OCI image, built from the same derivation `nix flake check` verifies, so the
# artifact that ships is the artifact that was tested.
#
# streamLayeredImage rather than buildLayeredImage: it produces a script that writes
# the tarball to stdout, so CI never materialises a few hundred MB in the Nix store.
# Pipe it straight into `skopeo copy docker-archive:/dev/stdin` or `docker load`.
#
# Single-arch by construction; the manifest list is assembled in the release workflow
# from one image per native runner, because that is a registry operation.
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

  # Epoch, so the same inputs give the same digest.
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

    # Both ports, unlike the Go image this replaces, which declared only 8888 and left
    # the health and metrics port undocumented in the image metadata.
    ExposedPorts = {
      "8888/tcp" = { };
      "8080/tcp" = { };
    };

    Env = [
      # rustls reads the trust store when the client is *constructed*, so a missing
      # bundle is a startup failure rather than a first-request one -- which is to say
      # one that every unit test passes. checks.image-starts is what catches it.
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
