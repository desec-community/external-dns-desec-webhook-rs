{ lib, ... }:
{
  perSystem =
    { pkgs, system, ... }:
    let
      webhook = pkgs.callPackage ./_package.nix { };
      image = pkgs.callPackage ./_image.nix { external-dns-desec-webhook = webhook; };

      # Docker images are Linux-only, and the image-starts check additionally needs to
      # run the binary, so it cannot cross-build either.
      linux = lib.hasSuffix "-linux" system;
    in
    {
      packages = {
        default = webhook;
      }
      // lib.optionalAttrs linux { inherit image; };

      apps.default = {
        type = "app";
        program = lib.getExe webhook;
      };

      checks = {
        webhook = webhook;
      }
      // lib.optionalAttrs linux {
        # A green `cargo build` says nothing about whether the image starts: the binary
        # constructs a reqwest client at startup, and rustls loads the system trust
        # store at that moment. Without a CA bundle in the image this is the only check
        # that fails. --check-config exits before any request is made.
        image-starts =
          pkgs.runCommand "image-starts"
            {
              nativeBuildInputs = [ webhook ];
            }
            ''
              export SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt
              external-dns-desec-webhook --check-config \
                --api-token dummy --domain-filter example.com
              touch $out
            '';
      };
    };
}
