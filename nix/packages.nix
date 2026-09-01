{ lib, ... }:
{
  perSystem =
    { pkgs, system, ... }:
    let
      webhook = pkgs.callPackage ./_package.nix { };

      # The image ships this one: a musl-static binary has no closure, so the layers
      # hold the executable and a CA bundle rather than a glibc tree it never calls.
      webhook-static = pkgs.pkgsStatic.callPackage ./_package.nix { };

      image = pkgs.callPackage ./_image.nix { external-dns-desec-webhook = webhook-static; };

      linux = lib.hasSuffix "-linux" system;
    in
    {
      packages = {
        default = webhook;
      }
      // lib.optionalAttrs linux { inherit image webhook-static; };

      apps.default = {
        type = "app";
        program = lib.getExe webhook;
      };

      checks = {
        webhook = webhook;
      }
      // lib.optionalAttrs linux {
        # Runs the binary the image actually contains, not its glibc sibling.
        image-starts =
          pkgs.runCommand "image-starts"
            {
              nativeBuildInputs = [ webhook-static ];
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
