{ lib, ... }:
{
  perSystem =
    { pkgs, system, ... }:
    let
      webhook = pkgs.callPackage ./_package.nix { };
      image = pkgs.callPackage ./_image.nix { external-dns-desec-webhook = webhook; };

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
