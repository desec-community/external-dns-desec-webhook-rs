{ lib, ... }:
{
  perSystem =
    {
      pkgs,
      craneLib,
      system,
      ...
    }:
    let
      webhook = pkgs.callPackage ./_package.nix { inherit craneLib; };
      image = pkgs.callPackage ./_image.nix { external-dns-desec-webhook = webhook; };

      # Clippy, the tests and the docs are three more consumers of the one dependency
      # build the package already paid for, so each only compiles this crate.
      #
      # They are also leaves: nothing builds on their target directory, and crane would
      # otherwise re-export a copy of it from each, putting three near-identical 460 MB
      # archives into a store that CI has to carry between runs.
      checkArgs = webhook.commonArgs // {
        inherit (webhook) cargoArtifacts;
        doInstallCargoArtifacts = false;
      };

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

        clippy = craneLib.cargoClippy (
          checkArgs // { cargoClippyExtraArgs = "--all-targets -- -D warnings"; }
        );

        # The live tests talk to the real deSEC API and are #[ignore]d, so this runs the
        # mock suite only, exactly as `just test` did.
        tests = craneLib.cargoTest checkArgs;

        docs = craneLib.cargoDoc checkArgs;
      }
      // lib.optionalAttrs linux {
        # A green build says nothing about whether the image starts: the binary
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
