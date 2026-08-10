# The build definition, shared by this flake's packages, the checks, the image and the
# overlay.
#
# Taking `pkgs` as an argument (rather than closing over this flake's own) is what
# lets the overlay build against the consumer's nixpkgs, so downstream can override
# and cross-compile it. craneLib comes in the same way, for the same reason.
#
# Dependencies compile in their own derivation, whose inputs are Cargo.lock and the
# toolchain rather than the crate's sources. A commit that touches only src/ therefore
# reuses it, which is the difference between a four-minute CI build and a short one.
# `passthru` re-exports the pieces so the checks build against that same derivation
# instead of each compiling the tree again.
{
  lib,
  craneLib,
  cacert,
  cmake,
  ...
}:
let
  commonArgs = {
    pname = "external-dns-desec-webhook";
    version = "0.0.1";

    # Naming the inputs explicitly keeps target/ and .direnv/ out of the store, and
    # means an unrelated edit does not invalidate the build. README.md is here because
    # lib.rs includes it as the crate-level doc.
    src = lib.fileset.toSource {
      root = ../.;
      fileset = lib.fileset.unions [
        ../Cargo.toml
        ../Cargo.lock
        ../crates
        ../README.md
      ];
    };

    # Nothing here needs a host/target distinction to blur, and it makes cmake below
    # land in the right place when the overlay cross-compiles this.
    strictDeps = true;

    # reqwest's rustls backend loads the system trust store when a client is constructed,
    # not when a request is made, so every test that builds a Client fails in the sandbox
    # with "No CA certificates were loaded from the system". The mock tests only ever talk
    # to loopback over plain HTTP; this is purely to get past client construction.
    #
    # The same fact reappears at runtime, because the constructing process is then the
    # shipped binary rather than the test harness -- see _image.nix, which has to put a
    # trust store in the image and point SSL_CERT_FILE at it for exactly this reason.
    SSL_CERT_FILE = "${cacert}/etc/ssl/certs/ca-bundle.crt";

    # aws-lc-sys, reached through reqwest's rustls feature, builds C and assembly.
    nativeBuildInputs = [ cmake ];
  };

  cargoArtifacts = craneLib.buildDepsOnly commonArgs;
in
craneLib.buildPackage (
  commonArgs
  // {
    inherit cargoArtifacts;

    # checks.tests runs the suite as its own derivation, so a red run names the failure
    # rather than reporting that the package did not build.
    doCheck = false;

    meta = {
      description = "external-dns webhook provider for deSEC DNS";
      mainProgram = "external-dns-desec-webhook";
      license = with lib.licenses; [
        mit
        asl20
      ];
    };

    passthru = { inherit commonArgs cargoArtifacts; };
  }
)
