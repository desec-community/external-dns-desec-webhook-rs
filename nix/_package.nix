# The build definition, shared by this flake's packages, the image and the overlay.
#
# Taking `pkgs` as an argument (rather than closing over this flake's own) is what
# lets the overlay build against the consumer's nixpkgs, so downstream can override
# and cross-compile it.
{
  lib,
  rustPlatform,
  cacert,
  cmake,
  ...
}:
rustPlatform.buildRustPackage {
  pname = "external-dns-desec-webhook";
  version = "0.0.1";

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

  # Naming the inputs explicitly keeps target/ and .direnv/ out of the store, and
  # means an unrelated edit does not invalidate the build.
  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../Cargo.toml
      ../Cargo.lock
      ../crates
      ../README.md
    ];
  };
  cargoLock.lockFile = ../Cargo.lock;

  cargoBuildFlags = [
    "--package"
    "external-dns-desec-webhook"
  ];

  meta = {
    description = "external-dns webhook provider for deSEC DNS";
    mainProgram = "external-dns-desec-webhook";
    license = with lib.licenses; [
      mit
      asl20
    ];
  };
}
