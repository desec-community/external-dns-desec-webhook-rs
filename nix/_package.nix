{
  lib,
  rustPlatform,
  cacert,
  cmake,
  ...
}:
rustPlatform.buildRustPackage {
  pname = "external-dns-desec-webhook";

  version = (lib.importTOML ../Cargo.toml).workspace.package.version;

  SSL_CERT_FILE = "${cacert}/etc/ssl/certs/ca-bundle.crt";

  nativeBuildInputs = [ cmake ];

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
