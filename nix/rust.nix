# How Rust is provided to everything else: the overlay, the toolchain, and crane.
#
# The toolchain is defined once here rather than per consumer. crane can only reuse a
# compiled dependency tree across the package, the checks and the devshell if the rustc
# that produced it is the same one everywhere, and nixpkgs' own rustPlatform is not it.
{ inputs, ... }:
{
  perSystem =
    { system, ... }:
    let
      pkgs = import inputs.nixpkgs {
        inherit system;
        overlays = [ inputs.rust-overlay.overlays.default ];
      };

      rust-toolchain = pkgs.rust-bin.fromRustupToolchainFile ../rust-toolchain.toml;
    in
    {
      _module.args = {
        inherit pkgs rust-toolchain;
        craneLib = (inputs.crane.mkLib pkgs).overrideToolchain rust-toolchain;
      };
    };
}
