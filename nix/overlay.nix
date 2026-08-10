{ inputs, ... }:
{
  flake.overlays.default = final: _prev: {
    external-dns-desec-webhook = final.callPackage ./_package.nix {
      # Deliberately not this flake's craneLib: that one is pinned to a rust-overlay
      # toolchain a consumer's nixpkgs need not have. Instantiating against `final`
      # keeps the package building with whatever rustc the consumer already uses.
      craneLib = inputs.crane.mkLib final;
    };
  };
}
