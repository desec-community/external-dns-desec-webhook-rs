{ ... }:
{
  flake.overlays.default = final: _prev: {
    external-dns-desec-webhook = final.callPackage ./_package.nix { };
  };
}
