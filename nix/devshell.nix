{ inputs, ... }:
{
  imports = [ inputs.devshell.flakeModule ];
  perSystem =
    { config, pkgs, ... }:
    let
      rust-toolchain = pkgs.rust-bin.fromRustupToolchainFile ../rust-toolchain.toml;
    in
    {
      devshells.default = {
        packages = [
          rust-toolchain
          config.treefmt.build.wrapper
          config.treefmt.build.programs.mdformat
          config.hk-nix.package
          pkgs.deadnix
          pkgs.stdenv.cc
          pkgs.git
          pkgs.just
          pkgs.cargo-readme
          pkgs.cmake
          pkgs.git-cliff
          pkgs.skopeo
          pkgs.syft
        ];

        env = [
          {
            name = "RUST_BACKTRACE";
            value = "1";
          }
        ];

        devshell.motd = "";
        devshell.startup.hk.text = config.hk-nix.shellHook;
      };
    };
}
