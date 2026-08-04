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
          # The same mdformat treefmt drives, so `just readme` normalises its output
          # exactly the way the pre-commit hook would.
          config.treefmt.build.programs.mdformat
          config.hk-nix.package
          pkgs.deadnix
          pkgs.stdenv.cc
          pkgs.git
          pkgs.just
          pkgs.cargo-readme
          # aws-lc-sys, which reqwest's rustls backend pulls in, is a cmake + bindgen
          # build rather than pure Rust.
          pkgs.cmake
          # The release workflow pushes and signs with these, so pin them here rather
          # than through a marketplace action.
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
