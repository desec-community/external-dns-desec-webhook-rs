{ inputs, ... }:
{
  imports = [ inputs.hk-nix.flakeModules.default ];
  perSystem =
    {
      config,
      pkgs,
      lib,
      ...
    }:
    let
      readmeArgs = "--project-root crates/external-dns-desec-webhook --input src/lib.rs --template ../../README.tpl";

      treefmt = lib.getExe config.treefmt.build.wrapper;

      cargo-readme = "${lib.getExe' pkgs.cargo-readme "cargo-readme"} readme";

      mdformat = config.treefmt.settings.formatter.mdformat.command;

      readme = "${cargo-readme} ${readmeArgs} | ${mdformat} -";

      check-tag-version = pkgs.writeShellApplication {
        name = "check-tag-version";
        runtimeInputs = [
          pkgs.git
          pkgs.gnused
        ];
        text = ''
          status=0
          while read -r local_ref local_sha _remote_ref _remote_sha; do
            case "$local_ref" in refs/tags/v*) ;; *) continue ;; esac
            case "$local_sha" in *[!0]*) ;; *) continue ;; esac

            tag="''${local_ref#refs/tags/}"
            commit="$(git rev-parse "$local_sha^{commit}")"
            crate="$(git show "$commit:Cargo.toml" \
              | sed -n '/^\[workspace\.package\]/,/^\[/{ s/^version = "\(.*\)"/\1/p }')"

            if [ "$tag" != "v$crate" ]; then
              echo "$tag names v$crate at ''${commit:0:12}" >&2
              status=1
            fi
          done
          exit "$status"
        '';
      };
    in
    {
      hk-nix.settings.hooks = {
        "pre-commit" = {
          fix = true;
          stash = "git";
          steps.treefmt = {
            check = "${treefmt} --fail-on-change --no-cache {{files}}";
            fix = "${treefmt} {{files}}";
          };
        };

        "pre-push".steps = {
          deadnix = {
            glob = "*.nix";
            check = "${lib.getExe pkgs.deadnix} --fail {{files}}";
          };
          clippy = {
            check = "cargo clippy --all-targets --all-features -- -D warnings";
          };
          readme = {
            check = "${readme} | diff - README.md";
            fix = "${readme} > README.md";
          };
          lock-check = {
            check = "cargo metadata --locked --format-version 1 > /dev/null";
          };
          tag-version = {
            check = ''printf '%s\n' "{{hook_stdin}}" | ${lib.getExe check-tag-version}'';
          };
          golden = {
            glob = "crates/external-dns-desec-webhook/tests/golden/*.json";
            check = "${lib.getExe pkgs.jq} -e . {{files}} > /dev/null";
          };
        };

        "commit-msg".steps.conventional.builtin = config.hk-nix.builtins.check_conventional_commit;
      };
    };
}
