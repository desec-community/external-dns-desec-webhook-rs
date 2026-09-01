# Git hooks via hk-nix. The generated hk.pkl stays in the store; the devshell startup hook
# (see devshell.nix) installs hooks that reach it through an HK_FILE wrapper, so nothing is
# written into the repo. The gitignore entry covers checkouts left over from when it was.
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
      # Flags to reproduce the committed README.md from README.tpl and the crate docs.
      readmeArgs = "--project-root crates/external-dns-desec-webhook --input src/lib.rs --template ../../README.tpl";

      # Reference tools by absolute store path: the `nix flake check` hk-check sandbox
      # runs hooks without the devshell PATH, so a bare `treefmt` is not found there.
      treefmt = lib.getExe config.treefmt.build.wrapper;

      # Called by store path rather than via `cargo readme`, so the cargo-subcommand
      # argv has to be supplied by hand: without it clap only prints its usage.
      cargo-readme = "${lib.getExe' pkgs.cargo-readme "cargo-readme"} readme";

      # cargo-readme emits markdown that mdformat then rewrites (link reference
      # definitions move to the end of the file), so the raw output never equals the
      # committed README.md and the two hooks would undo each other forever. Reuse
      # treefmt's own mdformat so the plugin set cannot drift from the pre-commit one.
      mdformat = config.treefmt.settings.formatter.mdformat.command;

      readme = "${cargo-readme} ${readmeArgs} | ${mdformat} -";

      # Reads git's pre-push stdin, one `<local ref> <local sha> <remote ref> <remote sha>`
      # line per ref. The version has to come from the tagged commit rather than from the
      # working tree, which is why `just check-version` cannot serve here: a tag can be
      # pushed from any checkout, including one several commits further along.
      #
      # Catching it at push time is the point. The release workflow runs the same check, but
      # by then the tag exists on the remote, and a tag that has already been fetched is
      # awkward to move.
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
            # An all-zero sha is a deletion: there is no commit to read a version from.
            case "$local_sha" in *[!0]*) ;; *) continue ;; esac

            tag="''${local_ref#refs/tags/}"
            # An annotated tag pushes the sha of the tag object, not of the commit it points
            # at. Peeled here so the sha in the message below is one that can be checked out.
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
          # The golden corpus is captured from a real external-dns, so a hand-edit can
          # silently stop being valid JSON. Parsing it needs no network and no build.
          golden = {
            glob = "crates/external-dns-desec-webhook/tests/golden/*.json";
            check = "${lib.getExe pkgs.jq} -e . {{files}} > /dev/null";
          };
        };

        # hk runs this one itself, so no tool needs pinning. Note it has no
        # equivalent of --require-scope; --allowed-types is the only policy knob.
        "commit-msg".steps.conventional.builtin = config.hk-nix.builtins.check_conventional_commit;
      };
    };
}
