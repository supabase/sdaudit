{ inputs, ... }:
{
  imports = [ inputs.git-hooks.flakeModule ];
  perSystem =
    { config, pkgs, ... }:
    let
      # Wrapper script for golangci-lint that includes go in PATH
      golangci-lint-with-go = pkgs.writeShellScriptBin "golangci-lint" ''
        export PATH="${pkgs.go}/bin:$PATH"
        exec ${pkgs.golangci-lint}/bin/golangci-lint "$@"
      '';
    in
    {
      pre-commit = {
        check.enable = true;
        settings = {
          hooks = {
            treefmt = {
              enable = true;
              package = config.treefmt.build.wrapper;
              pass_filenames = false;
              verbose = true;
            };

            golangci-lint = {
              enable = true;
              package = golangci-lint-with-go;
            };

            gotest = {
              enable = true;
              name = "go test";
              entry = "${pkgs.go}/bin/go test ./...";
              pass_filenames = false;
              types = [ "go" ];
            };
          };
        };
      };
    };
}
