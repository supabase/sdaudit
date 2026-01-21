{ inputs, ... }:
{
  imports = [ inputs.treefmt-nix.flakeModule ];
  perSystem =
    { pkgs, ... }:
    {
      treefmt = {
        programs = {
          deadnix.enable = true;
          nixfmt = {
            enable = true;
            package = pkgs.nixfmt-rfc-style;
          };
          gofmt.enable = true;
        };

        settings = {
          global.excludes = [
            "*.sum"
            "vendor/*"
            "testdata/*"
          ];
        };
      };
    };
}
