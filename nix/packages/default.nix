{ ... }:
{
  perSystem =
    { pkgs, self', ... }:
    {
      checks = {
        # Build check - ensures the package builds successfully
        build = self'.packages.sdaudit;

        # Test check - runs go test
        test = pkgs.stdenv.mkDerivation {
          name = "sdaudit-test";
          src = ../..;
          nativeBuildInputs = [ pkgs.go ];
          buildPhase = ''
            export HOME=$TMPDIR
            export GOCACHE=$TMPDIR/go-cache
            export GOMODCACHE=$TMPDIR/go-mod
            go test ./... -v
          '';
          installPhase = ''
            mkdir -p $out
            echo "Tests passed" > $out/result
          '';
        };

        # Lint check - runs golangci-lint
        lint = pkgs.stdenv.mkDerivation {
          name = "sdaudit-lint";
          src = ../..;
          nativeBuildInputs = [
            pkgs.go
            pkgs.golangci-lint
          ];
          buildPhase = ''
            export HOME=$TMPDIR
            export GOCACHE=$TMPDIR/go-cache
            export GOMODCACHE=$TMPDIR/go-mod
            golangci-lint run ./...
          '';
          installPhase = ''
            mkdir -p $out
            echo "Lint passed" > $out/result
          '';
        };
      };

      packages = {
        default = self'.packages.sdaudit;

        sdaudit = pkgs.buildGoModule {
          pname = "sdaudit";
          version = "0.1.0";
          src = ../..;

          vendorHash = "sha256-PFRrh1XjBfbSPRCanPP4FkE8nuEbFbzjYp8IX2ckNUA=";

          ldflags = [
            "-s"
            "-w"
            "-X main.version=0.1.0"
          ];

          meta = with pkgs.lib; {
            description = "Comprehensive systemd auditing tool for Ubuntu 24.04";
            homepage = "https://github.com/supabase/sdaudit";
            license = licenses.mit;
            maintainers = [ ];
            mainProgram = "sdaudit";
          };
        };

      }
      // pkgs.lib.optionalAttrs pkgs.stdenv.isLinux {
        # Ubuntu 24.04 container image for testing (Linux only)
        test-container = pkgs.dockerTools.buildImage {
          name = "sdaudit-test";
          tag = "latest";

          copyToRoot = pkgs.buildEnv {
            name = "image-root";
            paths = [
              pkgs.bashInteractive
              pkgs.coreutils
              pkgs.systemd
              self'.packages.sdaudit
            ];
            pathsToLink = [
              "/bin"
              "/lib"
              "/etc"
            ];
          };

          config = {
            Cmd = [ "/bin/bash" ];
            Env = [ "PATH=/bin" ];
          };
        };
      };
    };
}
