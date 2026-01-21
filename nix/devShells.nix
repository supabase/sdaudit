{ ... }:
{
  perSystem =
    {
      pkgs,
      self',
      config,
      ...
    }:
    let
      # Common development tools
      devTools = with pkgs; [
        # Go development
        go
        gopls
        gotools
        go-tools
        golangci-lint
        delve

        # Build tools
        gnumake
        just

        # Testing and debugging
        jq
        yq-go

        # Treefmt
        config.treefmt.build.wrapper
      ];

      # Container/VM tools for integration testing
      # These allow testing systemd on macOS via Linux containers/VMs
      containerTools =
        with pkgs;
        [
          # Docker CLI (works with Docker Desktop, OrbStack, colima)
          docker-client

          # Lima - Linux VMs on macOS (alternative to Docker)
          lima
        ]
        ++ pkgs.lib.optionals pkgs.stdenv.isLinux [
          # Native systemd tools on Linux
          systemd
        ];

      # Script to start a test VM with systemd
      startTestVm = pkgs.writeShellScriptBin "sdaudit-test-vm" ''
        set -euo pipefail

        LIMA_INSTANCE="sdaudit-test"

        # Check if lima instance exists
        if ! limactl list -q | grep -q "^$LIMA_INSTANCE$"; then
          echo "Creating Lima VM with Ubuntu 24.04..."
          limactl create --name="$LIMA_INSTANCE" template://ubuntu-lts
        fi

        # Start if not running
        if ! limactl list --json | jq -e ".[] | select(.name == \"$LIMA_INSTANCE\") | .status == \"Running\"" > /dev/null 2>&1; then
          echo "Starting Lima VM..."
          limactl start "$LIMA_INSTANCE"
        fi

        echo "VM is ready. Use 'limactl shell $LIMA_INSTANCE' to connect."
        echo "Or run: sdaudit-in-vm <command>"
      '';

      # Script to run commands in the test VM
      runInVm = pkgs.writeShellScriptBin "sdaudit-in-vm" ''
        set -euo pipefail
        LIMA_INSTANCE="sdaudit-test"
        limactl shell "$LIMA_INSTANCE" -- "$@"
      '';

      # Script to run tests in a Docker container with systemd
      runInContainer = pkgs.writeShellScriptBin "sdaudit-test-container" ''
        set -euo pipefail

        IMAGE="''${1:-ubuntu:24.04}"
        shift || true

        echo "Starting systemd-enabled container..."
        # Run with systemd as init (requires privileged or specific capabilities)
        docker run --rm -it \
          --privileged \
          --cgroupns=host \
          -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
          -v "$(pwd):/workspace:ro" \
          -w /workspace \
          "$IMAGE" \
          /bin/bash -c "
            # Install systemd if not present
            if ! command -v systemctl &> /dev/null; then
              apt-get update && apt-get install -y systemd
            fi
            # Run the provided command or drop to shell
            if [ \$# -gt 0 ]; then
              exec \"\$@\"
            else
              exec /bin/bash
            fi
          " -- "$@"
      '';

      # Script to build and load sdaudit into a test container
      loadInContainer = pkgs.writeShellScriptBin "sdaudit-load-container" ''
        set -euo pipefail

        echo "Building sdaudit..."
        nix build .#sdaudit

        echo "Loading into container..."
        docker run --rm -it \
          --privileged \
          --cgroupns=host \
          -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
          -v "$(pwd)/result/bin:/opt/sdaudit:ro" \
          -w /opt/sdaudit \
          ubuntu:24.04 \
          /bin/bash
      '';

      # NixOS VM for comprehensive testing (Linux only or via remote builder)
      nixosTestVm = pkgs.lib.optionalAttrs pkgs.stdenv.isLinux {
        test-vm = pkgs.nixosTest {
          name = "sdaudit-integration";

          nodes.machine =
            { pkgs, ... }:
            {
              # Ubuntu-like systemd configuration
              boot.loader.systemd-boot.enable = true;

              # Add some test services
              systemd.services.test-insecure = {
                description = "Intentionally insecure test service";
                wantedBy = [ "multi-user.target" ];
                serviceConfig = {
                  ExecStart = "${pkgs.coreutils}/bin/sleep infinity";
                  # Intentionally missing security hardening for testing
                };
              };

              systemd.services.test-secure = {
                description = "Well-configured test service";
                wantedBy = [ "multi-user.target" ];
                serviceConfig = {
                  ExecStart = "${pkgs.coreutils}/bin/sleep infinity";
                  NoNewPrivileges = true;
                  PrivateTmp = true;
                  ProtectSystem = "strict";
                  ProtectHome = true;
                  DynamicUser = true;
                };
              };

              environment.systemPackages = [ self'.packages.sdaudit ];
            };

          testScript = ''
            machine.wait_for_unit("multi-user.target")
            machine.succeed("sdaudit scan --format json > /tmp/results.json")
            machine.succeed("test -s /tmp/results.json")
          '';
        };
      };

    in
    {
      devShells = {
        default = pkgs.mkShell {
          packages =
            devTools
            ++ containerTools
            ++ [
              startTestVm
              runInVm
              runInContainer
              loadInContainer
            ];

          shellHook = ''
            export HISTFILE=.history
            ${config.pre-commit.installationScript}

            echo ""
            echo "sdaudit development shell"
            echo ""
            echo "Available commands:"
            echo "  nix fmt              - Format Go and Nix files"
            echo "  nix build            - Build sdaudit"
            echo "  nix flake check      - Run all checks"
            echo ""
            echo "Testing on macOS (via Linux container/VM):"
            echo "  sdaudit-test-vm       - Start Ubuntu 24.04 VM (via Lima)"
            echo "  sdaudit-in-vm <cmd>   - Run command in test VM"
            echo "  sdaudit-test-container [image] - Run in systemd-enabled container"
            echo "  sdaudit-load-container - Build and load sdaudit into container"
            echo ""
          '';
        };

        # Minimal shell for CI
        ci = pkgs.mkShell {
          packages = with pkgs; [
            go
            golangci-lint
            config.treefmt.build.wrapper
          ];
        };
      };

      # Add NixOS VM test as a check (Linux only)
      checks = nixosTestVm;
    };
}
