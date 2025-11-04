{
  description = "kauth - Kubernetes OIDC authentication system";
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    gomod2nix = {
      url = "github:nix-community/gomod2nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };
  outputs =
    {
      self,
      nixpkgs,
      gomod2nix,
    }:
    let
      systems = [ "x86_64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
      pkgsFor =
        system:
        import nixpkgs {
          inherit system;
          overlays = [ gomod2nix.overlays.default ];
        };
      # For package metadata - will be refined during build
      version = self.shortRev or self.lastModifiedDate or "dev";
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
        in
        {
          default = self.packages.${system}.kauth;
          kauth =
            let
              # Get version from git describe if available, otherwise use fallback
              gitVersion = pkgs.runCommand "git-version" { } ''
                cd ${self}
                ${pkgs.git}/bin/git describe --tags --always --dirty 2>/dev/null | sed 's/^v//' > $out || echo "${version}" > $out
              '';
              versionString = builtins.readFile gitVersion;
            in
            pkgs.buildGoApplication {
              pname = "kauth";
              version = versionString;
              src = ./.;
              modules = ./gomod2nix.toml;
              subPackages = [ "cmd/kauth" ];
              ldflags = [
                "-s"
                "-w"
                "-X github.com/krezh/kauth/cmd/kauth/cmd.Version=${versionString}"
                "-X github.com/krezh/kauth/cmd/kauth/cmd.GitCommit=${self.rev or "unknown"}"
              ];
            };
          kauth-server =
            let
              # Get version from git describe if available, otherwise use fallback
              gitVersion = pkgs.runCommand "git-version" { } ''
                cd ${self}
                ${pkgs.git}/bin/git describe --tags --always --dirty 2>/dev/null | sed 's/^v//' > $out || echo "${version}" > $out
              '';
              versionString = builtins.readFile gitVersion;
            in
            pkgs.buildGoApplication {
              pname = "kauth-server";
              version = versionString;
              src = ./.;
              modules = ./gomod2nix.toml;
              subPackages = [ "cmd/kauth-server" ];
              ldflags = [
                "-s"
                "-w"
                "-X github.com/krezh/kauth/cmd/kauth/cmd.Version=${versionString}"
                "-X github.com/krezh/kauth/cmd/kauth/cmd.GitCommit=${self.rev or "unknown"}"
              ];
            };
        }
      );
      devShells = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
        in
        {
          default = pkgs.mkShell {
            packages = with pkgs; [
              go
              gopls
              gotools
              golangci-lint
              gomod2nix.packages.${system}.default
            ];
          };
        }
      );
    };
}
