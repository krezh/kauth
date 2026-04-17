{
  description = "kauth - Kubernetes OIDC authentication system";
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    go-overlay = {
      url = "git+https://github.com/purpleclay/go-overlay?shallow=1";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };
  outputs =
    {
      self,
      nixpkgs,
      go-overlay,
    }:
    let
      systems = [ "x86_64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
      pkgsFor =
        system:
        import nixpkgs {
          inherit system;
          overlays = [ go-overlay.overlays.default ];
        };
      releaseManifest = builtins.fromJSON (builtins.readFile ./.release-please-manifest.json);
      version = releaseManifest.".";
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
        in
        {
          default = self.packages.${system}.kauth;
          kauth = pkgs.buildGoApplication {
            pname = "kauth";
            inherit version;
            src = builtins.path {
              path = ./.;
              name = "kauth-src";
            };
            go = pkgs.go-bin.fromGoMod ./go.mod;
            modules = ./govendor.toml;
            subPackages = [ "cmd/kauth" ];
            ldflags = [
              "-s"
              "-w"
              "-X github.com/krezh/kauth/cmd/kauth/cmd.Version=${version}"
              "-X github.com/krezh/kauth/cmd/kauth/cmd.GitCommit=${self.rev or "unknown"}"
            ];
          };
          kauth-server = pkgs.buildGoApplication {
            pname = "kauth-server";
            inherit version;
            src = builtins.path {
              path = ./.;
              name = "kauth-server-src";
            };
            modules = ./govendor.toml;
            go = pkgs.go-bin.fromGoMod ./go.mod;
            subPackages = [ "cmd/kauth-server" ];
            ldflags = [
              "-s"
              "-w"
              "-X github.com/krezh/kauth/cmd/kauth/cmd.Version=${version}"
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
              govulncheck
              go-overlay.packages.${system}.govendor
            ];
          };
        }
      );
    };
}
