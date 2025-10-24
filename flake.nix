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
      version = self.rev or "dirty";
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
            src = ./.;
            modules = ./gomod2nix.toml;
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
            src = ./.;
            modules = ./gomod2nix.toml;
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
              gomod2nix.packages.${system}.default
            ];
          };
        }
      );
    };
}
