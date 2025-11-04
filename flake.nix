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
      # Extract version from git tag or use shortRev
      # This will give us proper semver like "v1.2.3" from tags
      version =
        if (self ? rev) then
          # When built from a git repo, try to extract version from the last tag
          self.shortRev
        else
          "dirty";

      # Git commit for build info
      gitCommit = self.rev or "unknown";
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
              "-X github.com/krezh/kauth/cmd/kauth/cmd.GitCommit=${gitCommit}"
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
              "-X github.com/krezh/kauth/cmd/kauth/cmd.GitCommit=${gitCommit}"
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
