{
  description = "kauth - Kubernetes OIDC authentication system";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];

      forAllSystems = nixpkgs.lib.genAttrs systems;

      pkgsFor = system: nixpkgs.legacyPackages.${system};

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

          kauth = pkgs.buildGoModule {
            pname = "kauth";
            inherit version;
            src = ./.;
            vendorHash = "sha256-9M+zn2mgEwbntGFpaFlRJ/Gl93yqm93tYyWYod9/W00=";
            subPackages = [ "cmd/kauth" ];
            ldflags = [
              "-s"
              "-w"
            ];
          };

          kauth-server = pkgs.buildGoModule {
            pname = "kauth-server";
            inherit version;
            src = ./.;
            vendorHash = "sha256-9M+zn2mgEwbntGFpaFlRJ/Gl93yqm93tYyWYod9/W00=";
            subPackages = [ "cmd/kauth-server" ];
            ldflags = [
              "-s"
              "-w"
            ];
          };

          docker = pkgs.dockerTools.buildLayeredImage {
            name = "kauth-server";
            tag = version;
            contents = [
              self.packages.${system}.kauth-server
              pkgs.cacert
            ];
            config = {
              Cmd = [ "${self.packages.${system}.kauth-server}/bin/kauth-server" ];
              ExposedPorts."8080/tcp" = { };
              Env = [ "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt" ];
            };
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
            ];
          };
        }
      );
    };
}
