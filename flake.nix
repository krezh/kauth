{
  description = "kauth - Kubernetes OIDC authentication system";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        
        version = if (self ? rev) then self.rev else "dirty";
        
        kauth-cli = pkgs.buildGoModule {
          pname = "kauth";
          inherit version;
          
          src = ./.;
          
          vendorHash = "sha256-dUZSddFiOuuaG5TGF4DX0yTq33u/2FsYbekos/YwecQ="; # Will be updated
          
          subPackages = [ "cmd/kauth" ];
          
          ldflags = [
            "-s"
            "-w"
            "-X kauth/cmd/kauth/cmd.Version=${version}"
            "-X kauth/cmd/kauth/cmd.GitCommit=${version}"
            "-X kauth/cmd/kauth/cmd.BuildDate=1970-01-01T00:00:00Z"
          ];
          
          meta = with pkgs.lib; {
            description = "Kubernetes OIDC authentication CLI";
            homepage = "https://github.com/yourusername/kauth";
            license = licenses.mit;
            maintainers = [ ];
          };
        };
        
        kauth-server = pkgs.buildGoModule {
          pname = "kauth-server";
          inherit version;
          
          src = ./.;
          
          vendorHash = "sha256-dUZSddFiOuuaG5TGF4DX0yTq33u/2FsYbekos/YwecQ="; # Will be updated
          
          subPackages = [ "cmd/kauth-server" ];
          
          ldflags = [
            "-s"
            "-w"
          ];
          
          meta = with pkgs.lib; {
            description = "Kubernetes OIDC authentication server";
            homepage = "https://github.com/yourusername/kauth";
            license = licenses.mit;
            maintainers = [ ];
          };
        };
        
        kauth-docker = pkgs.dockerTools.buildLayeredImage {
          name = "kauth-server";
          tag = version;
          
          contents = [ kauth-server pkgs.cacert ];
          
          config = {
            Cmd = [ "${kauth-server}/bin/kauth-server" ];
            ExposedPorts = {
              "8080/tcp" = {};
            };
            Env = [
              "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
            ];
          };
        };
        
      in
      {
        packages = {
          default = kauth-cli;
          cli = kauth-cli;
          server = kauth-server;
          docker = kauth-docker;
        };
        
        apps = {
          default = flake-utils.lib.mkApp {
            drv = kauth-cli;
          };
          kauth = flake-utils.lib.mkApp {
            drv = kauth-cli;
          };
          kauth-server = flake-utils.lib.mkApp {
            drv = kauth-server;
          };
        };
        
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            go
            gopls
            gotools
            go-tools
            delve
            kubectl
          ];
          
          shellHook = ''
            echo "kauth development environment"
            echo "Go version: $(go version)"
            echo ""
            echo "Available commands:"
            echo "  go build -o kauth ./cmd/kauth"
            echo "  go build -o kauth-server ./cmd/kauth-server"
            echo "  go test ./..."
            echo ""
          '';
        };
      }
    ) // {
      # NixOS module for kauth-server
      nixosModules.default = { config, lib, pkgs, ... }:
        with lib;
        let
          cfg = config.services.kauth;
        in
        {
          options.services.kauth = {
            enable = mkEnableOption "kauth OIDC authentication server";
            
            package = mkOption {
              type = types.package;
              default = self.packages.${pkgs.system}.server;
              description = "The kauth-server package to use";
            };
            
            listenAddress = mkOption {
              type = types.str;
              default = ":8080";
              description = "Address to listen on";
            };
            
            baseURL = mkOption {
              type = types.str;
              example = "https://kauth.example.com";
              description = "Base URL for the service";
            };
            
            oidc = {
              issuerURL = mkOption {
                type = types.str;
                example = "https://authentik.example.com/application/o/kube-apiserver/";
                description = "OIDC issuer URL";
              };
              
              clientID = mkOption {
                type = types.str;
                example = "kube-apiserver";
                description = "OIDC client ID";
              };
              
              clientSecretFile = mkOption {
                type = types.path;
                description = "Path to file containing OIDC client secret";
              };
            };
            
            cluster = {
              name = mkOption {
                type = types.str;
                default = "kubernetes";
                description = "Kubernetes cluster name";
              };
              
              server = mkOption {
                type = types.str;
                example = "https://k8s.example.com:6443";
                description = "Kubernetes API server URL";
              };
              
              caDataFile = mkOption {
                type = types.path;
                description = "Path to file containing base64-encoded cluster CA certificate";
              };
            };
            
            tls = {
              enable = mkEnableOption "TLS";
              
              certFile = mkOption {
                type = types.nullOr types.path;
                default = null;
                description = "Path to TLS certificate file";
              };
              
              keyFile = mkOption {
                type = types.nullOr types.path;
                default = null;
                description = "Path to TLS key file";
              };
            };
          };
          
          config = mkIf cfg.enable {
            systemd.services.kauth = {
              description = "kauth OIDC authentication server";
              wantedBy = [ "multi-user.target" ];
              after = [ "network.target" ];
              
              serviceConfig = {
                Type = "simple";
                DynamicUser = true;
                ExecStart = "${cfg.package}/bin/kauth-server";
                Restart = "always";
                RestartSec = "10s";
                
                # Hardening
                NoNewPrivileges = true;
                PrivateTmp = true;
                ProtectSystem = "strict";
                ProtectHome = true;
                ProtectKernelTunables = true;
                ProtectKernelModules = true;
                ProtectControlGroups = true;
                RestrictAddressFamilies = [ "AF_INET" "AF_INET6" ];
                RestrictNamespaces = true;
                LockPersonality = true;
                RestrictRealtime = true;
                RestrictSUIDSGID = true;
                PrivateDevices = true;
              };
              
              environment = {
                LISTEN_ADDR = cfg.listenAddress;
                BASE_URL = cfg.baseURL;
                OIDC_ISSUER_URL = cfg.oidc.issuerURL;
                OIDC_CLIENT_ID = cfg.oidc.clientID;
                CLUSTER_NAME = cfg.cluster.name;
                CLUSTER_SERVER = cfg.cluster.server;
              } // (optionalAttrs cfg.tls.enable {
                TLS_CERT_FILE = toString cfg.tls.certFile;
                TLS_KEY_FILE = toString cfg.tls.keyFile;
              });
              
              script = ''
                export OIDC_CLIENT_SECRET=$(cat ${cfg.oidc.clientSecretFile})
                export CLUSTER_CA_DATA=$(cat ${cfg.cluster.caDataFile})
                exec ${cfg.package}/bin/kauth-server
              '';
            };
          };
        };
    };
}
