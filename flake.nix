{
  description = "Logos Core Microkernel Library";

  nixConfig = {
    extra-substituters = [
      "https://experiments.cachix.org"
      "https://nix-community.cachix.org"
    ];
    extra-trusted-public-keys = [
      "experiments.cachix.org-1:Gg91e1XhvoSF/vp+I5cyI+RLzLSICT5VDh7hI3BPr+o="
      "nix-community.cachix.org-1:mB9FSh9qf2dCimDSUo8Zy7bkq5CX+/rkCWyvRCYg3Fs="
    ];
  };

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            nim
            nimble          
            nimlangserver
            nph 
            openssl
            pkg-config
          ];

          env = {
            LD_LIBRARY_PATH = with pkgs; lib.makeLibraryPath [ ];
          };

          shellHook = ''
            export SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt
            export NIMBLE_DIR="$(git rev-parse --show-toplevel)/.nimble"
          '';
        };
      }
    );
}
