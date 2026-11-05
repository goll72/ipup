{
  description = "ipup - dynamic DNS updates from IPv6 addresses";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-23.11";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      ...
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
        };
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = [
            pkgs.pkg-config
            pkgs.ldns
            pkgs.inih
            pkgs.libnl
            pkgs.openssl
            pkgs.meson
            pkgs.ninja
          ];
        };
      }
    );
}
