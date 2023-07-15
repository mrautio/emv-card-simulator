{ sources ? import ./nix/sources.nix
, pkgs ? import sources.nixpkgs {}
}:

pkgs.mkShell {
  buildInputs = [
    pkgs.git
    pkgs.pkg-config
    pkgs.openssl
    pkgs.cacert
    pkgs.jdk8
    pkgs.gradle
    pkgs.rustc
    pkgs.cargo
    pkgs.gcc
    pkgs.pcsclite
  ];

  SSL_CERT_FILE = "${pkgs.cacert.out}/etc/ssl/certs/ca-bundle.crt";
}
