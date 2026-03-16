{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.05";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
    let
      pkgs = import nixpkgs { inherit system; };

      bip39key = pkgs.rustPlatform.buildRustPackage {
        pname = "bip39key";
        version = "0.2.0";
        src = ./.;
        cargoLock.lockFile = ./Cargo.lock;

        nativeBuildInputs = [
          pkgs.pkg-config
          pkgs.llvmPackages.libclang
        ];

        buildInputs = [
          pkgs.nettle
        ];

        LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";

        BINDGEN_EXTRA_CLANG_ARGS = builtins.concatStringsSep " " [
          (builtins.readFile "${pkgs.stdenv.cc}/nix-support/libc-crt1-cflags")
          (builtins.readFile "${pkgs.stdenv.cc}/nix-support/libc-cflags")
          (builtins.readFile "${pkgs.stdenv.cc}/nix-support/cc-cflags")
          (builtins.readFile "${pkgs.stdenv.cc}/nix-support/libcxx-cxxflags")
          (pkgs.lib.optionalString pkgs.stdenv.cc.isClang
            "-idirafter ${pkgs.stdenv.cc.cc}/lib/clang/${
              pkgs.lib.getVersion pkgs.stdenv.cc.cc
            }/include")
          (pkgs.lib.optionalString pkgs.stdenv.cc.isGNU
            "-isystem ${pkgs.stdenv.cc.cc}/include/c++/${
              pkgs.lib.getVersion pkgs.stdenv.cc.cc
            } -isystem ${pkgs.stdenv.cc.cc}/include/c++/${
              pkgs.lib.getVersion pkgs.stdenv.cc.cc
            }/${pkgs.stdenv.hostPlatform.config} -idirafter ${pkgs.stdenv.cc.cc}/lib/gcc/${pkgs.stdenv.hostPlatform.config}/${
              pkgs.lib.getVersion pkgs.stdenv.cc.cc
            }/include")
        ];

        meta = with pkgs.lib; {
          description = "Deterministic GPG key generation from BIP39 seed phrases";
          license = licenses.gpl3Only;
          mainProgram = "bip39key";
        };
      };
    in
    {
      packages = {
        default = bip39key;
        bip39key = bip39key;
      };

      devShell = pkgs.mkShell {
        buildInputs = [
          pkgs.rustc
          pkgs.cargo
          pkgs.rustfmt
          pkgs.clippy
          pkgs.pkg-config
          pkgs.nettle
          pkgs.llvmPackages.libclang
        ];

        shellHook = ''
          export LIBCLANG_PATH=${pkgs.llvmPackages.libclang.lib}/lib
          export RUST_BACKTRACE=1
          export BINDGEN_EXTRA_CLANG_ARGS="$(< ${pkgs.stdenv.cc}/nix-support/libc-crt1-cflags) \
          $(< ${pkgs.stdenv.cc}/nix-support/libc-cflags) \
          $(< ${pkgs.stdenv.cc}/nix-support/cc-cflags) \
          $(< ${pkgs.stdenv.cc}/nix-support/libcxx-cxxflags) \
          ${
            pkgs.lib.optionalString pkgs.stdenv.cc.isClang
            "-idirafter ${pkgs.stdenv.cc.cc}/lib/clang/${
              pkgs.lib.getVersion pkgs.stdenv.cc.cc
            }/include"
          } \
          ${
            pkgs.lib.optionalString pkgs.stdenv.cc.isGNU
            "-isystem ${pkgs.stdenv.cc.cc}/include/c++/${
              pkgs.lib.getVersion pkgs.stdenv.cc.cc
            } -isystem ${pkgs.stdenv.cc.cc}/include/c++/${
              pkgs.lib.getVersion pkgs.stdenv.cc.cc
            }/${pkgs.stdenv.hostPlatform.config} -idirafter ${pkgs.stdenv.cc.cc}/lib/gcc/${pkgs.stdenv.hostPlatform.config}/${
              pkgs.lib.getVersion pkgs.stdenv.cc.cc
            }/include"
          } \
        "
        '';
      };
    });
}
