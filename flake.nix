{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.05";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
    let
      pkgs = import nixpkgs { inherit system; };
    in
    {
      devShell = pkgs.mkShell {
        buildInputs = [
          pkgs.rustc
          pkgs.cargo
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
