{
  description = "vaultwarden on serverless";

  inputs.flake-utils.url = "github:numtide/flake-utils";

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        repoSource = pkgs.nix-gitignore.gitignoreSource [ ] ./.;
        vaultwarden = pkgs.stdenv.mkDerivation {
          name = "vaultwarden-wrapped";
          phases = [ "installPhase" ];
          nativeBuildInputs = [ pkgs.makeWrapper ];
          installPhase = ''
            mkdir -p $out/bin
            makeWrapper ${pkgs.vaultwarden}/bin/vaultwarden $out/bin/vaultwarden \
              --set WEB_VAULT_FOLDER "${pkgs.vaultwarden-vault}/share/vaultwarden/vault" \
              --set ENABLE_DB_WAL false \
              --set DISABLE_ICON_DOWNLOAD true \
              --set ROCKET_ADDRESS 127.0.0.1
          '';
        };
        buildPython = pkgs.python3.withPackages (ps:
          with ps;
          pkgs.lib.attrValues rec {
            awacs = (buildPythonPackage rec {
              pname = "awacs";
              version = "2.0.2";
              src = fetchPypi {
                inherit pname version;
                sha256 =
                  "018138c10f82e11734aee7f9e7fff5dbfe1245ddaf15d5927f60f3b16e01ad7e";
              };
            });
            troposphere = (buildPythonPackage rec {
              pname = "troposphere";
              version = "3.1.1";
              src = fetchPypi {
                inherit pname version;
                sha256 =
                  "68313c119c3e5ad457d2a41f7396baadd54551f221268ab97d44134f15bdb2f3";
              };
              propagatedBuildInputs = [ cfn-flip awacs ];
              doCheck = false; # tests not distributed on pypi
            });
          });
        cloudformationTemplate =
          pkgs.runCommand "vaultwarden-cloudformation-template" { } ''
            ${buildPython}/bin/python ${repoSource}/template.py > $out
          '';
        runtimePython =
          pkgs.python3.withPackages (ps: with ps; [ awslambdaric httpx ]);
        proxySource = pkgs.lib.sourceByRegex repoSource [ "proxy\\.py" ];
        containerImage = pkgs.dockerTools.streamLayeredImage {
          name = "vaultwarden-container-image";
          config = {
            Cmd = [
              "${runtimePython}/bin/python"
              "-m"
              "awslambdaric"
              "proxy.handler"
            ];
            Env =
              [ "PYTHONPATH=${proxySource}" "PATH=${vaultwarden}/bin:$PATH" ];
          };
        };
        deployScript = pkgs.writeShellApplication {
          name = "vaultwarden-deploy";
          runtimeInputs = with pkgs; [ awscli coreutils jq skopeo ];
          text = ''
            IMAGETMP="$(mktemp -d --suffix ".$(basename "$0")")"
            trap 'rm -rf -- "$IMAGETMP"' EXIT

            STACK_NAME="vaultwarden-test-3"

            STACK_EXISTS="$(aws cloudformation describe-stacks --stack-name "$STACK_NAME" \
              --query "Stacks[] | length(@)" --output text || echo 0)"
            if [ "$STACK_EXISTS" -eq 0 ]; then
              >&2 echo "Deploying CloudFormation stack to bootstrap image repository"
              aws cloudformation deploy --stack-name "$STACK_NAME" \
                --template-file ${cloudformationTemplate} --parameter-overrides "$@"
            fi

            >&2 echo "Uploading container image"
            ECR_REPOSITORY="$(aws cloudformation describe-stacks --stack-name "$STACK_NAME" \
              --query "Stacks[0].Outputs[?OutputKey == 'FunctionImageRepositoryUri'].OutputValue" --output text)"
            ECR_PASSWORD="$(aws ecr get-login-password)"
            ${containerImage} > "$IMAGETMP/image.tar"
            skopeo copy "docker-archive:$IMAGETMP/image.tar" "dir:$IMAGETMP/image" --insecure-policy --dest-compress
            skopeo copy "dir:$IMAGETMP/image" "docker://$ECR_REPOSITORY" --insecure-policy --dest-creds "AWS:$ECR_PASSWORD"
            IMAGE_DIGEST="$(skopeo inspect "dir:$IMAGETMP/image" | jq -r .Digest)"

            >&2 echo "Updating CloudFormation stack"
            aws cloudformation deploy \
              --stack-name "$STACK_NAME" --template-file ${cloudformationTemplate} --capabilities CAPABILITY_IAM \
              --parameter-overrides "ImageDigest=$IMAGE_DIGEST" "$@"
          '';
        };
      in rec { defaultPackage = deployScript; });
}
