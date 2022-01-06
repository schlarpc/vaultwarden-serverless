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
          runtimeInputs = with pkgs; [ awscli coreutils jq skopeo util-linux ];
          text = ''
            PROGRAM="$(basename "$0")"
            if ! PARSED_ARGS="$(getopt --name "$PROGRAM" \
              --longoptions stack-name:,availability-zones: -- "" "$@")"; then
                exit 1
            fi
            eval set -- "$PARSED_ARGS"
            declare -a PARAMETER_OVERRIDES
            while [[ $# -gt 0 ]]; do
                case "$1" in
                    --stack-name)
                      shift
                      STACK_NAME="$1"
                      ;;
                    --availability-zones)
                      shift
                      PARAMETER_OVERRIDES+=("AvailabilityZones=$1")
                      ;;
                    --domain-name)
                      shift
                      PARAMETER_OVERRIDES+=("DomainName=$1")
                      ;;
                    --hosted-zone-id)
                      shift
                      PARAMETER_OVERRIDES+=("HostedZoneId=$1")
                      ;;
                esac
                shift
            done
            if [ -z "''${STACK_NAME:-}" ]; then
              echo "$PROGRAM: --stack-name is a required argument"
              exit 1
            fi

            STACK_EXISTS="$(aws cloudformation describe-stacks --stack-name "$STACK_NAME" \
              --query "Stacks[] | length(@)" --output text || echo 0)"
            if [ "$STACK_EXISTS" -eq 0 ]; then
              >&2 echo "Deploying CloudFormation stack to bootstrap image repository"
              # shellcheck disable=SC2016
              ALL_AVAILABILITY_ZONES="$(aws ec2 describe-availability-zones --filters \
                Name=opt-in-status,Values=opted-in,opt-in-not-required \
                Name=zone-type,Values=availability-zone \
                --query 'AvailabilityZones[].ZoneName | sort(@) | join(`,`, @)' --output text)"
              aws cloudformation deploy --stack-name "$STACK_NAME" \
                --template-file ${cloudformationTemplate} \
                --parameter-overrides "AvailabilityZones=$ALL_AVAILABILITY_ZONES"
            fi

            >&2 echo "Uploading container image"
            IMAGETMP="$(mktemp -d --suffix ".$PROGRAM")"
            trap 'rm -rf -- "$IMAGETMP"' EXIT
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
              --parameter-overrides "ImageDigest=$IMAGE_DIGEST" "''${PARAMETER_OVERRIDES[@]}"
          '';
        };
      in rec { defaultPackage = deployScript; });
}
