# Check if the repository name is passed as an argument
if [ -z "$1" ] || [ -z "$2" ]; then
    echo "Usage: ./release-assistant.sh <docker_repository_name> <Release>"
    exit 1
fi

# Assign the first argument to a variable
REPO_NAME=$1
RELEASE=$2

# Print the repository name to verify
echo "Repository Name: $REPO_NAME"
echo "Release: $RELEASE"

# Build and push the base image
docker build . \
  --platform linux/amd64 \
  -f docker/zenml-dev.Dockerfile \
  -t "$REPO_NAME"/zenml:release-base

docker push "$REPO_NAME"/zenml:release-base

# Build and push GCP quickstart image
docker build . \
  --platform linux/amd64 \
  --build-arg ZENML_VERSION="$RELEASE" \
  --build-arg CLOUD_PROVIDER=gcp \
  --build-arg BASE_REPO="$REPO_NAME" \
  -f docker/zenml-quickstart.Dockerfile \
  -t "$REPO_NAME"/zenml:release-quickstart-gcp

docker push "$REPO_NAME"/zenml:release-quickstart-gcp

# Build and push AWS quickstart image
docker build . \
  --platform linux/amd64 \
  --build-arg ZENML_VERSION="$RELEASE" \
  --build-arg CLOUD_PROVIDER=aws \
  --build-arg BASE_REPO="$REPO_NAME" \
  -f docker/zenml-quickstart.Dockerfile \
  -t "$REPO_NAME"/zenml:release-quickstart-aws

docker push "$REPO_NAME"/zenml:release-quickstart-aws

# Build and push Azure quickstart image
docker build . \
  --platform linux/amd64 \
	--build-arg ZENML_VERSION="$RELEASE" \
	--build-arg CLOUD_PROVIDER=azure \
  --build-arg BASE_REPO="$REPO_NAME" \
	-f docker/zenml-quickstart.Dockerfile  \
	-t "$REPO_NAME"/zenml:release-quickstart-azure

docker push "$REPO_NAME"/zenml:release-quickstart-azure

# Run Examples
cd examples/quickstart || exit

zenml stack set default
python run.py --model_type=t5-small

# Run it on AWS
zenml stack set aws
python run.py --model_type=t5-small

# Run it on GCP
zenml stack set gcp
python run.py --model_type=t5-small

# Run it on Azure
zenml stack set azure
python run.py --model_type=t5-small
