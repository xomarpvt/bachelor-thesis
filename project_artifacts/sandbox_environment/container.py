import os

import docker
from docker import DockerClient
from dotenv import load_dotenv

load_dotenv()

CONTAINER_SANDBOX_FOLDER = os.getenv("CONTAINER_SANDBOX_FOLDER")
CONTAINER_ID_NAME = os.getenv("CONTAINER_ID_NAME")
CONTAINER_IMAGE_NAME = os.getenv("CONTAINER_IMAGE_NAME")
CONTAINER_MOUNTED_FOLDER = os.getenv("CONTAINER_MOUNTED_FOLDER")


def get_sandbox_container():
    """
    Get the sandbox container.

    If the container already exists, reuse it.
    If it does not exist, create it with restricted resources
    and no network access.
    """

    try:
        # Connect to the local Docker daemon and verify that it is reachable.
        client: DockerClient = docker.from_env()
        client.ping()

    except docker.errors.DockerException as e:
        raise RuntimeError(
            "Docker isn't running or is unreachable."
        ) from e

    try:
        # Try to find an existing container by its configured name.
        container = client.containers.get(CONTAINER_ID_NAME)

        # If the container exists but is stopped, start it.
        if container.status != "running":
            container.start()

        return container

    except docker.errors.NotFound:

        # Container doesn't exist, so create a new sandbox container.
        #
        # The container:
        # - runs in the background
        # - has no network access
        # - mounts the sandbox directory
        # - has a 1 GB memory limit
        # - is limited to one CPU core
        container = client.containers.run(
            name=CONTAINER_ID_NAME,
            image=CONTAINER_IMAGE_NAME,
            detach=True,

            # Completely disable network access from the container.
            network_mode="none",

            # Mount the host sandbox folder into the container.
            volumes={
                str(CONTAINER_SANDBOX_FOLDER): {
                    "bind": CONTAINER_MOUNTED_FOLDER,
                    "mode": "rw",
                }
            },

            # Resource limits for the sandbox.
            mem_limit="1g",
            nano_cpus=1_000_000_000,  # 1 CPU core
        )

        return container
