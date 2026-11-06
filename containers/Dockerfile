# The source archive and base image are immutable. Runtime dependency versions
# are constrained and captured in environment manifests inside the image.
ARG BASE_IMAGE=python:3.11-slim@sha256:65bd3d9f1d7fa268dd1909973ba7eb4bdf41f6dcf2cfbe76ba9528b170f3fd79
FROM ${BASE_IMAGE}

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    HF_HUB_OFFLINE=1 \
    HF_HUB_DISABLE_TELEMETRY=1 \
    HF_HOME=/tmp/cs263-huggingface \
    XDG_CACHE_HOME=/tmp/cs263-cache \
    CS263_ISOLATED_WORKER=1

WORKDIR /opt/cs263

COPY scripts/fetch_reference.py /tmp/fetch_reference.py
COPY containers/reference-constraints.txt /opt/cs263/reference-constraints.txt
RUN python /tmp/fetch_reference.py --output /tmp/smolagents-reference.tar.gz \
    && python -m pip install --no-cache-dir \
        --constraint /opt/cs263/reference-constraints.txt \
        /tmp/smolagents-reference.tar.gz \
    && python -m pip freeze --all > /opt/cs263/reference-environment.txt \
    && rm /tmp/fetch_reference.py /tmp/smolagents-reference.tar.gz

COPY pyproject.toml ./
COPY src ./src
COPY benchmarks ./benchmarks
RUN python -m pip install --no-cache-dir --no-deps . \
    && python -m pip check \
    && python -m pip freeze --all > /opt/cs263/environment.txt \
    && python -c "from smolagents.local_python_executor import LocalPythonExecutor; LocalPythonExecutor(additional_authorized_imports=[], timeout_seconds=None).send_tools({})" \
    && mkdir /work \
    && chmod 0555 /work

WORKDIR /work
USER 10001:10001

# The controller supplies the command and adds network/resource/filesystem
# restrictions. This image alone does not establish runtime containment.
CMD ["python", "-m", "cs263_sandbox.worker"]
