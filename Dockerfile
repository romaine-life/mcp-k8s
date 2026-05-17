FROM python:3.12-slim

# kubectl and helm are pinned. The cluster is on a moving AKS minor — keep
# kubectl within the Kubernetes ±1-minor support window when bumping. helm
# 3.x is forward-compatible with all live charts in the cluster.
ARG KUBECTL_VERSION=v1.31.4
ARG HELM_VERSION=v3.16.3

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates git \
    && rm -rf /var/lib/apt/lists/* \
    && arch="$(dpkg --print-architecture)" \
    && curl -fsSL -o /usr/local/bin/kubectl "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${arch}/kubectl" \
    && chmod +x /usr/local/bin/kubectl \
    && curl -fsSL "https://get.helm.sh/helm-${HELM_VERSION}-linux-${arch}.tar.gz" -o /tmp/helm.tgz \
    && tar -xzf /tmp/helm.tgz -C /tmp \
    && mv "/tmp/linux-${arch}/helm" /usr/local/bin/helm \
    && rm -rf /tmp/helm.tgz "/tmp/linux-${arch}" \
    && apt-get purge -y curl \
    && apt-get autoremove -y

COPY pyproject.toml .
COPY src ./src

RUN pip install --no-cache-dir .

ENTRYPOINT ["mcp-k8s-http"]
