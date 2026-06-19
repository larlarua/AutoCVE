# AutoCVE Agent Sandbox
# 安全沙箱环境用于漏洞验证和 PoC 执行
# 集成各类安全扫描工具 (Semgrep, Bandit, Gitleaks, etc.)

FROM docker.m.daocloud.io/python:3.11-bookworm

ARG SEMGREP_VERSION=1.161.0
ARG PIP_INDEX_URL=https://mirrors.aliyun.com/pypi/simple/

LABEL maintainer="XCodeReviewer Team"
LABEL description="Secure sandbox environment for vulnerability verification and security scanning"

# 安装基本工具
# 安装基本工具
# 使用默认 Debian 源并开启 apt 重试，避免绑定单个不稳定镜像站
RUN unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY && \
    echo 'Acquire::Retries "5";' > /etc/apt/apt.conf.d/99-retries && \
    echo 'Acquire::http::Timeout "30";' >> /etc/apt/apt.conf.d/99-retries && \
    echo 'Acquire::https::Timeout "30";' >> /etc/apt/apt.conf.d/99-retries && \
    apt-get update && apt-get install -y --fix-missing --no-install-recommends \
    curl \
    wget \
    netcat-openbsd \
    dnsutils \
    iputils-ping \
    ca-certificates \
    git \
    unzip \
    xz-utils \
    jq \
    php-cli \
    openjdk-17-jdk-headless \
    ruby-full \
    rustc \
    cargo \
    build-essential \
    cmake \
    clang \
    llvm \
    && rm -rf /var/lib/apt/lists/*

# 安装 Node.js (用于 JavaScript/TypeScript 代码执行 和 npm audit)
# 使用 Node.js binary tarball，优先国内镜像并回退官方源
ARG NODE_VERSION=20.20.2
ARG TARGETARCH
RUN unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY && \
    case "${TARGETARCH}" in \
      amd64) NODE_ARCH="x64" ;; \
      arm64) NODE_ARCH="arm64" ;; \
      *) echo "Unsupported Node.js architecture: ${TARGETARCH}" && exit 1 ;; \
    esac && \
    for base_url in "https://npmmirror.com/mirrors/node" "https://nodejs.org/dist"; do \
      curl -fsSL --retry 5 --retry-delay 3 --connect-timeout 30 "${base_url}/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-${NODE_ARCH}.tar.xz" -o /tmp/node.tar.xz && break; \
    done && \
    test -s /tmp/node.tar.xz && \
    tar -xJf /tmp/node.tar.xz -C /usr/local --strip-components=1 && \
    rm /tmp/node.tar.xz && \
    node --version && \
    npm --version && \
    npm config set registry https://registry.npmmirror.com

# 安装 Go (使用阿里云镜像)
ENV PATH=$PATH:/usr/local/go/bin
ENV GOPROXY=https://goproxy.cn,direct
RUN unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY && \
    case "${TARGETARCH}" in \
      amd64) GO_ARCH="amd64" ;; \
      arm64) GO_ARCH="arm64" ;; \
      *) echo "Unsupported Go architecture: ${TARGETARCH}" && exit 1 ;; \
    esac && \
    curl -L "https://mirrors.aliyun.com/golang/go1.21.6.linux-${GO_ARCH}.tar.gz" -o go.tar.gz && \
    tar -C /usr/local -xzf go.tar.gz && \
    rm go.tar.gz

# Verify distro-provided Rust tools instead of relying on an external rustup installer.
RUN rustc --version && cargo --version

# 安装 Python 安全工具
RUN unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY && \
    for index_url in "${PIP_INDEX_URL}" "https://pypi.org/simple"; do \
      python -m pip install --no-cache-dir -i "${index_url}" \
      requests \
      httpx \
      aiohttp \
      beautifulsoup4 \
      lxml \
      pycryptodome \
      paramiko \
      pyjwt \
      python-jose \
      sqlparse \
      "semgrep==${SEMGREP_VERSION}" \
      bandit \
      safety && break; \
    done && \
    semgrep --version && \
    test "$(semgrep --version)" = "${SEMGREP_VERSION}"

# 安装 Gitleaks
RUN unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY && \
    case "${TARGETARCH}" in \
      amd64) GITLEAKS_ARCH="x64" ;; \
      arm64) GITLEAKS_ARCH="arm64" ;; \
      *) echo "Unsupported Gitleaks architecture: ${TARGETARCH}" && exit 1 ;; \
    esac && \
    curl -L "https://github.com/gitleaks/gitleaks/releases/download/v8.18.2/gitleaks_8.18.2_linux_${GITLEAKS_ARCH}.tar.gz" -o gitleaks.tar.gz && \
    tar -xzf gitleaks.tar.gz && \
    mv gitleaks /usr/local/bin/ && \
    rm gitleaks.tar.gz

# 安装 TruffleHog
RUN unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY && \
    curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin

# 安装 OSV-Scanner
RUN unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY && \
    case "${TARGETARCH}" in \
      amd64) OSV_ARCH="amd64" ;; \
      arm64) OSV_ARCH="arm64" ;; \
      *) echo "Unsupported OSV-Scanner architecture: ${TARGETARCH}" && exit 1 ;; \
    esac && \
    curl -L "https://github.com/google/osv-scanner/releases/download/v1.6.2/osv-scanner_1.6.2_linux_${OSV_ARCH}" -o /usr/local/bin/osv-scanner && \
    chmod +x /usr/local/bin/osv-scanner

# 创建非 root 用户
RUN groupadd -g 1000 sandbox && \
    useradd -u 1000 -g sandbox -m -s /bin/bash sandbox

# 创建工作目录
RUN mkdir -p /workspace /tmp/sandbox && \
    chown -R sandbox:sandbox /workspace /tmp/sandbox

# 设置环境变量
ENV HOME=/home/sandbox
ENV PATH=/home/sandbox/.local/bin:$PATH
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# 限制 Python 导入路径
ENV PYTHONPATH=/workspace

# 切换到非 root 用户
USER sandbox

WORKDIR /workspace

# 默认命令
CMD ["/bin/bash"]

