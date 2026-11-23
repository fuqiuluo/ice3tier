# controller 的镜像：i3t-controller（带内嵌的 WebUI）和 i3tctl。
#
# 从源码构建，在仓库的根目录执行：
#   docker build -f deploy/docker/Dockerfile -t ghcr.io/fuqiuluo/ice3tier-controller .
#
# 发布时不在这里编译：用发布流程编好的程序把 binaries 这一阶段换掉，
#   docker buildx build --build-context binaries=<目录> …
# 目录里按平台放着 amd64/i3t-controller、amd64/i3tctl、arm64/…，和 binaries 阶段的样子一样。
# 最后一个阶段因此不执行任何命令：别的架构的镜像只是拷文件，不用模拟器。

ARG NODE_IMAGE=node:22-bookworm-slim
ARG RUST_IMAGE=rust:1-slim-bookworm
ARG RUNTIME_IMAGE=debian:bookworm-slim

# WebUI 和架构无关，在构建的机器上编一次。
FROM --platform=$BUILDPLATFORM ${NODE_IMAGE} AS web
WORKDIR /src/web
RUN npm install --global pnpm@10
COPY web/package.json web/pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY web/ ./
RUN pnpm build

FROM ${RUST_IMAGE} AS build
ARG TARGETARCH
WORKDIR /src
COPY . .
# controller 在编译时把 web/dist 嵌进程序。
COPY --from=web /src/web/dist web/dist
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target,sharing=locked \
    cargo build --release --locked -p i3t-controller-bin -p i3tctl \
    && mkdir -p "/out/${TARGETARCH}" \
    && cp target/release/i3t-controller target/release/i3tctl "/out/${TARGETARCH}/"

FROM scratch AS binaries
COPY --from=build /out/ /

FROM ${RUNTIME_IMAGE}
ARG TARGETARCH
COPY --from=binaries --chmod=0755 /${TARGETARCH}/i3t-controller /${TARGETARCH}/i3tctl /usr/local/bin/
# 以普通用户运行。数据目录（controller 的密钥、更新包的缓存）归它；第一次挂上来的命名卷跟着这个属主。
# 不用安装脚本的 /var/lib/i3t-controller：WebUI 看到那个目录会给出 systemd 的命令，在容器里用不上。
USER 10001:10001
WORKDIR /data
VOLUME /data
ENV I3T_DATA_DIR=/data
# 20331：节点协议（TCP）和地址查询（UDP）。20332：管理 API 和 WebUI。
EXPOSE 20331/tcp 20331/udp 20332/tcp
ENTRYPOINT ["i3t-controller"]
# 容器里的回环地址外面连不到，所以管理 API 听所有地址；发布这个端口时只发布到宿主机的 127.0.0.1（见 compose.yaml）。
CMD ["--admin-listen", "0.0.0.0:20332"]
