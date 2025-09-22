# Open

[![Build and Push Docker Image](https://github.com/<OWNER>/<REPO>/actions/workflows/docker-publish.yml/badge.svg?branch=main)](https://github.com/<OWNER>/<REPO>/actions/workflows/docker-publish.yml)

## Forward-Auth（Go）快速开始

- 目录：`go-forward-auth/` 提供基于 Go 的 Forward-Auth 边车服务，直接适配你的聚合登录接口（u.june.ink/connect.php）。
- 运行环境变量：
  - `JUNE_API_URL`：聚合登录 API 基址，默认 `https://u.june.ink/`（会自动补全 `/connect.php`）。
  - `JUNE_APP_ID`：应用 ID（必须）。
  - `JUNE_APP_KEY`：应用密钥（必须）。
  - `JUNE_SESSION_SECRET`：本地会话签名密钥（必须）。
  - `JUNE_COOKIE_NAME`：会话 Cookie 名称，默认 `june_session`。
  - `JUNE_COOKIE_DOMAIN`：可选，跨子域 SSO 时设置为 `.example.com`。
  - `JUNE_DEFAULT_TYPE`：默认登录方式（qq/wx/alipay/sina/baidu），默认 `qq`。
  - `JUNE_DEFAULT_TYPES`：默认登录方式候选（逗号分隔，按顺序回退），如 `wx,alipay,qq`。
  - `LISTEN_ADDR`：监听地址，默认 `:4181`。

- Nginx 参考片段：`nginx/june-auth.conf`，于各站点 `server` 中 include，并设置 `$upstream_app` 指向后端。示例 server 配置见 `nginx/examples/server.example.conf`，`map` 片段见 `nginx/examples/http-map-upgrade.conf`（需放在 http 块）。

- HTTP 接口：
  - `GET /verify`：校验会话，成功 200 并返回 `X-Auth-*` 头；失败 401。
  - `GET /start?rd=`：发起登录跳转，`rd` 为回跳地址（同域校验）。
  - `GET /callback`：登录回调，颁发 Cookie 并 302 回 `rd`。
  - `GET /logout?rd=`：清除 Cookie 并 302 回 `rd`。

### Docker 部署

- 构建镜像：
  - `cd go-forward-auth`
  - `docker build -t june-forward-auth:latest .`
- 运行容器（示例）：
  - `docker run -d --name june-auth -p 4181:4181 -e JUNE_APP_ID=你的ID -e JUNE_APP_KEY=你的密钥 -e JUNE_SESSION_SECRET=随机强密钥 june-forward-auth:latest`
  - 可选默认方式单个：`-e JUNE_DEFAULT_TYPE=google`
  - 可选默认方式多选回退：`-e JUNE_DEFAULT_TYPES=google,microsoft,github,gitee`
  - 可选自定义用户可选清单：`-e JUNE_LOGIN_OPTIONS=google:Google,microsoft:Microsoft,github:GitHub,gitee:Gitee`
  - 如需跨子域 SSO：`-e JUNE_COOKIE_DOMAIN=.example.com`
- Nginx：将 `nginx/june-auth.conf` 部署为服务器可读路径（如 `/etc/nginx/snippets/june-auth.conf`），并按 `nginx/examples/server.example.conf` 集成。

### 目录备注
- `php_sdk/`：示例/参考，不参与生产部署。
- `go-forward-auth/`：Go 实现的 Forward-Auth 边车，生产使用。
- `nginx/`：Nginx 片段与示例配置。

### GitHub Actions（自动构建并推送 GHCR）
- 工作流：`.github/workflows/docker-publish.yml`
- 触发：推送到 `main/master` 或 PR 触发构建；默认分支推送 `latest`；分支/标签/commit 分别打对应 tag。
- 目标镜像：`ghcr.io/<OWNER>/go-forward-auth`（OWNER 自动取自仓库属主）
- 权限：workflow 内已启用 `packages: write`，使用 `GITHUB_TOKEN` 登录 GHCR。
- 拉取示例：`docker pull ghcr.io/<OWNER>/go-forward-auth:latest`
- 若需公开镜像：在 GitHub Packages 将该镜像可见性设为 public。

### docker-compose 示例（使用 GHCR 镜像）
- 说明：将 `<OWNER>/<REPO>` 替换为你仓库实际路径；若镜像为私有，请先 `docker login ghcr.io`。

```yaml
version: "3.8"
services:
  june-auth:
    image: ghcr.io/<OWNER>/go-forward-auth:latest
    container_name: june-auth
    restart: unless-stopped
    ports:
      - "4181:4181"
    environment:
      - JUNE_APP_ID=你的应用ID
      - JUNE_APP_KEY=你的应用密钥
      - JUNE_SESSION_SECRET=强随机密钥
      - JUNE_API_URL=https://u.june.ink/
      # 可选：跨子域 SSO 场景
      # - JUNE_COOKIE_DOMAIN=.example.com
      - LISTEN_ADDR=:4181
```
