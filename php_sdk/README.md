# php_sdk 目录说明（示例/参考）

本目录为彩虹聚合登录的 PHP 示例 SDK，仅用于理解第三方接口的参数与返回格式，便于你在其他语言/框架中对接。

当前项目的推荐接入方案为：Nginx `auth_request` + Go Forward-Auth 边车（目录：`../go-forward-auth`），无需依赖 PHP SDK。

注意：生产环境请使用 Go 边车 + Nginx 统一接入；本目录文件可作为参考，不参与部署。
