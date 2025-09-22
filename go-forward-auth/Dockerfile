# 仅用于快速容器化部署（单阶段构建）
# 若需更小镜像，可改为多阶段构建并使用 distroless/alpine 运行时
FROM golang:1.21-alpine

WORKDIR /app
COPY go.mod ./
COPY main.go ./

# 不依赖外部模块，直接构建
RUN go build -o forward-auth

EXPOSE 4181
ENV LISTEN_ADDR=:4181
ENTRYPOINT ["/app/forward-auth"]
