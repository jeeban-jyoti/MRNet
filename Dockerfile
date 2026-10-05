# One image for every MRNet auth component; the compose file picks the
# component with the first argument (mrnet token, mrnet validator, ...).
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/mrnet ./cmd/mrnet

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/mrnet /mrnet
ENTRYPOINT ["/mrnet"]
