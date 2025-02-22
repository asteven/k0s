ARG BUILDIMAGE=golang:1.17-alpine
FROM $BUILDIMAGE AS build

ARG VERSION
ARG BUILD_GO_TAGS
ARG BUILD_GO_CGO_ENABLED
ARG BUILD_GO_FLAGS
ARG BUILD_GO_LDFLAGS
ARG BUILD_GO_LDFLAGS_EXTRA
ENV GOPATH=/go
ENV COMMANDS="kubelet kube-apiserver kube-scheduler kube-controller-manager"
COPY kubernetes/armv7.patch /tmp/armv7.patch
RUN apk add build-base git go-bindata linux-headers rsync grep coreutils bash

RUN mkdir -p $GOPATH/src/github.com/kubernetes/kubernetes
RUN git clone -b v$VERSION --depth=1 https://github.com/kubernetes/kubernetes.git $GOPATH/src/github.com/kubernetes/kubernetes
WORKDIR /go/src/github.com/kubernetes/kubernetes
RUN GIT_COMMITTER_EMAIL="foo@example.com" git am /tmp/armv7.patch
RUN go version
RUN \
	# Ensure that all of the binaries are built with CGO \
	if [ ${BUILD_GO_CGO_ENABLED:-0} -eq 1 ]; then \
		export KUBE_CGO_OVERRIDES="${COMMANDS}"; \
	fi; \
	for cmd in $COMMANDS; do \
		export KUBE_GIT_VERSION="v$VERSION+k0s"; \
		make GOFLAGS="${BUILD_GO_FLAGS} -tags=${BUILD_GO_TAGS}" GOLDFLAGS="${BUILD_GO_LDFLAGS_EXTRA}" WHAT=cmd/$cmd || break;\
	done

FROM scratch
COPY --from=build \
	/go/src/github.com/kubernetes/kubernetes/_output/local/bin/linux/*/kubelet \
	/go/src/github.com/kubernetes/kubernetes/_output/local/bin/linux/*/kube-apiserver \
	/go/src/github.com/kubernetes/kubernetes/_output/local/bin/linux/*/kube-scheduler \
	/go/src/github.com/kubernetes/kubernetes/_output/local/bin/linux/*/kube-controller-manager \
	/bin/
CMD ["/bin/kubelet"]
