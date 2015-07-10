FROM scratch
EXPOSE 8080
COPY pki.pem /etc/ssl/certs/ca-certificates.crt
COPY tokengenerator /
ENTRYPOINT ["/tokengenerator"]
