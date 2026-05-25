FROM scratch
COPY bin/longsocks /longsocks
EXPOSE 8080
ENTRYPOINT ["/longsocks"]
CMD ["server", "--addr", "0.0.0.0:8080"]
