# The helper holds only the pilot's transactional head; CDS encrypts the WAL.
FROM gcr.io/distroless/static:nonroot@sha256:25ac8f0c3b2334a9eb05452266bd4697864a8c8ef0ef71e5e6480d7f92868329
COPY build/cds-metadata-pilot /cds-metadata-pilot
ENTRYPOINT ["/cds-metadata-pilot"]
