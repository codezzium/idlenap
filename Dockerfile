FROM python:3.15-alpine

ENV IDLENAP_PROC_ROOT=/host/proc \
    IDLENAP_CGROUP_ROOT=/host/cgroup \
    IDLENAP_CONFIG=/etc/idlenap/config.toml

COPY idlenap.py /usr/local/lib/idlenap.py
RUN printf '#!/bin/sh\nexec python3 -I /usr/local/lib/idlenap.py "$@"\n' > /usr/local/bin/idlenap \
    && chmod 755 /usr/local/bin/idlenap

ENTRYPOINT ["idlenap"]
CMD ["run"]
