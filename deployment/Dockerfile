FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 ENKSTEIN_POLICY_PACK=/nonexistent/guard-container
WORKDIR /opt/guard
ARG GUARD_WHEEL=dist/deployment/enkstein_guard-0.5.0rc2-py3-none-any.whl
COPY ${GUARD_WHEEL} /tmp/wheels/
COPY dist/vendor-linux-arm64/*.whl /tmp/wheels/
COPY deployment/requirements-linux-arm64.txt /tmp/wheels/requirements.txt
RUN pip install --no-index --require-hashes --find-links /tmp/wheels -r /tmp/wheels/requirements.txt && python -m pip uninstall -y pip && rm -rf /tmp/wheels /usr/local/lib/python3.12/ensurepip
USER 10001:10001
ENTRYPOINT ["enkstein-guard-host"]
