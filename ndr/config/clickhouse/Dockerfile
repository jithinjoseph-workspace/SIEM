FROM clickhouse/clickhouse-server:24.8
COPY ndr-user.xml /etc/clickhouse-server/users.d/ndr-user.xml
COPY init.sql /docker-entrypoint-initdb.d/01-init.sql
