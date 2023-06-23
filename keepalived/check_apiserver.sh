#!/bin/bash
errorExit() {
    echo "*** " 1>&2
    exit 1
}
curl --silent --max-time 2 --insecure https://localhost:8080/ -o /dev/null || errorExit "Error GET https://localhost:8080/"
if ip addr | grep -q 10.3.16.222; then
    curl --silent --max-time 2 --insecure https://X.X.X.222:8080/ -o /dev/null || errorExit "Error GET https://X.X.X.222:8080/"
fi
