#!/bin/bash

gen_csv() {
    local nb_line=${1}
    local output="${2}"

    echo -n "line_number,value" >"gen_content/${output}"
    for i in $(seq 1 ${nb_line}); do
        echo -n -e "\n${i},value ${i}" >>"gen_content/${output}"
    done
}


[ -e gen_content ] || mkdir gen_content

gen_csv 3 "data3.csv"
gen_csv 4 "data4.csv"
gen_csv 5 "data5.csv"
gen_csv 6 "data6.csv"

conn_string="${AZURE_STORAGE_CONNECTION_STRING:-${1:-not_defined}}"

filesystem="hn1"
az storage fs create -n "${filesystem}" --connection-string "${conn_string}"

az storage fs file upload -s "gen_content/data3.csv" -p "/data.csv" -f "${filesystem}" --connection-string "${conn_string}"

az storage fs directory create -n "key1=my" -f "${filesystem}" --connection-string "${conn_string}"
az storage fs file upload -s "gen_content/data4.csv" -p "/key1=my/data.csv" -f "${filesystem}" --connection-string "${conn_string}"

az storage fs directory create -n "key1=our" -f "${filesystem}" --connection-string "${conn_string}"
az storage fs file upload -s "gen_content/data5.csv" -p "/key1=our/data.csv" -f "${filesystem}" --connection-string "${conn_string}"

az storage fs directory create -n "key1=our/hidden" -f "${filesystem}" --connection-string "${conn_string}"
az storage fs file upload -s "gen_content/data6.csv" -p "/key1=our/hidden/data.csv" -f "${filesystem}" --connection-string "${conn_string}"

rm -rf gen_content

