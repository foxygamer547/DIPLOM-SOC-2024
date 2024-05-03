#!/bin/bash

# Чтение JSON ввода от Wazuh
read INPUT_JSON
INPUT_ARRAY=$(echo $INPUT_JSON | jq '.')

# Переменные для команды и IP адреса
command=$(echo $INPUT_ARRAY | jq -r '.command')
destinationip=$(echo $INPUT_ARRAY | jq -r '.parameters.alert.data.misp.value')

# Получение текущего IP адреса хоста
hostip=$(hostname -I | cut -d' ' -f1)

# Добавление IP адреса в iptables
if [ "$command" == "add" ] && [ "$destinationip" != "127.0.0.1" ] && [ "$destinationip" != "0.0.0.0" ] && [ "$destinationip" != "$hostip" ]; then
    sudo iptables -A OUTPUT -d $destinationip -j DROP
    echo "{\"message\":\"$destinationip added to blocklist via iptables\"}" | sudo tee -a /var/ossec/logs/active-responses.log
fi

# Удаление IP адреса из iptables
if [ "$command" == "delete" ] && [ "$destinationip" != "127.0.0.1" ] && [ "$destinationip" != "0.0.0.0" ] && [ "$destinationip" != "$hostip" ]; then
    sudo iptables -D OUTPUT -d $destinationip -j DROP
    echo "{\"message\":\"$destinationip removed from blocklist via iptables\"}" | sudo tee -a /var/ossec/logs/active-responses.log
