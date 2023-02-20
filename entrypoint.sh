#!/bin/sh -l
ip=$1
port=$2
protocol=$3
security_group_id=$4

echo "Adding IP: $ip to security group: $security_group_id on port: $port $protocol"

aws ec2 authorize-security-group-ingress --group-id "$security_group_id" --protocol "$protocol" --port "$port" --cidr "$ip"/32