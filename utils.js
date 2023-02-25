function makeParams(securityGroupId, protocol, port, ip) {
    return {
        GroupId: securityGroupId,
        IpProtocol: protocol,
        FromPort: parseInt(port),
        ToPort: parseInt(port),
        CidrIp: ip + '/32',
    };
}

module.exports = {makeParams};