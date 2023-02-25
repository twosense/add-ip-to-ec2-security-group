async function getActionInputs(core) {
    let ip = core.getInput('ip');
    const protocol = core.getInput('protocol');
    const port = core.getInput('port');
    const securityGroupId = core.getInput('security-group-id');

    if (!ip)
        ip = await getPublicIp();

    return {ip, protocol, port, securityGroupId};
}

async function getPublicIp() {
    const {publicIpv4} = await import("public-ip");
    const ip = await publicIpv4();

    console.debug(`Public IP: ${ip}`);
    return ip;
}

function makeParams(ip, protocol, port, securityGroupId) {
    return {
        GroupId: securityGroupId,
        IpProtocol: protocol,
        FromPort: parseInt(port),
        ToPort: parseInt(port),
        CidrIp: ip + '/32',
    };
}

module.exports = {getActionInputs, makeParams};