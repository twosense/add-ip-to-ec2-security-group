async function getActionInputs() {
    const core = await import('@actions/core');
    const {publicIpv4} = await import("public-ip");

    let ip = core.getInput('ip');
    const protocol = core.getInput('protocol');
    const port = core.getInput('port');
    const securityGroupId = core.getInput('security-group-id');

    if (!ip) {
        ip = await publicIpv4();
        console.info("No IP provided, using public IP: " + ip)
    }

    return {ip, protocol, port, securityGroupId};
}

function makeParams(inputs) {
    return {
        GroupId: inputs.securityGroupId,
        IpProtocol: inputs.protocol,
        FromPort: parseInt(inputs.port),
        ToPort: parseInt(inputs.port),
        CidrIp: inputs.ip + '/32',
    };
}

module.exports = {getActionInputs, makeParams};