const core = require('@actions/core');
const {EC2Client, RevokeSecurityGroupIngressCommand} = require("@aws-sdk/client-ec2");
const {makeParams, getActionInputs} = require("./utils");

try {
    const inputs = getActionInputs(core);
    const params = makeParams(inputs);

    const client = new EC2Client({region: process.env.AWS_REGION});
    const command = new RevokeSecurityGroupIngressCommand(params);
    client.send(command).then(response => {
        console.debug(response)
    });

} catch (error) {
    core.setFailed(error.message);
}