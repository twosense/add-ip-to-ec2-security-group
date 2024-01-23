const core = require('@actions/core');
const {EC2Client, AuthorizeSecurityGroupIngressCommand} = require("@aws-sdk/client-ec2");
const {makeParams, getActionInputs} = require("./utils");

async function main() {
    try {
        const inputs = await getActionInputs();
        const params = makeParams(inputs);

        const client = new EC2Client({region: process.env.AWS_REGION});
        const command = new AuthorizeSecurityGroupIngressCommand(params);

        const response = client.send(command);
        core.debug(response);
    } catch (error) {
        core.setFailed(error);
    }
}

main();