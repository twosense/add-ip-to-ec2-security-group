const core = require('@actions/core');
const {EC2Client, RevokeSecurityGroupIngressCommand} = require("@aws-sdk/client-ec2");
const {makeParams, getActionInputs} = require("./utils");

async function cleanUp() {
    try {
        const inputs = await getActionInputs();
        const params = makeParams(inputs);

        const client = new EC2Client({region: process.env.AWS_REGION});
        const command = new RevokeSecurityGroupIngressCommand(params);
        client.send(command).then(response => {
            console.debug(response)
        });

    } catch (error) {
        core.setFailed(error.message);
    }
}

cleanUp();