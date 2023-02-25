# Add IP to EC2 security group action

This action adds an IP address on a specific port to an EC2 security group.
If no IP address is provided, the action will use the IP address of the machine running the action.

This action assumes that the AWS CLI is installed and configured.

## Inputs
______________
### `security-group-id`
**Required**

The EC2 security group ID to add the IP to.

### `port`
**Required**

The port to open on the security group.

### `ip`
The IP address to add to the security group. 
If no IP address is provided, the action will use the IP address of the machine running the action.

### `protocol`
The protocol to use for the security group rule. Defaults to `tcp`.

## Usage
______________
Add the following step to your workflow:

```yaml
    - name: Add IP to EC2 security group
      uses: twosense/add-ip-to-ec2-security-group@v1
      with:
        security-group-id: ${{ secrets.SECURITY_GROUP_ID }}
        port: 22
```