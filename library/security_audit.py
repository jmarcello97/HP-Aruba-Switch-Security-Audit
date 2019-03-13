from ansible.module_utils.basic import *

f = open("text.txt", "w")

def port_security_audit(module):
	command_output = module.params['port_security']

	# remove unneeded lines from show port_security command
	command_output=command_output[5:]

	port_security_config=dict()

	# put port security info into a dictionary
	# port number is the key and the value is a list of [learn mode, action, eavesdrop prevention]
	for line in command_output:
		line=str(line.strip())
		info = line.split()
		port_security_config[info[0]] = [info[1],info[3],info[4]]


	return port_security_config

def main():

	fields = {
		"port_security": {"required": True, "type": "list"}
	}

	module = AnsibleModule(argument_spec=fields)

	port_security_config = port_security_audit(module)

	module.exit_json(changed=False, meta=module.params, port_security_config=port_security_config)

main()
